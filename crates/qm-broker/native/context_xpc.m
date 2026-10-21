#import "context_xpc.h"
#import <AppKit/AppKit.h>
#include <stdatomic.h>
#include <unistd.h>
#include <time.h>

static const size_t messageLimit = 16384;
static _Atomic(uint64_t) nextConnection = 1;

static NSData *rejected(void) {
    return [@"{\"kind\":\"error\"}" dataUsingEncoding:NSUTF8StringEncoding];
}
@interface QMContextPeer : NSObject <QuartermasterContextProtocol>
@property(nonatomic) uint64_t identifier;
@property(nonatomic) void *owner;
@property(nonatomic) QMContextHandler handler;
@property(nonatomic, strong) NSXPCConnection *connection;
@property(nonatomic, strong) dispatch_queue_t controlQueue;
@property(nonatomic, strong) dispatch_queue_t contextQueue;
@property(nonatomic, strong) LAContext *context;
@property(nonatomic) uint64_t contextGeneration;
@property(nonatomic) uint64_t contextDeadline;
@property(nonatomic, strong) NSLock *lock;
@property(nonatomic) BOOL closed;
@property(nonatomic) NSUInteger inFlight;
- (void)releaseContext;
- (void)releaseGeneration:(uint64_t)generation;
- (void)expireGeneration:(uint64_t)generation at:(uint64_t)deadline;
- (void)disconnect;
@end

@implementation QMContextPeer
- (BOOL)reserve {
    [self.lock lock];
    BOOL allowed = !self.closed && self.inFlight < 4;
    if (allowed) self.inFlight++;
    [self.lock unlock];
    return allowed;
}

- (void)invoke:(NSData *)message context:(LAContext *)context reply:(void (^)(NSData *))reply {
    [self.lock lock];
    BOOL closed = self.closed;
    [self.lock unlock];
    if (closed) { reply(rejected()); return; }
    self.handler(self.owner, self.identifier, 0, message.bytes, message.length,
                 context ? self.contextGeneration : 0, (__bridge void *)context, (__bridge void *)self, (__bridge void *)reply);
}

- (void)send:(NSData *)message reply:(void (^)(NSData *))reply {
    if (message.length > messageLimit || ![self reserve]) { reply(rejected()); return; }
    dispatch_async(self.controlQueue, ^{
        @autoreleasepool {
            [self invoke:message context:nil reply:reply];
            [self.lock lock]; self.inFlight--; [self.lock unlock];
        }
    });
}

- (void)authenticate:(NSData *)message context:(LAContext *)context reply:(void (^)(NSData *))reply {
    if (message.length > messageLimit || !context || ![self reserve]) { reply(rejected()); return; }
    dispatch_async(self.contextQueue, ^{
        @autoreleasepool {
            [self.lock lock]; BOOL closed = self.closed; [self.lock unlock];
            uint64_t now = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
            if (self.context && now >= self.contextDeadline) {
                [self.context invalidate]; self.context = nil;
            }
            if (closed || self.context || self.contextGeneration == UINT64_MAX
                || now > UINT64_MAX - 30000000000ULL) { reply(rejected()); }
            else {
                self.context = context;
                self.contextGeneration++;
                self.contextDeadline = now + 30000000000ULL;
                context.interactionNotAllowed = YES;
                [self expireGeneration:self.contextGeneration at:self.contextDeadline];
                [self invoke:message context:context reply:reply];
            }
            [self.lock lock]; self.inFlight--; [self.lock unlock];
        }
    });
}

- (void)expireGeneration:(uint64_t)generation at:(uint64_t)deadline {
    if (!self.context || self.contextGeneration != generation) return;
    self.contextDeadline = MIN(self.contextDeadline, deadline);
    uint64_t now = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
    if (now >= self.contextDeadline) {
        [self.context invalidate]; self.context = nil; self.contextDeadline = 0;
        return;
    }
    dispatch_after(dispatch_walltime(NULL, (int64_t)(self.contextDeadline - now)), self.contextQueue, ^{
        [self expireGeneration:generation at:deadline];
    });
}

- (void)releaseGeneration:(uint64_t)generation {
    dispatch_async(self.contextQueue, ^{
        if (self.contextGeneration == generation) {
            [self.context invalidate]; self.context = nil; self.contextDeadline = 0;
        }
    });
}

- (void)releaseContext {
    dispatch_async(self.contextQueue, ^{
        [self.context invalidate];
        self.context = nil;
        self.contextDeadline = 0;
    });
}

- (void)disconnect {
    [self.lock lock];
    BOOL notify = !self.closed;
    self.closed = YES;
    [self.lock unlock];
    if (!notify) return;
    self.handler(self.owner, self.identifier, 1, NULL, 0, 0, NULL, (__bridge void *)self, NULL);
    [self releaseContext];
}
@end

@class QMContextListener;
static QMContextListener *activeListener;

@interface QMContextListener : NSObject <NSXPCListenerDelegate>
@property(nonatomic) void *owner;
@property(nonatomic) QMContextHandler handler;
@property(nonatomic, strong) NSLock *lock;
@property(nonatomic, strong) NSMutableSet<QMContextPeer *> *peers;
- (void)observeHostSession;
- (void)workspaceEvent:(NSNotification *)notification;
- (void)screenLocked:(NSNotification *)notification;
- (void)hostSessionEvent:(uint8_t)reason;
@end

@implementation QMContextListener
- (void)hostSessionEvent:(uint8_t)reason {
    self.handler(self.owner, 0, 2, &reason, 1, 0, NULL, NULL, NULL);
    [self.lock lock];
    NSArray<QMContextPeer *> *peers = self.peers.allObjects;
    [self.lock unlock];
    for (QMContextPeer *peer in peers) {
        [peer disconnect];
        [peer.connection invalidate];
    }
}

- (void)workspaceEvent:(NSNotification *)notification {
    if ([notification.name isEqualToString:NSWorkspaceWillSleepNotification]) [self hostSessionEvent:1];
    else if ([notification.name isEqualToString:NSWorkspaceDidWakeNotification]) [self hostSessionEvent:2];
    else if ([notification.name isEqualToString:NSWorkspaceSessionDidResignActiveNotification]) [self hostSessionEvent:4];
    else if ([notification.name isEqualToString:NSWorkspaceWillPowerOffNotification]) [self hostSessionEvent:5];
}

- (void)screenLocked:(NSNotification *)notification {
    (void)notification;
    [self hostSessionEvent:3];
}

- (void)observeHostSession {
    NSNotificationCenter *workspace = NSWorkspace.sharedWorkspace.notificationCenter;
    for (NSNotificationName name in @[NSWorkspaceWillSleepNotification, NSWorkspaceDidWakeNotification,
                                     NSWorkspaceSessionDidResignActiveNotification, NSWorkspaceWillPowerOffNotification]) {
        [workspace addObserver:self selector:@selector(workspaceEvent:) name:name object:nil];
    }
    [NSDistributedNotificationCenter.defaultCenter addObserver:self selector:@selector(screenLocked:)
        name:@"com.apple.screenIsLocked" object:nil suspensionBehavior:NSNotificationSuspensionBehaviorDeliverImmediately];
}

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection {
    (void)listener;
    if (connection.effectiveUserIdentifier != geteuid()) return NO;
    [self.lock lock];
    if (self.peers.count >= 4) { [self.lock unlock]; return NO; }
    uint64_t identifier = atomic_load(&nextConnection);
    while (identifier < UINT64_MAX
           && !atomic_compare_exchange_weak(&nextConnection, &identifier, identifier + 1)) {}
    if (identifier == UINT64_MAX) { [self.lock unlock]; return NO; }
    QMContextPeer *peer = [QMContextPeer new];
    peer.identifier = identifier;
    peer.owner = self.owner;
    peer.handler = self.handler;
    peer.connection = connection;
    peer.lock = [NSLock new];
    peer.controlQueue = dispatch_queue_create("dev.quartermaster.control", DISPATCH_QUEUE_SERIAL);
    peer.contextQueue = dispatch_queue_create("dev.quartermaster.context", DISPATCH_QUEUE_SERIAL);
    [self.peers addObject:peer];
    [self.lock unlock];
    __weak QMContextPeer *weakPeer = peer;
    __weak QMContextListener *weakSelf = self;
    connection.interruptionHandler = ^{ [weakPeer disconnect]; [weakPeer.connection invalidate]; };
    connection.invalidationHandler = ^{
        QMContextPeer *peer = weakPeer;
        if (!peer) return;
        [peer disconnect];
        QMContextListener *server = weakSelf;
        [server.lock lock]; [server.peers removeObject:peer]; [server.lock unlock];
        peer.connection = nil;
    };
    connection.exportedInterface = qm_context_interface();
    connection.exportedObject = peer;
    [connection resume];
    return YES;
}
@end

int qm_context_serve(const char *service, const char *requirement, void *owner, QMContextHandler handler) {
    @autoreleasepool {
        if (!service || !requirement || !owner || !handler) return 1;
        QMContextListener *server = [QMContextListener new];
        server.owner = owner;
        server.handler = handler;
        server.lock = [NSLock new];
        server.peers = [NSMutableSet new];
        [server observeHostSession];
        @synchronized(QMContextListener.class) {
            if (activeListener) return 2;
            activeListener = server;
        }
        NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:[NSString stringWithUTF8String:service]];
        [listener setConnectionCodeSigningRequirement:[NSString stringWithUTF8String:requirement]];
        listener.delegate = server;
        [listener resume];
        for (;;) {
            @autoreleasepool {
                [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:60]];
            }
        }
    }
}

void qm_context_reply(void *opaque, const uint8_t *bytes, size_t length) {
    void (^reply)(NSData *) = (__bridge id)opaque;
    reply(length <= messageLimit ? [NSData dataWithBytes:bytes length:length] : rejected());
}

void qm_context_expire(void *opaque, uint64_t generation, uint64_t deadline) {
    QMContextPeer *peer = (__bridge QMContextPeer *)opaque;
    dispatch_async(peer.contextQueue, ^{ [peer expireGeneration:generation at:deadline]; });
}

void qm_context_release_lease(uint64_t connection, uint64_t generation) {
    QMContextListener *server = activeListener;
    [server.lock lock];
    QMContextPeer *selected = nil;
    for (QMContextPeer *peer in server.peers) {
        if (peer.identifier == connection) { selected = peer; break; }
    }
    [server.lock unlock];
    [selected releaseGeneration:generation];
}

bool qm_context_connected(void *opaque) {
    QMContextPeer *peer = (__bridge QMContextPeer *)opaque;
    [peer.lock lock];
    bool connected = !peer.closed;
    [peer.lock unlock];
    return connected;
}
