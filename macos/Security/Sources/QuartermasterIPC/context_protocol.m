#import "QuartermasterIPC.h"

NSXPCInterface *qm_context_interface(void) {
    NSXPCInterface *interface = [NSXPCInterface interfaceWithProtocol:@protocol(QuartermasterContextProtocol)];
    for (NSString *name in @[@"send:reply:", @"authenticate:context:reply:"]) {
        SEL selector = NSSelectorFromString(name);
        [interface setClasses:[NSSet setWithObject:NSData.class] forSelector:selector argumentIndex:0 ofReply:NO];
        [interface setClasses:[NSSet setWithObject:NSData.class] forSelector:selector argumentIndex:0 ofReply:YES];
    }
    [interface setClasses:[NSSet setWithObject:LAContext.class]
             forSelector:@selector(authenticate:context:reply:) argumentIndex:1 ofReply:NO];
    return interface;
}
