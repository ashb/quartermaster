#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

NS_ASSUME_NONNULL_BEGIN

@protocol QuartermasterContextProtocol
- (void)send:(NSData *)message reply:(void (^)(NSData *))reply;
- (void)authenticate:(NSData *)message context:(LAContext *)context reply:(void (^)(NSData *))reply;
@end

FOUNDATION_EXPORT NSXPCInterface *qm_context_interface(void);

NS_ASSUME_NONNULL_END
