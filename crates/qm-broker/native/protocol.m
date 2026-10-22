#import "QuartermasterIPC.h"

// NSXPCInterface needs Clang's extended method signatures for reply blocks;
// protocols registered with objc2's runtime builder do not contain that metadata.
Protocol *qm_context_protocol(void) {
    return @protocol(QuartermasterContextProtocol);
}
