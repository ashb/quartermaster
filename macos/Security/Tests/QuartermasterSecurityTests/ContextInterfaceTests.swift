import Foundation
import LocalAuthentication
import QuartermasterIPC
import Testing

@Test func nativeContextInterfaceHasClangMetadataAndOnlyExpectedObjectClasses() {
    let interface = qm_context_interface()
    for selector in [
        #selector(QuartermasterContextProtocol.send(_:reply:)),
        #selector(QuartermasterContextProtocol.authenticate(_:context:reply:)),
    ] {
        for reply in [false, true] {
            let classes = interface.classes(for: selector, argumentIndex: 0, ofReply: reply) as NSSet
            #expect(classes.count == 1)
            #expect(classes.contains(NSData.self))
            #expect(!classes.contains(NSString.self))
        }
    }
    let classes =
        interface.classes(
            for: #selector(QuartermasterContextProtocol.authenticate(_:context:reply:)),
            argumentIndex: 1, ofReply: false) as NSSet
    #expect(classes.count == 1)
    #expect(classes.contains(LAContext.self))
    #expect(!classes.contains(NSData.self))
}
