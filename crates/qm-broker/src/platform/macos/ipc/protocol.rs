use block2::DynBlock;
use objc2::{ClassType, extern_protocol, rc::Retained, runtime::AnyProtocol, sel};
use objc2_foundation::{NSData, NSSet, NSXPCInterface};
use objc2_local_authentication::LAContext;
use std::ptr::NonNull;

pub(super) type ReplyBlock = DynBlock<dyn Fn(NonNull<NSData>)>;

extern_protocol!(
    /// # Safety
    /// Implementations must match the shared Clang protocol's selectors and block ABI.
    #[allow(
        clippy::missing_safety_doc,
        reason = "extern_protocol! loses the doc spans used by this lint"
    )]
    pub(super) unsafe trait QuartermasterContextProtocol {
        #[unsafe(method(send:reply:))]
        fn send(&self, message: Option<&NSData>, reply: Option<&ReplyBlock>);

        #[unsafe(method(authenticate:context:reply:))]
        fn authenticate(
            &self,
            message: Option<&NSData>,
            context: Option<&LAContext>,
            reply: Option<&ReplyBlock>,
        );
    }
);

unsafe extern "C" {
    fn qm_context_protocol() -> *const AnyProtocol;
}

pub(super) fn interface() -> Retained<NSXPCInterface> {
    // Clang emits the block's extended signature, which public runtime registration cannot supply.
    let protocol = unsafe { &*qm_context_protocol() };
    let interface = unsafe { NSXPCInterface::interfaceWithProtocol(protocol) };
    let data = NSSet::from_slice(&[NSData::class()]);
    for selector in [sel!(send:reply:), sel!(authenticate:context:reply:)] {
        unsafe {
            interface.setClasses_forSelector_argumentIndex_ofReply(&data, selector, 0, false);
            interface.setClasses_forSelector_argumentIndex_ofReply(&data, selector, 0, true);
        }
    }
    let context = NSSet::from_slice(&[LAContext::class()]);
    unsafe {
        interface.setClasses_forSelector_argumentIndex_ofReply(
            &context,
            sel!(authenticate:context:reply:),
            1,
            false,
        );
    }
    interface
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_protocol_methods_restrict_request_and_reply_objects_to_data() {
        let interface = interface();
        for selector in [sel!(send:reply:), sel!(authenticate:context:reply:)] {
            for reply in [false, true] {
                let classes = unsafe {
                    interface.classesForSelector_argumentIndex_ofReply(selector, 0, reply)
                };
                assert_eq!(classes.len(), 1);
                assert!(classes.containsObject(NSData::class()));
            }
        }
        let classes = unsafe {
            interface.classesForSelector_argumentIndex_ofReply(
                sel!(authenticate:context:reply:),
                1,
                false,
            )
        };
        assert_eq!(classes.len(), 1);
        assert!(classes.containsObject(LAContext::class()));
    }
}
