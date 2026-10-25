use core_foundation::{
    base::{CFType, TCFType},
    boolean::CFBoolean,
    data::CFData,
    dictionary::CFDictionary,
    string::{CFString, CFStringRef},
};
use security_framework_sys::access_control::kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
use security_framework_sys::{
    item::*,
    keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemUpdate},
};

const LIMIT: usize = 128 * 1024;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecUseAuthenticationUIFail: CFStringRef;
    static kSecMatchLimitOne: CFStringRef;
    static kSecAttrAccessible: CFStringRef;
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Entitlements,
    Invalid,
    Security(i32),
}

pub struct ProtectedRecord {
    group: String,
    service: String,
}

impl ProtectedRecord {
    pub fn open(service: &str) -> Result<Self, Error> {
        if service.is_empty()
            || service.len() > 128
            || !service
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        {
            return Err(Error::Invalid);
        }
        let group = crate::cache_key::own_access_group().map_err(|_| Error::Entitlements)?;
        Ok(Self {
            group,
            service: service.to_owned(),
        })
    }

    pub fn load(&self) -> Result<Option<Vec<u8>>, Error> {
        let mut pairs = query_pairs(&self.group, &self.service);
        unsafe {
            pairs.push((
                CFString::wrap_under_get_rule(kSecReturnData),
                CFBoolean::true_value().into_CFType(),
            ));
            pairs.push((
                CFString::wrap_under_get_rule(kSecMatchLimit),
                CFString::wrap_under_get_rule(kSecMatchLimitOne).into_CFType(),
            ));
        }
        let query = CFDictionary::from_CFType_pairs(&pairs);
        let mut found = std::ptr::null();
        let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut found) };
        if status == -25300 {
            return Ok(None);
        }
        if status != 0 {
            return Err(Error::Security(status));
        }
        if found.is_null() {
            return Err(Error::Invalid);
        }
        let value = unsafe { CFType::wrap_under_create_rule(found) };
        let data = value.downcast::<CFData>().ok_or(Error::Invalid)?;
        if data.len() as usize > LIMIT {
            return Err(Error::Invalid);
        }
        Ok(Some(data.to_vec()))
    }

    pub fn create(&self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.is_empty() || bytes.len() > LIMIT {
            return Err(Error::Invalid);
        }
        let mut pairs = query_pairs(&self.group, &self.service);
        unsafe {
            pairs.push((
                CFString::wrap_under_get_rule(kSecValueData),
                CFData::from_buffer(bytes).into_CFType(),
            ));
            pairs.push((
                CFString::wrap_under_get_rule(kSecAttrAccessible),
                CFString::wrap_under_get_rule(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
                    .into_CFType(),
            ));
        }
        let query = CFDictionary::from_CFType_pairs(&pairs);
        check(unsafe { SecItemAdd(query.as_concrete_TypeRef(), std::ptr::null_mut()) })
    }

    pub fn replace(&self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.is_empty() || bytes.len() > LIMIT {
            return Err(Error::Invalid);
        }
        let query = query(&self.group, &self.service);
        let update = CFDictionary::from_CFType_pairs(&[unsafe {
            (
                CFString::wrap_under_get_rule(kSecValueData),
                CFData::from_buffer(bytes).into_CFType(),
            )
        }]);
        check(unsafe { SecItemUpdate(query.as_concrete_TypeRef(), update.as_concrete_TypeRef()) })
    }
}

fn check(status: i32) -> Result<(), Error> {
    if status == 0 {
        Ok(())
    } else {
        Err(Error::Security(status))
    }
}

fn query(group: &str, service: &str) -> CFDictionary<CFString, CFType> {
    CFDictionary::from_CFType_pairs(&query_pairs(group, service))
}

fn query_pairs(group: &str, service: &str) -> Vec<(CFString, CFType)> {
    unsafe {
        vec![
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrService),
                CFString::new(service).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrAccount),
                CFString::new("approved-settings").into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrAccessGroup),
                CFString::new(group).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain),
                CFBoolean::true_value().into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrSynchronizable),
                CFBoolean::false_value().into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecUseAuthenticationUI),
                CFString::wrap_under_get_rule(kSecUseAuthenticationUIFail).into_CFType(),
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unentitled_process_cannot_open_the_backend_settings_store() {
        assert!(matches!(
            ProtectedRecord::open("dev.quartermaster.tests.unentitled"),
            Err(Error::Entitlements)
        ));
    }

    #[test]
    fn protected_record_queries_use_the_exact_group_and_data_protection_keychain() {
        let query = query(
            "ABCDEFGHIJ.dev.quartermaster.cache.debug",
            "dev.quartermaster.tests.query",
        );
        unsafe {
            assert_eq!(
                query
                    .find(CFString::wrap_under_get_rule(kSecAttrAccessGroup))
                    .unwrap()
                    .downcast::<CFString>()
                    .unwrap()
                    .to_string(),
                "ABCDEFGHIJ.dev.quartermaster.cache.debug"
            );
            assert_eq!(
                query
                    .find(CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain))
                    .unwrap()
                    .downcast::<CFBoolean>()
                    .unwrap(),
                CFBoolean::true_value()
            );
            assert_eq!(
                query
                    .find(CFString::wrap_under_get_rule(kSecAttrSynchronizable))
                    .unwrap()
                    .downcast::<CFBoolean>()
                    .unwrap(),
                CFBoolean::false_value()
            );
            assert_eq!(
                query
                    .find(CFString::wrap_under_get_rule(kSecUseAuthenticationUI))
                    .unwrap()
                    .downcast::<CFString>()
                    .unwrap(),
                CFString::wrap_under_get_rule(kSecUseAuthenticationUIFail)
            );
        }
    }
}
