use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};
use core_foundation::url::CFURL;
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement, SecStaticCode,
};
use serde::Serialize;
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const COMMAND_LINE_BYTES: usize = 65536;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecCodeCopySigningInformation(
        code: *const std::ffi::c_void,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> i32;
    static kSecCodeInfoIdentifier: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    static kSecCodeInfoUnique: CFStringRef;
    static kSecCodeInfoFlags: CFStringRef;
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservedProcess {
    pid: u32,
    parent_pid: u32,
    name: String,
    executable: String,
    #[serde(skip)]
    started: (u64, u64),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerIdentity {
    pid: u32,
    executable: String,
    signing_identifier: String,
    team_identifier: Option<String>,
    cd_hash: String,
    ad_hoc: bool,
    ancestry: Vec<ObservedProcess>,
    ancestry_complete: bool,
    command_line: Option<String>,
    #[serde(skip)]
    started: (u64, u64),
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerPresentation {
    pub pid: u32,
    pub executable: String,
    pub signing_identifier: String,
    pub team_identifier: Option<String>,
    pub cd_hash: String,
    pub ad_hoc: bool,
    pub ancestry_complete: bool,
    pub command_line: Option<String>,
}

impl PeerIdentity {
    pub fn presentation(&self) -> PeerPresentation {
        PeerPresentation {
            pid: self.pid,
            executable: self.executable.clone(),
            signing_identifier: self.signing_identifier.clone(),
            team_identifier: self.team_identifier.clone(),
            cd_hash: self.cd_hash.clone(),
            ad_hoc: self.ad_hoc,
            ancestry_complete: self.ancestry_complete,
            command_line: self.command_line.clone(),
        }
    }
    pub fn code_hash(&self) -> &str {
        &self.cd_hash
    }

    /// Signature validity identifies the running image; it does not grant authority.
    pub fn capture(stream: &UnixStream) -> io::Result<Self> {
        let mut pid = 0i32;
        let mut pid_length = size_of_val(&pid) as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut i32).cast(),
                &mut pid_length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        if pid_length as usize != size_of_val(&pid) || pid <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unexpected socket peer",
            ));
        }
        let mut token = [0u32; 8];
        let mut length = size_of_val(&token) as libc::socklen_t;
        // LOCAL_PEERTOKEN includes the process generation, avoiding PID-only code lookup.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERTOKEN,
                token.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize != size_of_val(&token) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unexpected socket peer",
            ));
        }
        let data = CFData::from_buffer(unsafe {
            std::slice::from_raw_parts(token.as_ptr().cast(), size_of_val(&token))
        });
        let mut attributes = GuestAttributes::new();
        attributes.set_audit_token(data.as_concrete_TypeRef());
        let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
            .map_err(io::Error::other)?;
        let flags = Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS;
        let mut information = std::ptr::null();
        // security-framework does not yet wrap SecCodeCopySigningInformation.
        let status =
            unsafe { SecCodeCopySigningInformation(code.as_CFTypeRef(), 2, &mut information) };
        if status != 0 || information.is_null() {
            return Err(io::Error::other("signing information unavailable"));
        }
        let information =
            unsafe { CFDictionary::<CFString, CFType>::wrap_under_create_rule(information) };
        let unique_key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoUnique) };
        let unique = information
            .find(&unique_key)
            .and_then(|v| v.downcast::<CFData>())
            .ok_or_else(|| io::Error::other("peer has no code hash"))?;
        let cd_hash = unique
            .bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if !matches!(unique.len(), 20 | 32) {
            return Err(io::Error::other("unsupported code hash"));
        }
        let requirement: SecRequirement = format!("cdhash H\"{cd_hash}\"")
            .parse()
            .map_err(io::Error::other)?;
        code.check_validity(flags, &requirement)
            .map_err(io::Error::other)?;
        let executable = code
            .path(Flags::NONE)
            .map_err(io::Error::other)?
            .to_path()
            .ok_or_else(|| io::Error::other("peer path unavailable"))?;
        let identifier = string_value(&information, unsafe { kSecCodeInfoIdentifier })
            .ok_or_else(|| io::Error::other("peer signing identifier unavailable"))?;
        let team = string_value(&information, unsafe { kSecCodeInfoTeamIdentifier });
        let flags_key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoFlags) };
        let ad_hoc = information
            .find(&flags_key)
            .and_then(|v| v.downcast::<CFNumber>())
            .and_then(|n| n.to_i64())
            .is_some_and(|f| f & 2 != 0);
        let (ancestry, ancestry_complete) = ancestry(pid as u32)?;
        let fresh = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
            .map_err(io::Error::other)?;
        fresh
            .check_validity(flags, &requirement)
            .map_err(io::Error::other)?;
        let started = ancestry.last().unwrap().started;
        Ok(Self {
            pid: pid as u32,
            executable: display_text(&executable.to_string_lossy()),
            signing_identifier: identifier,
            team_identifier: team,
            cd_hash,
            ad_hoc,
            ancestry,
            ancestry_complete,
            command_line: None,
            started,
        })
    }

    /// Observed arguments provide display context, never authority.
    pub fn observe_command_line(&mut self) {
        self.command_line = self.read_command_line();
    }

    fn read_command_line(&self) -> Option<String> {
        let before = observed_process(self.pid).ok()?;
        if before.started != self.started || before.executable != self.executable {
            return None;
        }
        let mut buffer = Zeroizing::new(vec![0u8; COMMAND_LINE_BYTES]);
        let mut length = buffer.len();
        let mut name = [libc::CTL_KERN, libc::KERN_PROCARGS2, self.pid as i32];
        if unsafe {
            libc::sysctl(
                name.as_mut_ptr(),
                name.len() as u32,
                buffer.as_mut_ptr().cast(),
                &mut length,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return None;
        }
        let after = observed_process(self.pid).ok()?;
        if after.started != before.started || after.executable != before.executable {
            return None;
        }
        command_line(buffer.get(..length)?)
    }

    pub fn process_chain(&self) -> Vec<String> {
        self.ancestry
            .iter()
            .map(|p| {
                let name = if p.pid == self.pid {
                    crate::process_display::display_name(Path::new(&p.executable), &p.name)
                } else {
                    &p.name
                };
                format!("{name} · PID {}", p.pid)
            })
            .collect()
    }
}

fn command_line(bytes: &[u8]) -> Option<String> {
    // A full buffer may be the truncated tail of argv and environment data.
    if bytes.len() >= COMMAND_LINE_BYTES {
        return None;
    }
    let count = usize::try_from(i32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?)).ok()?;
    let mut remaining = bytes.get(4..)?;
    let path_end = remaining.iter().position(|b| *b == 0)? + 1;
    // XNU aligns argv after executable_path= and the saved path; sysctl removes
    // the 16-byte prefix. Skipping all NULs would swallow empty arguments.
    let argv_start = path_end.next_multiple_of(8);
    if remaining.get(path_end..argv_start)?.iter().any(|b| *b != 0) {
        return None;
    }
    remaining = remaining.get(argv_start..)?;
    if count == 0 || count > remaining.len() {
        return None;
    }
    let mut arguments = Vec::new();
    // KERN_PROCARGS2 appends environment strings; stop at argc and wipe the native buffer.
    for index in 0..count {
        let end = remaining.iter().position(|b| *b == 0)?;
        let argument = std::str::from_utf8(&remaining[..end]).ok()?;
        let argument = if index == 0 && !argument.is_empty() {
            Path::new(argument).file_name()?.to_str()?
        } else {
            argument
        };
        arguments.push(crate::process_display::argument(argument));
        remaining = &remaining[end + 1..];
    }
    Some(arguments.join(" "))
}

/// Pins a development peer to the code in this local bundle, not a claimed name.
pub fn requirement_for_path(path: &Path) -> io::Result<String> {
    let url = CFURL::from_path(path, path.is_dir())
        .ok_or_else(|| io::Error::other("invalid code path"))?;
    let code = SecStaticCode::from_path(&url, Flags::NONE).map_err(io::Error::other)?;
    let mut information = std::ptr::null();
    let status = unsafe { SecCodeCopySigningInformation(code.as_CFTypeRef(), 2, &mut information) };
    if status != 0 || information.is_null() {
        return Err(io::Error::other("code information unavailable"));
    }
    let information =
        unsafe { CFDictionary::<CFString, CFType>::wrap_under_create_rule(information) };
    let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoUnique) };
    let hash = information
        .find(&key)
        .and_then(|v| v.downcast::<CFData>())
        .ok_or_else(|| io::Error::other("code has no hash"))?;
    if !matches!(hash.len(), 20 | 32) {
        return Err(io::Error::other("unsupported code hash"));
    }
    let hash: String = hash.bytes().iter().map(|b| format!("{b:02x}")).collect();
    let text = format!("cdhash H\"{hash}\"");
    let requirement = text.parse().map_err(io::Error::other)?;
    code.check_validity(
        Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
        &requirement,
    )
    .map_err(io::Error::other)?;
    Ok(text)
}

fn string_value(info: &CFDictionary<CFString, CFType>, key: CFStringRef) -> Option<String> {
    let key = unsafe { CFString::wrap_under_get_rule(key) };
    info.find(&key)
        .and_then(|v| v.downcast::<CFString>())
        .map(|s| display_text(&s.to_string()))
}

fn bsd_info(pid: u32) -> io::Result<libc::proc_bsdinfo> {
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = size_of::<libc::proc_bsdinfo>() as i32;
    let result = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if result != size {
        return Err(io::Error::other("process exited or metadata unavailable"));
    }
    Ok(unsafe { info.assume_init() })
}

fn observed_process(pid: u32) -> io::Result<ObservedProcess> {
    let before = bsd_info(pid)?;
    let mut bytes = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let size =
        unsafe { libc::proc_pidpath(pid as i32, bytes.as_mut_ptr().cast(), bytes.len() as u32) };
    if size <= 0 {
        return Err(io::Error::other("process executable unavailable"));
    }
    let end = bytes
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| io::Error::other("invalid process path"))?;
    let executable = display_text(&String::from_utf8_lossy(&bytes[..end]));
    let after = bsd_info(pid)?;
    if (
        before.pbi_start_tvsec,
        before.pbi_start_tvusec,
        before.pbi_ppid,
    ) != (
        after.pbi_start_tvsec,
        after.pbi_start_tvusec,
        after.pbi_ppid,
    ) {
        return Err(io::Error::other("process changed during observation"));
    }
    let name = PathBuf::from(&executable)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    Ok(ObservedProcess {
        pid,
        parent_pid: before.pbi_ppid,
        name,
        executable,
        started: (before.pbi_start_tvsec, before.pbi_start_tvusec),
    })
}

fn ancestry(pid: u32) -> io::Result<(Vec<ObservedProcess>, bool)> {
    let mut result = vec![observed_process(pid)?];
    let mut complete = false;
    while result.len() < 6 {
        let parent = result.last().unwrap().parent_pid;
        if parent <= 1 {
            complete = true;
            break;
        }
        if result.iter().any(|p| p.pid == parent) {
            break;
        }
        let Ok(process) = observed_process(parent) else {
            break;
        };
        let child = result.last().unwrap();
        let Ok(current) = bsd_info(child.pid) else {
            break;
        };
        if !parent_link_is_current(child, &process, &current) {
            break;
        }
        result.push(process);
    }
    result.reverse();
    Ok((result, complete))
}

fn parent_link_is_current(
    child: &ObservedProcess,
    parent: &ObservedProcess,
    current: &libc::proc_bsdinfo,
) -> bool {
    child.started == (current.pbi_start_tvsec, current.pbi_start_tvusec)
        && child.parent_pid == current.pbi_ppid
        && child.parent_pid == parent.pid
        && parent.started <= child.started
}

fn display_text(value: &str) -> String {
    value.chars().filter(|c| !c.is_control() && !matches!(*c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')).take(512).collect()
}

#[cfg(test)]
#[path = "../tests/unit/peer_identity.rs"]
mod tests;
