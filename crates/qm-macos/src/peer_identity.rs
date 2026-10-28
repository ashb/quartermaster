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
struct ObservedAncestry {
    process_chain: Vec<String>,
    complete: bool,
    note: Option<String>,
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
    ancestry: ObservedAncestry,
    command_line: Option<String>,
    #[serde(skip)]
    started: (u64, u64),
    #[serde(skip)]
    audit_token: [u32; 8],
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
    pub ancestry_note: Option<String>,
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
            ancestry_complete: self.ancestry.complete,
            ancestry_note: self.ancestry.note.clone(),
            command_line: self.command_line.clone(),
        }
    }
    pub fn code_hash(&self) -> &str {
        &self.cd_hash
    }

    pub fn process_peer(
        &self,
        stream: &UnixStream,
    ) -> io::Result<crate::process_scope::ProcessPeer> {
        crate::process_scope::ProcessPeer::capture(stream, self.audit_token)
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
        if length as usize != size_of_val(&token) || token[5] != pid as u32 {
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
        let process = observed_process(pid as u32)?;
        let started = process.started;
        let ancestry = ancestry_with(process, bsd_info, process_path);
        let fresh = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
            .map_err(io::Error::other)?;
        fresh
            .check_validity(flags, &requirement)
            .map_err(io::Error::other)?;
        if crate::process_scope::peer_token(stream)? != token {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socket peer changed",
            ));
        }
        Ok(Self {
            pid: pid as u32,
            executable: display_text(&executable.to_string_lossy()),
            signing_identifier: identifier,
            team_identifier: team,
            cd_hash,
            ad_hoc,
            ancestry,
            command_line: None,
            started,
            audit_token: token,
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
        self.ancestry.process_chain.clone()
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
    if result <= 0 {
        return Err(io::Error::last_os_error());
    }
    if result != size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete process metadata",
        ));
    }
    Ok(unsafe { info.assume_init() })
}

fn observed_process(pid: u32) -> io::Result<ObservedProcess> {
    observed_process_with(pid, &mut bsd_info, &mut process_path)
}

fn process_path(pid: u32) -> io::Result<String> {
    let mut bytes = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let size =
        unsafe { libc::proc_pidpath(pid as i32, bytes.as_mut_ptr().cast(), bytes.len() as u32) };
    if size <= 0 {
        return Err(io::Error::last_os_error());
    }
    let end = bytes
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid process path"))?;
    Ok(display_text(&String::from_utf8_lossy(&bytes[..end])))
}

fn observed_process_with(
    pid: u32,
    info: &mut impl FnMut(u32) -> io::Result<libc::proc_bsdinfo>,
    path: &mut impl FnMut(u32) -> io::Result<String>,
) -> io::Result<ObservedProcess> {
    let before = info(pid)?;
    let executable = path(pid)?;
    let after = info(pid)?;
    if (
        before.pbi_start_tvsec,
        before.pbi_start_tvusec,
        before.pbi_ppid,
    ) != (
        after.pbi_start_tvsec,
        after.pbi_start_tvusec,
        after.pbi_ppid,
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "process changed during observation",
        ));
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

fn ancestry_with(
    peer: ObservedProcess,
    mut info: impl FnMut(u32) -> io::Result<libc::proc_bsdinfo>,
    mut path: impl FnMut(u32) -> io::Result<String>,
) -> ObservedAncestry {
    let pid = peer.pid;
    let mut result = vec![peer];
    let mut complete = false;
    let mut unavailable_ancestor = None;
    let mut note = Some("Earlier ancestors could not be inspected.".to_owned());
    while result.len() < 6 {
        let parent = result.last().unwrap().parent_pid;
        if parent <= 1 {
            complete = true;
            note = None;
            break;
        }
        if result.iter().any(|p| p.pid == parent) {
            break;
        }
        let process = match observed_process_with(parent, &mut info, &mut path) {
            Ok(process) => process,
            Err(error) => {
                if error.kind() == io::ErrorKind::InvalidData {
                    break;
                }
                let exited = error.raw_os_error() == Some(libc::ESRCH)
                    || error.kind() == io::ErrorKind::NotFound;
                let executable = if exited { None } else { path(parent).ok() };
                let child = result.last().unwrap();
                let Ok(current) = info(child.pid) else {
                    break;
                };
                if !child_link_is_current(child, &current) {
                    break;
                }
                let name = executable
                    .as_deref()
                    .and_then(|path| Path::new(path).file_name())
                    .and_then(|name| name.to_str())
                    .unwrap_or("Process");
                unavailable_ancestor = Some(format!("{name} · PID {parent} · limited information"));
                note = Some(
                    if error.kind() == io::ErrorKind::PermissionDenied {
                        "Earlier ancestors unavailable: macOS denied access to process information."
                    } else if exited {
                        "Earlier ancestors unavailable: the parent process exited."
                    } else {
                        "Earlier ancestors could not be inspected."
                    }
                    .to_owned(),
                );
                break;
            }
        };
        let child = result.last().unwrap();
        let Ok(current) = info(child.pid) else {
            break;
        };
        if !parent_link_is_current(child, &process, &current) {
            break;
        }
        result.push(process);
    }
    result.reverse();
    let process_chain = unavailable_ancestor
        .into_iter()
        .chain(result.iter().map(|p| {
            let name = if p.pid == pid {
                crate::process_display::display_name(Path::new(&p.executable), &p.name)
            } else {
                &p.name
            };
            format!("{name} · PID {}", p.pid)
        }))
        .collect();
    ObservedAncestry {
        process_chain,
        complete,
        note,
    }
}

fn parent_link_is_current(
    child: &ObservedProcess,
    parent: &ObservedProcess,
    current: &libc::proc_bsdinfo,
) -> bool {
    child_link_is_current(child, current)
        && child.parent_pid == parent.pid
        && parent.started <= child.started
}

fn child_link_is_current(child: &ObservedProcess, current: &libc::proc_bsdinfo) -> bool {
    child.started == (current.pbi_start_tvsec, current.pbi_start_tvusec)
        && child.parent_pid == current.pbi_ppid
}

fn display_text(value: &str) -> String {
    value.chars().filter(|c| !c.is_control() && !matches!(*c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')).take(512).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(pid: u32, parent_pid: u32, started: (u64, u64)) -> ObservedProcess {
        ObservedProcess {
            pid,
            parent_pid,
            name: "process".into(),
            executable: "/process".into(),
            started,
        }
    }

    #[test]
    fn unchanged_parent_link_can_be_displayed() {
        let parent = observation(10, 1, (100, 0));
        let child = observation(20, 10, (101, 0));
        let mut current: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        current.pbi_ppid = 10;
        current.pbi_start_tvsec = 101;
        assert!(parent_link_is_current(&child, &parent, &current));
    }

    #[test]
    fn pid_reuse_or_reparenting_cannot_extend_the_observed_chain() {
        let child = observation(20, 10, (101, 0));
        for (parent_started, child_started, current_parent) in [
            ((102, 0), (101, 0), 10),
            ((100, 0), (103, 0), 10),
            ((100, 0), (101, 0), 1),
        ] {
            let parent = observation(10, 1, parent_started);
            let mut current: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
            current.pbi_start_tvsec = child_started.0;
            current.pbi_start_tvusec = child_started.1;
            current.pbi_ppid = current_parent;
            assert!(!parent_link_is_current(&child, &parent, &current));
        }
    }

    fn fixture_info(pid: u32) -> io::Result<libc::proc_bsdinfo> {
        let (parent, started) = match pid {
            10 => return Err(io::Error::from_raw_os_error(libc::EPERM)),
            20 => (10, 200),
            30 => (20, 300),
            _ => panic!("unexpected PID {pid}"),
        };
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        info.pbi_ppid = parent;
        info.pbi_start_tvsec = started;
        Ok(info)
    }

    fn fixture_path(pid: u32) -> io::Result<String> {
        Ok(match pid {
            10 => "/usr/bin/login",
            20 => "/bin/zsh",
            30 => "/bin/gh",
            _ => panic!("unexpected PID {pid}"),
        }
        .into())
    }

    fn fixture_peer() -> ObservedProcess {
        ObservedProcess {
            name: "gh".into(),
            executable: "/bin/gh".into(),
            ..observation(30, 20, (300, 0))
        }
    }

    #[test]
    fn permission_denied_ancestor_keeps_its_available_path_and_explains_the_gap() {
        let ancestry = ancestry_with(fixture_peer(), fixture_info, fixture_path);
        assert_eq!(
            ancestry.process_chain,
            [
                "login · PID 10 · limited information",
                "zsh · PID 20",
                "gh · PID 30"
            ]
        );
        assert!(!ancestry.complete);
        assert_eq!(
            ancestry.note.as_deref(),
            Some("Earlier ancestors unavailable: macOS denied access to process information.")
        );
    }

    #[test]
    fn an_exited_ancestor_keeps_its_known_pid_without_a_stale_name() {
        let ancestry = ancestry_with(
            fixture_peer(),
            |pid| {
                if pid == 10 {
                    Err(io::Error::from_raw_os_error(libc::ESRCH))
                } else {
                    fixture_info(pid)
                }
            },
            fixture_path,
        );
        assert_eq!(
            ancestry.process_chain,
            [
                "Process · PID 10 · limited information",
                "zsh · PID 20",
                "gh · PID 30"
            ]
        );
        assert!(!ancestry.complete);
        assert_eq!(
            ancestry.note.as_deref(),
            Some("Earlier ancestors unavailable: the parent process exited.")
        );
    }

    #[test]
    fn an_unreadable_path_still_leaves_the_parent_pid_visible() {
        let ancestry = ancestry_with(fixture_peer(), fixture_info, |pid| {
            if pid == 10 {
                Err(io::Error::from_raw_os_error(libc::EPERM))
            } else {
                fixture_path(pid)
            }
        });
        assert_eq!(
            ancestry.process_chain,
            [
                "Process · PID 10 · limited information",
                "zsh · PID 20",
                "gh · PID 30"
            ]
        );
        assert!(!ancestry.complete);
    }

    #[test]
    fn a_changed_child_cannot_attach_a_partially_observed_parent() {
        for reused in [false, true] {
            let mut shell_reads = 0;
            let ancestry = ancestry_with(
                fixture_peer(),
                |pid| {
                    let mut info = fixture_info(pid)?;
                    if pid == 20 {
                        shell_reads += 1;
                        if shell_reads > 2 {
                            if reused {
                                info.pbi_start_tvsec += 1;
                            } else {
                                info.pbi_ppid = 1;
                            }
                        }
                    }
                    Ok(info)
                },
                fixture_path,
            );
            assert_eq!(ancestry.process_chain, ["zsh · PID 20", "gh · PID 30"]);
            assert!(!ancestry.complete);
            assert!(ancestry.note.is_some());
        }
    }

    #[test]
    fn missing_metadata_for_the_caller_still_fails_identity_capture() {
        let error = observed_process_with(
            30,
            &mut |_| Err(io::Error::from_raw_os_error(libc::EPERM)),
            &mut fixture_path,
        )
        .err()
        .unwrap();
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn a_complete_chain_has_no_missing_ancestor_notice() {
        let ancestry = ancestry_with(
            fixture_peer(),
            |pid| {
                if pid == 10 {
                    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
                    info.pbi_ppid = 1;
                    info.pbi_start_tvsec = 100;
                    Ok(info)
                } else {
                    fixture_info(pid)
                }
            },
            fixture_path,
        );
        assert_eq!(
            ancestry.process_chain,
            ["login · PID 10", "zsh · PID 20", "gh · PID 30"]
        );
        assert!(ancestry.complete);
        assert!(ancestry.note.is_none());
    }

    #[test]
    fn ancestry_remains_bounded_to_six_processes() {
        let ancestry = ancestry_with(
            observation(30, 29, (300, 0)),
            |pid| {
                assert!(pid >= 25, "walk exceeded the process limit");
                let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
                info.pbi_ppid = pid - 1;
                info.pbi_start_tvsec = u64::from(pid) * 10;
                Ok(info)
            },
            |_| Ok("/process".into()),
        );
        assert_eq!(ancestry.process_chain.len(), 6);
        assert!(!ancestry.complete);
        assert!(ancestry.note.is_some());
    }

    #[test]
    fn a_racing_ancestor_is_not_reattached_as_a_partial_process() {
        let mut login_reads = 0;
        let ancestry = ancestry_with(
            fixture_peer(),
            |pid| {
                if pid == 10 {
                    login_reads += 1;
                    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
                    info.pbi_ppid = 1;
                    info.pbi_start_tvsec = 100 + login_reads;
                    Ok(info)
                } else {
                    fixture_info(pid)
                }
            },
            fixture_path,
        );
        assert_eq!(ancestry.process_chain, ["zsh · PID 20", "gh · PID 30"]);
        assert!(!ancestry.complete);
        assert!(ancestry.note.is_some());
    }

    #[test]
    fn failed_native_metadata_queries_preserve_the_os_error() {
        let error = bsd_info(u32::MAX).err().unwrap();
        assert_eq!(error.raw_os_error(), Some(libc::ESRCH));
    }

    fn argument_buffer(arguments: &[&str]) -> Vec<u8> {
        let mut bytes = (arguments.len() as i32).to_ne_bytes().to_vec();
        bytes.extend(b"/nix/store/example/bin/.gh-wrapped\0\0\0\0\0\0");
        for argument in arguments {
            bytes.extend(argument.as_bytes());
            bytes.push(0);
        }
        bytes.extend(b"GH_ENTERPRISE_TOKEN=environment-canary\0");
        bytes
    }

    #[test]
    fn arbitrary_commands_keep_all_arguments_and_never_environment() {
        for arguments in [
            vec![
                "/nix/profile/bin/gh",
                "issue",
                "reopen",
                "1",
                "--repo",
                "ashb/example",
            ],
            vec!["wiff", "forge", "pull"],
            vec!["unfamiliar-tool", "new-action", "--new-flag=value"],
            vec!["tool", "--password", "caller-supplied-value"],
        ] {
            let displayed = command_line(&argument_buffer(&arguments)).unwrap();
            let mut expected = arguments.clone();
            expected[0] = Path::new(arguments[0])
                .file_name()
                .unwrap()
                .to_str()
                .unwrap();
            assert_eq!(displayed, expected.join(" "));
            assert!(!displayed.contains("environment-canary"));
        }
        assert_eq!(
            command_line(&argument_buffer(&[
                "gh",
                "api",
                "--jq",
                "{number,state,html_url}"
            ]))
            .unwrap(),
            "gh api --jq $'{number,state,html_url}'"
        );
    }

    #[test]
    fn native_arguments_preserve_empty_values_quotes_and_controls() {
        let bytes = argument_buffer(&["tool", "", "two words", "a'b", "line\n\u{202e}\u{1b}"]);
        assert_eq!(
            command_line(&bytes).unwrap(),
            "tool $'' $'two words' $'a\\'b' $'line\\n\\xe2\\x80\\xae\\x1b'"
        );
    }

    #[test]
    fn leading_empty_arguments_cannot_consume_environment_entries() {
        for (arguments, expected) in [
            (vec!["", "visible"], "$'' visible"),
            (vec!["", "", "visible"], "$'' $'' visible"),
            (vec![""], "$''"),
        ] {
            assert_eq!(
                command_line(&argument_buffer(&arguments)).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn path_alignment_preserves_empty_argv_at_every_padding_length() {
        for path in [
            b"/aaaaaa\0".as_slice(),
            b"/aaaaa\0\0",
            b"/aaaa\0\0\0",
            b"/aaa\0\0\0\0",
            b"/aa\0\0\0\0\0",
            b"/a\0\0\0\0\0\0",
            b"/\0\0\0\0\0\0\0",
            b"/aaaaaaa\0\0\0\0\0\0\0\0",
        ] {
            let mut bytes = 3i32.to_ne_bytes().to_vec();
            bytes.extend(path);
            bytes.extend(b"\0\0visible\0ENV=environment-canary\0");
            assert_eq!(command_line(&bytes).unwrap(), "$'' $'' visible");
        }
    }

    #[test]
    fn argument_count_is_bounded_by_the_capture_not_cli_syntax() {
        let mut arguments = vec!["tool"];
        arguments.extend(std::iter::repeat_n("--new-flag=value", 64));
        assert_eq!(
            command_line(&argument_buffer(&arguments)).unwrap(),
            arguments.join(" ")
        );
    }

    #[test]
    fn malformed_or_excessive_arguments_have_no_command_context() {
        let mut unterminated = 2i32.to_ne_bytes().to_vec();
        unterminated.extend(b"/bin/gh\0gh\0api");
        let mut invalid_utf8 = 1i32.to_ne_bytes().to_vec();
        invalid_utf8.extend(b"/bin/gh\0\xff\0");
        let mut full_buffer = argument_buffer(&["tool"]);
        full_buffer.resize(COMMAND_LINE_BYTES, 0);
        for bytes in [
            vec![],
            0i32.to_ne_bytes().to_vec(),
            33i32.to_ne_bytes().to_vec(),
            unterminated,
            invalid_utf8,
            full_buffer,
        ] {
            assert!(command_line(&bytes).is_none());
        }
    }
}
