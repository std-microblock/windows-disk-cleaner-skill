//! Privilege handling. Elevation happens only when the caller passes --elevate:
//! the CLI then relaunches itself through the Windows UAC consent prompt and
//! relays the elevated child's stdout/stderr over Windows named pipes, so the
//! caller keeps seeing live, byte-exact output on its own streams. It never
//! starts gsudo, never changes UAC or credential-cache policy, and never
//! elevates implicitly.
//!
//! Only the shell's "runas" verb (ShellExecuteExW) can raise an unprivileged
//! process, and that call hands no handle to the child, so the child has to call
//! back over a kernel object both integrity levels can open: a named pipe pair,
//! the same shape gsudo's service bridge uses. No crates.io crate does this for
//! us, which is why the Win32 calls below stay in this file:
//!
//! * deelevate drops privileges: its spawn_with_elevated_privileges computes a
//!   *safer* normal-user token and never shows a consent prompt, so it cannot
//!   raise anything.
//! * elevator, windows-elevate, self-runas and runas-with-inherited-cmd wrap
//!   ShellExecuteExW in a few lines and either join arguments by hand or leave
//!   stdio to temp files (which is also what sudo-prompt does).
//! * runas-rs is a credential-based launcher for other user accounts.
//!
//! Temp files are kept as a fallback for machines that refuse named pipes, but
//! the pipes are the primary path: they keep output live and byte-exact, and
//! they survive a child that is killed halfway through.

use anyhow::Result;
use std::ffi::OsString;
use std::path::PathBuf;

/// Hidden flags that carry the caller's relay into the elevated child.
pub const STDOUT_FLAG: &str = "--elevation-stdout";
pub const STDERR_FLAG: &str = "--elevation-stderr";
pub const CWD_FLAG: &str = "--elevation-cwd";
pub const PARENT_FLAG: &str = "--elevation-parent";
pub const FALLBACK_FLAG: &str = "--elevation-fallback";

/// Everything the elevated child needs to get its output back to the caller.
#[derive(Debug, Clone)]
pub struct RelaySpec {
    /// Named pipe carrying this process' stdout.
    pub stdout: OsString,
    /// Named pipe carrying this process' stderr.
    pub stderr: OsString,
    /// Directory this process must run in; the shell cannot always supply one
    /// (an elevated logon session does not see the caller's mapped drives).
    pub cwd: Option<PathBuf>,
    /// Process this one should not outlive: the caller, whose shell may be killed.
    pub parent: Option<u32>,
    /// Last-resort output directory, used only when the pipes cannot be opened.
    pub fallback: Option<PathBuf>,
}

/// True when this process already holds what raw volume reads need: a
/// UAC-elevated token, or a high-integrity administrator token that never saw a
/// consent prompt (LocalSystem, ssh/psexec/scheduled-task logons).
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        win::is_elevated()
    }
    #[cfg(not(windows))]
    {
        false
    }
}
pub fn require_administrator() -> Result<()> {
    #[cfg(windows)]
    anyhow::ensure!(
        is_elevated(),
        "快速扫描需要管理员权限。请在同一个命令上加 --elevate 重试：CLI 会通过 Windows UAC 重新启动自身（一次弹窗，由用户同意），并把子进程输出实时回传到当前流；不调用 gsudo、不改 UAC 或凭据缓存策略。仅当用户明确要求普通目录枚举时才改用 --backend fs，并说明结果不完整。"
    );
    Ok(())
}

/// Caller side of --elevate: one UAC consent prompt, a live output relay, and the
/// elevated child's exit code. Blocks until the child exits.
pub fn relaunch_elevated() -> Result<i32> {
    #[cfg(windows)]
    {
        win::relaunch()
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("--elevate is a Windows-only option")
    }
}

/// Elevated child side: point stdout/stderr at the caller's relay, restore the
/// caller's working directory, and stay attached to the caller's lifetime.
pub fn attach_relay(spec: &RelaySpec) -> Result<()> {
    #[cfg(windows)]
    {
        win::attach(spec)
    }
    #[cfg(not(windows))]
    {
        let _ = spec;
        Ok(())
    }
}

/// Enable the administrator's existing backup privilege for READ-ONLY metadata
/// handles. This does not grant elevation, change ACLs, or enable restore/delete rights.
pub fn enable_backup_privilege() -> Result<()> {
    #[cfg(windows)]
    {
        win::enable_backup_privilege()
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

#[cfg(windows)]
mod win {
    use super::RelaySpec;
    use crate::platform::wide;
    use anyhow::{Context, Result, bail, ensure};
    use std::ffi::{OsStr, OsString};
    use std::io::Write;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_BROKEN_PIPE, ERROR_CANCELLED, ERROR_HANDLE_EOF, ERROR_IO_INCOMPLETE,
            ERROR_IO_PENDING, ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED, GENERIC_WRITE,
            GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Security::{
            AdjustTokenPrivileges, CheckTokenMembership, CreateWellKnownSid, GetSidSubAuthority,
            GetSidSubAuthorityCount, GetTokenInformation, LookupPrivilegeValueW,
            SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL,
            TOKEN_QUERY, TokenElevation, TokenIntegrityLevel, WELL_KNOWN_SID_TYPE,
            WinBuiltinAdministratorsSid, WinLocalSystemSid,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, PIPE_ACCESS_INBOUND, ReadFile,
            SYNCHRONIZE,
        },
        System::{
            Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx},
            Console::{STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle},
            Environment::SetCurrentDirectoryW,
            IO::{GetOverlappedResult, OVERLAPPED},
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
            },
            Threading::{
                CreateEventW, GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcess,
                OpenProcessToken, ResetEvent, WaitForMultipleObjects, WaitForSingleObject,
            },
        },
        UI::{
            Shell::{
                SEE_MASK_FLAG_NO_UI, SEE_MASK_NO_CONSOLE, SEE_MASK_NOCLOSEPROCESS,
                SHELLEXECUTEINFOW, ShellExecuteExW,
            },
            WindowsAndMessaging::SW_SHOWNORMAL,
        },
    };

    /// SECURITY_MANDATORY_HIGH_RID: the integrity level an administrator token runs at.
    const SECURITY_MANDATORY_HIGH_RID: u32 = 0x3000;
    /// ERROR_NOT_ALL_ASSIGNED: AdjustTokenPrivileges succeeded without granting.
    const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;
    /// Buffer each relay pipe hands to a single read.
    const PIPE_BUFFER: u32 = 64 * 1024;
    /// How long to keep draining a child that already exited.
    const DRAIN_MS: u32 = 5_000;

    /// Owns a kernel handle and closes it exactly once.
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    fn current_token(access: u32) -> Option<Handle> {
        let mut token: HANDLE = null_mut();
        (unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) } != 0)
            .then(|| Handle(token))
    }
    fn token_elevated(token: HANDLE) -> Option<bool> {
        let mut value: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
        let mut returned = 0u32;
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                (&mut value as *mut TOKEN_ELEVATION).cast(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        };
        (ok != 0).then_some(value.TokenIsElevated != 0)
    }
    /// The token's integrity level RID: 0x2000 medium, 0x3000 high, 0x4000 system.
    fn token_integrity(token: HANDLE) -> Option<u32> {
        let mut size = 0u32;
        unsafe { GetTokenInformation(token, TokenIntegrityLevel, null_mut(), 0, &mut size) };
        if size == 0 {
            return None;
        }
        let mut buffer = vec![0u8; size as usize];
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenIntegrityLevel,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        };
        if ok == 0 {
            return None;
        }
        // The SID lives inside the same buffer right behind the label, so the
        // label must be read in place instead of being copied out of it.
        let label = unsafe { &*(buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
        if label.Label.Sid.is_null() {
            return None;
        }
        let count = unsafe { *GetSidSubAuthorityCount(label.Label.Sid) } as u32;
        (count > 0).then(|| unsafe { *GetSidSubAuthority(label.Label.Sid, count - 1) })
    }
    fn token_has_well_known_sid(token: HANDLE, kind: WELL_KNOWN_SID_TYPE) -> bool {
        let mut size = 0u32;
        unsafe { CreateWellKnownSid(kind, null_mut(), null_mut(), &mut size) };
        if size == 0 {
            return false;
        }
        let mut buffer = vec![0u8; size as usize];
        let ok =
            unsafe { CreateWellKnownSid(kind, null_mut(), buffer.as_mut_ptr().cast(), &mut size) };
        if ok == 0 {
            return false;
        }
        let mut member = 0;
        let ok = unsafe { CheckTokenMembership(token, buffer.as_mut_ptr().cast(), &mut member) };
        ok != 0 && member != 0
    }

    pub(super) fn is_elevated() -> bool {
        let Some(token) = current_token(TOKEN_QUERY) else {
            return false;
        };
        if token_elevated(token.0).is_some_and(|elevated| elevated) {
            return true;
        }
        // TokenElevation stays 0 for high-integrity tokens that never went through
        // a consent prompt (LocalSystem, ssh/psexec/scheduled-task logons). Those
        // can read raw volumes too, and this answer only decides whether --elevate
        // has to ask for UAC at all, so they count as elevated here.
        token_integrity(token.0).is_some_and(|level| level >= SECURITY_MANDATORY_HIGH_RID)
            && (token_has_well_known_sid(token.0, WinBuiltinAdministratorsSid)
                || token_has_well_known_sid(token.0, WinLocalSystemSid))
    }

    pub(super) fn enable_backup_privilege() -> Result<()> {
        let token =
            current_token(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES).context("open privilege token")?;
        let mut luid = unsafe { std::mem::zeroed() };
        if unsafe { LookupPrivilegeValueW(null(), wide("SeBackupPrivilege").as_ptr(), &mut luid) }
            == 0
        {
            return Err(std::io::Error::last_os_error()).context("look up backup privilege");
        }
        let privileges = windows_sys::Win32::Security::TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [windows_sys::Win32::Security::LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        unsafe { windows_sys::Win32::Foundation::SetLastError(0) };
        let adjusted =
            unsafe { AdjustTokenPrivileges(token.0, 0, &privileges, 0, null_mut(), null_mut()) };
        ensure!(
            adjusted != 0 && unsafe { GetLastError() } != ERROR_NOT_ALL_ASSIGNED,
            "enable read-only backup privilege: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }

    /// The verb used to relaunch. Production always asks Windows for consent;
    /// CI and local verification can exercise the identical launch and relay path
    /// without a prompt by setting DISK_CLEANER_ELEVATION_VERB=open, in which case
    /// the child keeps the caller's own token.
    fn elevation_verb() -> Vec<u16> {
        match std::env::var("DISK_CLEANER_ELEVATION_VERB").as_deref() {
            Ok("open") => wide("open"),
            _ => wide("runas"),
        }
    }

    /// One of the caller's own streams, with just enough state to keep a split
    /// multi-byte UTF-8 character in a single write: a console sink rejects a
    /// write that ends mid-character.
    struct StreamWriter {
        sink: Sink,
        carry: Vec<u8>,
    }
    impl StreamWriter {
        fn new(sink: Sink) -> Self {
            Self {
                sink,
                carry: Vec::new(),
            }
        }
        fn write(&mut self, bytes: &[u8]) -> Result<()> {
            if bytes.is_empty() {
                return Ok(());
            }
            self.carry.extend_from_slice(bytes);
            let ready = writable_prefix(&self.carry);
            if ready == 0 {
                return Ok(());
            }
            let tail = self.carry.split_off(ready);
            let ready_bytes = std::mem::replace(&mut self.carry, tail);
            self.emit(&ready_bytes)
        }
        fn finish(&mut self) {
            if self.carry.is_empty() {
                return;
            }
            let bytes = std::mem::take(&mut self.carry);
            let _ = self.emit(&bytes);
        }
        fn emit(&self, bytes: &[u8]) -> Result<()> {
            let written = match self.sink {
                Sink::Stdout => {
                    let mut out = std::io::stdout().lock();
                    out.write_all(bytes).and_then(|()| out.flush())
                }
                Sink::Stderr => {
                    let mut err = std::io::stderr().lock();
                    err.write_all(bytes).and_then(|()| err.flush())
                }
            };
            match written {
                Ok(()) => Ok(()),
                // A console sink refuses bytes that are not valid UTF-8: the child
                // wrote something unprintable, which is not worth failing on.
                Err(error) if error.kind() == std::io::ErrorKind::InvalidData => Ok(()),
                Err(error) => Err(error).context("把提权子进程的输出写回当前流"),
            }
        }
    }

    /// How much of a buffered chunk can be written now: everything except a
    /// truncated UTF-8 sequence at the very end. Genuinely invalid bytes are not
    /// held back, or unprintable output would stall the relay forever.
    fn writable_prefix(carry: &[u8]) -> usize {
        match std::str::from_utf8(carry) {
            Ok(_) => carry.len(),
            Err(error) if error.error_len().is_none() => error.valid_up_to(),
            Err(_) => carry.len(),
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Sink {
        Stdout,
        Stderr,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Phase {
        Connecting,
        Reading,
        Done,
    }

    /// Server end of one relay pipe. An OVERLAPPED has to keep its address while
    /// an operation is in flight, so the one below lives on its own allocation.
    struct Pipe {
        name: OsString,
        handle: Handle,
        event: Handle,
        overlapped: Box<OVERLAPPED>,
        buffer: Vec<u8>,
        stream: StreamWriter,
        phase: Phase,
        pending: bool,
        failure: Option<u32>,
    }
    impl Pipe {
        fn listen(name: OsString, sink: Sink) -> Result<Self> {
            let path = wide(&name);
            let handle = unsafe {
                CreateNamedPipeW(
                    path.as_ptr(),
                    PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    1,
                    0,
                    PIPE_BUFFER,
                    0,
                    null(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error())
                    .context("创建提权输出管道（命名管道被安全策略禁用？）");
            }
            let handle = Handle(handle);
            let event = unsafe { CreateEventW(null(), 1, 0, null()) };
            if event.is_null() {
                return Err(std::io::Error::last_os_error()).context("创建提权输出事件");
            }
            Ok(Self {
                name,
                handle,
                event: Handle(event),
                overlapped: Box::new(unsafe { std::mem::zeroed() }),
                buffer: vec![0u8; PIPE_BUFFER as usize],
                stream: StreamWriter::new(sink),
                phase: Phase::Connecting,
                pending: false,
                failure: None,
            })
        }
        /// Drive this pipe forward until an operation is genuinely in flight.
        fn advance(&mut self) -> Result<()> {
            while self.phase != Phase::Done {
                if self.pending {
                    let completed = match self.phase {
                        Phase::Connecting => self.finish_connect(),
                        _ => self.finish_read()?,
                    };
                    if !completed {
                        break;
                    }
                } else if self.phase == Phase::Connecting {
                    self.begin_connect();
                } else {
                    self.begin_read()?;
                }
            }
            Ok(())
        }
        fn begin_connect(&mut self) {
            self.overlapped.hEvent = self.event.0;
            self.pending = true;
            unsafe { ResetEvent(self.event.0) };
            if unsafe { ConnectNamedPipe(self.handle.0, &mut *self.overlapped) } != 0 {
                self.connected();
                return;
            }
            match unsafe { GetLastError() } {
                ERROR_IO_PENDING => {}
                ERROR_PIPE_CONNECTED => self.connected(),
                error => self.fail(error),
            }
        }
        fn finish_connect(&mut self) -> bool {
            let mut transferred = 0u32;
            if unsafe { GetOverlappedResult(self.handle.0, &*self.overlapped, &mut transferred, 0) }
                != 0
            {
                self.connected();
                return true;
            }
            match unsafe { GetLastError() } {
                ERROR_IO_INCOMPLETE => false,
                ERROR_PIPE_CONNECTED => {
                    self.connected();
                    true
                }
                error => {
                    self.fail(error);
                    true
                }
            }
        }
        fn begin_read(&mut self) -> Result<()> {
            self.overlapped.hEvent = self.event.0;
            self.pending = true;
            unsafe { ResetEvent(self.event.0) };
            let mut read = 0u32;
            let ok = unsafe {
                ReadFile(
                    self.handle.0,
                    self.buffer.as_mut_ptr(),
                    self.buffer.len() as u32,
                    &mut read,
                    &mut *self.overlapped,
                )
            };
            if ok != 0 {
                self.pending = false;
                return self.deliver(read);
            }
            match unsafe { GetLastError() } {
                ERROR_IO_PENDING => Ok(()),
                ERROR_BROKEN_PIPE | ERROR_HANDLE_EOF => {
                    self.done();
                    Ok(())
                }
                error => {
                    self.fail(error);
                    Ok(())
                }
            }
        }
        fn finish_read(&mut self) -> Result<bool> {
            let mut read = 0u32;
            let ok =
                unsafe { GetOverlappedResult(self.handle.0, &*self.overlapped, &mut read, 0) } != 0;
            if ok {
                self.pending = false;
                self.deliver(read)?;
                return Ok(true);
            }
            match unsafe { GetLastError() } {
                ERROR_IO_INCOMPLETE => Ok(false),
                ERROR_BROKEN_PIPE | ERROR_HANDLE_EOF | ERROR_OPERATION_ABORTED => {
                    self.done();
                    Ok(true)
                }
                error => {
                    self.fail(error);
                    Ok(true)
                }
            }
        }
        fn deliver(&mut self, bytes: u32) -> Result<()> {
            if bytes == 0 {
                self.done();
                return Ok(());
            }
            let (stream, buffer) = (&mut self.stream, &self.buffer);
            stream.write(&buffer[..bytes as usize])
        }
        fn connected(&mut self) {
            self.phase = Phase::Reading;
            self.pending = false;
        }
        fn done(&mut self) {
            self.phase = Phase::Done;
            self.pending = false;
        }
        fn fail(&mut self, error: u32) {
            self.failure = Some(error);
            self.done();
        }
    }

    struct Relay {
        pipes: Vec<Pipe>,
        fallback: PathBuf,
    }
    impl Relay {
        fn listen() -> Result<Self> {
            let id = uuid::Uuid::new_v4().simple();
            let prefix = format!(r"\\.\pipe\disk-cleaner-{}-{id}", std::process::id());
            let fallback = std::env::temp_dir().join(format!(
                "disk-cleaner-elevation-{}-{id}",
                std::process::id()
            ));
            Ok(Self {
                pipes: vec![
                    Pipe::listen(OsString::from(format!("{prefix}-stdout")), Sink::Stdout)?,
                    Pipe::listen(OsString::from(format!("{prefix}-stderr")), Sink::Stderr)?,
                ],
                fallback,
            })
        }
        fn stdout_name(&self) -> &OsStr {
            self.pipes[0].name.as_os_str()
        }
        fn stderr_name(&self) -> &OsStr {
            self.pipes[1].name.as_os_str()
        }
        /// Stream both pipes until the child exited and its output is drained,
        /// then return the child's own exit code.
        fn pump(&mut self, process: HANDLE) -> Result<i32> {
            let mut exited = false;
            let mut exit_code = 1u32;
            loop {
                // A pipe that is not waiting on the kernel has to start its next
                // operation now; otherwise nobody would ever read the child.
                for pipe in &mut self.pipes {
                    pipe.advance()?;
                }
                if exited && self.pipes.iter().all(|pipe| !pipe.pending) {
                    break;
                }
                let mut waits: Vec<HANDLE> = Vec::with_capacity(self.pipes.len() + 1);
                if !exited {
                    waits.push(process);
                }
                for pipe in &self.pipes {
                    if pipe.pending {
                        waits.push(pipe.event.0);
                    }
                }
                let timeout = if exited { DRAIN_MS } else { INFINITE };
                let signalled = unsafe {
                    WaitForMultipleObjects(waits.len() as u32, waits.as_ptr(), 0, timeout)
                };
                if signalled == WAIT_TIMEOUT {
                    break;
                }
                if signalled == WAIT_FAILED {
                    bail!("等待提权子进程失败: {}", std::io::Error::last_os_error());
                }
                let slot = (signalled - WAIT_OBJECT_0) as usize;
                if !exited && slot == 0 {
                    exited = true;
                    ensure!(
                        unsafe { GetExitCodeProcess(process, &mut exit_code) } != 0,
                        "读取提权子进程退出码失败: {}",
                        std::io::Error::last_os_error()
                    );
                }
            }
            self.finish_streams();
            let missing = self.unconnected();
            if missing.is_empty() {
                // The fallback directory only exists when a pipe was unusable; a
                // relayed run owns nothing there and can drop it.
                let _ = std::fs::remove_dir_all(&self.fallback);
                return Ok(exit_code as i32);
            }
            eprintln!(
                "警告：提权子进程（退出码 {exit_code}）没有接上输出管道（{}）；可能是安全软件拦截了命名管道，或子进程在接管输出前就退出了。正在尝试它留下的回退文件 {}。",
                missing.join("、"),
                self.fallback.display()
            );
            let replayed = match replay_fallback(&self.fallback) {
                Ok(bytes) => bytes,
                Err(error) => {
                    eprintln!("警告：读取提权回退文件失败：{error:#}");
                    0
                }
            };
            // An exit code of 0 without any output the caller could see would let
            // it report a success nobody can check, so fail loudly instead.
            Ok(if exit_code == 0 && replayed == 0 {
                1
            } else {
                exit_code as i32
            })
        }
        fn finish_streams(&mut self) {
            for pipe in &mut self.pipes {
                pipe.stream.finish();
            }
        }
        fn unconnected(&self) -> Vec<String> {
            self.pipes
                .iter()
                .filter(|pipe| pipe.phase == Phase::Connecting)
                .map(|pipe| match pipe.failure {
                    Some(error) => format!("{}（管道错误 {error}）", pipe.name.to_string_lossy()),
                    None => pipe.name.to_string_lossy().into_owned(),
                })
                .collect()
        }
    }

    /// Last resort on the caller side: replay whatever the child managed to write
    /// into the fallback directory when the pipes could not be used, and report
    /// how many bytes that was.
    fn replay_fallback(directory: &Path) -> Result<usize> {
        let mut total = 0;
        for (name, sink) in [("stdout.txt", Sink::Stdout), ("stderr.txt", Sink::Stderr)] {
            let path = directory.join(name);
            match std::fs::read(&path) {
                Ok(bytes) => {
                    total += bytes.len();
                    let mut stream = StreamWriter::new(sink);
                    stream.write(&bytes)?;
                    stream.finish();
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("读取提权回退文件 {}", path.display()));
                }
            }
        }
        Ok(total)
    }

    pub(super) fn attach(spec: &RelaySpec) -> Result<()> {
        match connect_pipes(spec.stdout.as_os_str(), spec.stderr.as_os_str()) {
            Ok((stdout, stderr)) => {
                unsafe {
                    SetStdHandle(STD_OUTPUT_HANDLE, stdout.0);
                    SetStdHandle(STD_ERROR_HANDLE, stderr.0);
                }
                // The handles have to outlive every write in this process.
                std::mem::forget(stdout);
                std::mem::forget(stderr);
            }
            Err(error) => install_fallback(spec, &error)?,
        }
        // An elevated logon session does not see the caller's mapped drives, so
        // the directory the shell handed us may be wrong. Every relative path in
        // this CLI (--plan, --save, .disk-cleaner) depends on getting this right.
        if let Some(cwd) = &spec.cwd {
            enter_directory(cwd)?;
        }
        // Without this, killing the caller's shell would leave an elevated scan
        // running with nobody left to read its output.
        if let Some(parent) = spec.parent {
            watch_parent(parent);
        }
        if !is_elevated() {
            eprintln!(
                "警告：提权子进程没有拿到管理员权限（UAC 结果没有生效，或被安全策略拦下）；本轮按当前权限继续，需要管理员的步骤会失败。"
            );
        }
        Ok(())
    }

    fn connect_pipes(stdout: &OsStr, stderr: &OsStr) -> Result<(Handle, Handle)> {
        let out = open_pipe(stdout)?;
        let err = open_pipe(stderr)?;
        Ok((out, err))
    }
    fn open_pipe(name: &OsStr) -> Result<Handle> {
        let path = wide(name);
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("连接命名管道 {}", name.to_string_lossy()));
        }
        Ok(Handle(handle))
    }
    fn install_fallback(spec: &RelaySpec, pipe_error: &anyhow::Error) -> Result<()> {
        let directory = spec
            .fallback
            .as_deref()
            .context("提权调用方没有提供回退输出目录")?;
        std::fs::create_dir_all(directory)
            .with_context(|| format!("创建提权回退目录 {}", directory.display()))?;
        let stdout = open_report(&directory.join("stdout.txt"))?;
        let stderr = open_report(&directory.join("stderr.txt"))?;
        unsafe {
            SetStdHandle(STD_OUTPUT_HANDLE, stdout.as_raw_handle().cast());
            SetStdHandle(STD_ERROR_HANDLE, stderr.as_raw_handle().cast());
        }
        // The handles have to outlive every write in this process.
        std::mem::forget(stdout);
        std::mem::forget(stderr);
        eprintln!(
            "警告：无法连接提权调用方的命名管道（{pipe_error:#}）；已改用临时文件回传输出，调用方会在本次运行结束后读取。"
        );
        Ok(())
    }
    fn open_report(path: &Path) -> Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)
            .with_context(|| format!("打开提权回退文件 {}", path.display()))
    }
    fn enter_directory(path: &Path) -> Result<()> {
        let directory = wide(path);
        if unsafe { SetCurrentDirectoryW(directory.as_ptr()) } != 0 {
            return Ok(());
        }
        bail!(
            "提权子进程无法进入工作目录 {}：{}。提权后的进程看不到调用方映射的网络驱动器，请改用本地工作目录，或给 --plan/--save 传绝对路径。",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    fn watch_parent(pid: u32) {
        // SYNCHRONIZE is enough to wait; the handle stays open for the life of the
        // watchdog thread on purpose.
        let parent = unsafe { OpenProcess(SYNCHRONIZE, 0, pid) };
        if parent.is_null() {
            return;
        }
        // Handles are raw pointers and so are not Send; the thread only waits.
        let parent = parent as usize;
        std::thread::spawn(move || {
            unsafe { WaitForSingleObject(parent as HANDLE, INFINITE) };
            // 130 is the usual "terminated by Ctrl+C" status: the caller is gone,
            // so an elevated run nobody can read should stop instead of finishing.
            std::process::exit(130);
        });
    }

    pub(super) fn relaunch() -> Result<i32> {
        let mut relay = Relay::listen()?;
        let cwd = std::env::current_dir().context("current working directory")?;
        let executable = std::env::current_exe().context("locate this executable")?;
        let parameters = child_command_line(&relay, &cwd);
        eprintln!(
            "请求管理员权限：将通过 UAC 以管理员身份重新运行同一命令（一次弹窗，需要用户同意）；子进程输出会实时回传。"
        );
        let process = shell_execute(&executable, &parameters, &cwd)?;
        relay.pump(process.0)
    }

    fn shell_execute(executable: &Path, parameters: &[u16], cwd: &Path) -> Result<Handle> {
        // The shell may use COM for this verb, and MSDN asks callers to have COM
        // initialized. RPC_E_CHANGED_MODE only means someone already chose a
        // model, which is fine.
        unsafe {
            CoInitializeEx(
                null(),
                (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
            );
        }
        let verb = elevation_verb();
        let file = wide(executable);
        let directory = wide(cwd);
        let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        // One consent prompt, no second console, no error dialog, and a process
        // handle so the caller can wait and adopt the child's exit code.
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE | SEE_MASK_FLAG_NO_UI;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = parameters.as_ptr();
        info.lpDirectory = directory.as_ptr();
        info.nShow = SW_SHOWNORMAL;
        if unsafe { ShellExecuteExW(&mut info) } == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_CANCELLED as i32) {
                bail!(
                    "用户取消了 UAC 提权（ERROR_CANCELLED）；未执行任何扫描或标记。如需普通目录枚举，请显式使用 --backend fs 并说明范围不完整。"
                );
            }
            return Err(error).context("ShellExecuteExW(runas)");
        }
        ensure!(!info.hProcess.is_null(), "UAC 提权没有返回进程句柄");
        Ok(Handle(info.hProcess))
    }

    /// The elevated child runs the same command minus --elevate, plus the hidden
    /// flags that carry the relay, the working directory, and the caller's pid.
    fn child_command_line(relay: &Relay, cwd: &Path) -> Vec<u16> {
        let mut line: Vec<u16> = Vec::new();
        for argument in std::env::args_os().skip(1) {
            if argument == "--elevate" {
                continue;
            }
            push_argument(&mut line, &argument);
        }
        let pid = std::process::id().to_string();
        let extra: [(&str, &OsStr); 5] = [
            (super::STDOUT_FLAG, relay.stdout_name()),
            (super::STDERR_FLAG, relay.stderr_name()),
            (super::CWD_FLAG, cwd.as_os_str()),
            (super::PARENT_FLAG, OsStr::new(&pid)),
            (super::FALLBACK_FLAG, relay.fallback.as_os_str()),
        ];
        for (flag, value) in extra {
            push_argument(&mut line, OsStr::new(flag));
            push_argument(&mut line, value);
        }
        line.push(0);
        line
    }
    /// Arguments keep their original encoding and are quoted the way the child's
    /// own parser (CommandLineToArgvW rules, which Rust's std implements) reads
    /// them back.
    fn push_argument(line: &mut Vec<u16>, argument: &OsStr) {
        if !line.is_empty() {
            line.push(b' ' as u16);
        }
        line.extend(quote(argument));
    }
    fn quote(argument: &OsStr) -> Vec<u16> {
        let text: Vec<u16> = argument.encode_wide().collect();
        let quotes = text.is_empty() || text.iter().any(|c| matches!(*c, 0x20 | 0x09 | 0x22));
        if !quotes {
            return text;
        }
        let mut out = vec![b'"' as u16];
        let mut backslashes = 0usize;
        for character in text {
            if character == b'\\' as u16 {
                backslashes += 1;
                continue;
            }
            if character == b'"' as u16 {
                out.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
            } else {
                out.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
            }
            out.push(character);
            backslashes = 0;
        }
        out.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
        out.push(b'"' as u16);
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::windows::ffi::OsStringExt;
        use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

        fn parse(line: &[u16]) -> Vec<String> {
            let mut count = 0i32;
            let argv = unsafe { CommandLineToArgvW(line.as_ptr(), &mut count) };
            assert!(!argv.is_null(), "CommandLineToArgvW failed");
            let mut parsed = Vec::new();
            for index in 0..count as usize {
                let wide = unsafe { *argv.add(index) };
                let len = (0..)
                    .take_while(|offset| unsafe { *wide.add(*offset) } != 0)
                    .count();
                let text = unsafe { std::slice::from_raw_parts(wide, len) };
                parsed.push(OsString::from_wide(text).to_string_lossy().into_owned());
            }
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(argv.cast());
            }
            parsed
        }

        #[test]
        fn arguments_survive_the_child_command_line() {
            let arguments = [
                "--plan",
                r"C:\work\clean targets.json",
                "--save",
                r".disk-cleaner\a b\中文 Δ.dcscan",
                "scan",
                r"\\?\D:\a'b\c d\",
                r"trailing\\",
                r#"quote"inside"#,
                "tab\tseparated",
                "",
                "--reason",
                "C:\\with\\backslashes\\",
            ];
            // The child parses a full command line, so every token after the
            // executable path is an ordinary quoted argument.
            let mut line = wide(r"C:\tools\disk-cleaner.exe");
            line.pop();
            for argument in arguments {
                push_argument(&mut line, OsStr::new(argument));
            }
            line.push(0);
            let parsed = parse(&line);
            assert_eq!(parsed[0], r"C:\tools\disk-cleaner.exe");
            assert_eq!(parsed[1..], arguments);
        }

        #[test]
        fn only_a_truncated_utf8_tail_is_held_back() {
            assert_eq!(writable_prefix(b"abcdef"), 6);
            assert_eq!(writable_prefix(b"abc"), 3);
            // A multi-byte character that arrived in one piece is ready.
            assert_eq!(writable_prefix("中文".as_bytes()), 6);
            // Half a character waits for the rest.
            assert_eq!(writable_prefix(&"中".as_bytes()[..2]), 0);
            assert_eq!(writable_prefix(b"abc\xe4\xb8"), 3);
            // Bytes that are not UTF-8 at all are passed on, not buffered forever.
            assert_eq!(writable_prefix(b"abc\xff\xfe"), 5);
        }

        #[test]
        fn fallback_files_keep_their_order() {
            let directory = std::env::temp_dir().join(format!(
                "disk-cleaner-fallback-test-{}",
                uuid::Uuid::new_v4().simple()
            ));
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join("stdout.txt"), b"first\nsecond\n").unwrap();
            std::fs::write(directory.join("stderr.txt"), b"").unwrap();
            // Only reaching the files is asserted here; the streams themselves are
            // covered end to end by tests/elevation_relay.rs.
            assert_eq!(replay_fallback(&directory).unwrap(), 13);
            let _ = std::fs::remove_dir_all(&directory);
        }
    }
}
