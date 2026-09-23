//! Privilege handling. Elevation happens only when the caller passes --elevate:
//! the CLI then relaunches itself through the Windows UAC consent prompt and
//! replays the elevated child's output. It never starts gsudo, never changes UAC
//! or credential-cache policy, and never elevates implicitly.
#[cfg(windows)]
use super::wide;
use anyhow::{Context, Result};
#[cfg(windows)]
use std::path::Path;
#[cfg(windows)]
use std::{ffi::OsStr, io::Write, os::windows::io::AsRawHandle};
#[cfg(windows)]
use windows_sys::Win32::{Foundation::*, Security::*, System::Threading::*};

/// Internal flag used by an elevated child: its stdout/stderr are written into
/// this directory so the parent process can replay them on the caller's streams.
pub const REPORT_FLAG: &str = "--elevation-report";
#[cfg(windows)]
const STDOUT_REPORT: &str = "stdout.txt";
#[cfg(windows)]
const STDERR_REPORT: &str = "stderr.txt";

pub fn is_elevated() -> bool {
    #[cfg(windows)]
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut len = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of_val(&elevation) as u32,
            &mut len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
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
        "快速扫描需要管理员权限。请在同一个命令上加 --elevate 重试：CLI 会通过 Windows UAC 重新启动自身（一次弹窗，由用户同意），并在结束后把子进程输出原样回传；不调用 gsudo、不改 UAC 或凭据缓存策略。仅当用户明确要求普通目录枚举时才改用 --backend fs，并说明结果不完整。"
    );
    Ok(())
}

/// Parent side of --elevate: start this same command through the UAC consent
/// prompt, wait for it, relay its output and adopt its exit code.
#[cfg(windows)]
pub fn relaunch_elevated() -> Result<i32> {
    use windows_sys::Win32::UI::{
        Shell::{
            SEE_MASK_FLAG_NO_UI, SEE_MASK_NO_CONSOLE, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
            ShellExecuteExW,
        },
        WindowsAndMessaging::SW_SHOWNORMAL,
    };
    let report = std::env::temp_dir().join(format!(
        "disk-cleaner-elevation-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&report).context("create elevation report directory")?;
    let executable = std::env::current_exe().context("locate this executable")?;
    let directory = std::env::current_dir().context("current working directory")?;
    let verb = wide("runas");
    let file = wide(&executable);
    let parameters = child_command_line(&report);
    let working = wide(&directory);
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    // No new console: the child reports through files, the caller keeps its own.
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE | SEE_MASK_FLAG_NO_UI;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = parameters.as_ptr();
    info.lpDirectory = working.as_ptr();
    info.nShow = SW_SHOWNORMAL;
    eprintln!(
        "请求管理员权限：将通过 UAC 以管理员身份重新运行同一命令（一次弹窗，需要用户同意）；子进程输出会在结束后原样回传。"
    );
    let started = unsafe { ShellExecuteExW(&mut info) };
    if started == 0 {
        let error = std::io::Error::last_os_error();
        cleanup(&report);
        if error.raw_os_error() == Some(1223) {
            anyhow::bail!(
                "用户取消了 UAC 提权（ERROR_CANCELLED）；未执行任何扫描或标记。如需普通目录枚举，请显式使用 --backend fs 并说明范围不完整。"
            );
        }
        return Err(error).context("ShellExecuteExW(runas)");
    }
    if info.hProcess.is_null() {
        cleanup(&report);
        anyhow::bail!("UAC 提权没有返回进程句柄");
    }
    let waited = unsafe { WaitForSingleObject(info.hProcess, INFINITE) };
    let mut exit: u32 = 1;
    let read = unsafe { GetExitCodeProcess(info.hProcess, &mut exit) };
    unsafe { CloseHandle(info.hProcess) };
    anyhow::ensure!(waited == WAIT_OBJECT_0 && read != 0, "等待提权进程失败");
    let stdout = std::fs::read_to_string(report.join(STDOUT_REPORT)).unwrap_or_default();
    let stderr = std::fs::read_to_string(report.join(STDERR_REPORT)).unwrap_or_default();
    if !stdout.is_empty() {
        let mut out = std::io::stdout().lock();
        out.write_all(stdout.as_bytes())?;
        out.flush()?;
    }
    if !stderr.is_empty() {
        let mut err = std::io::stderr().lock();
        err.write_all(stderr.as_bytes())?;
        err.flush()?;
    }
    cleanup(&report);
    Ok(exit as i32)
}
#[cfg(not(windows))]
pub fn relaunch_elevated() -> Result<i32> {
    anyhow::bail!("--elevate is a Windows-only option")
}

/// Child side of --elevate: point this process' stdout and stderr at the report
/// files, so nothing depends on a console the elevated child may not own.
pub fn redirect_output(directory: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::{
            STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
        };
        std::fs::create_dir_all(directory).context("create elevation report directory")?;
        let open = |name: &str| -> Result<std::fs::File> {
            std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(directory.join(name))
                .with_context(|| format!("open elevation report {name}"))
        };
        let stdout = open(STDOUT_REPORT)?;
        let stderr = open(STDERR_REPORT)?;
        unsafe {
            SetStdHandle(STD_OUTPUT_HANDLE, stdout.as_raw_handle() as HANDLE);
            SetStdHandle(STD_ERROR_HANDLE, stderr.as_raw_handle() as HANDLE);
        }
        // The handles must outlive every write in this process; keep them open.
        std::mem::forget(stdout);
        std::mem::forget(stderr);
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = directory;
        Ok(())
    }
}

#[cfg(windows)]
fn cleanup(directory: &Path) {
    let _ = std::fs::remove_dir_all(directory);
}
/// The elevated child receives the same arguments minus --elevate, plus the
/// internal report flag. Arguments keep their original encoding and quoting.
#[cfg(windows)]
fn child_command_line(report: &Path) -> Vec<u16> {
    let mut line: Vec<u16> = Vec::new();
    for argument in std::env::args_os().skip(1) {
        if argument == "--elevate" {
            continue;
        }
        if !line.is_empty() {
            line.push(b' ' as u16);
        }
        line.extend(quote(&argument));
    }
    for argument in [OsStr::new(REPORT_FLAG), report.as_os_str()] {
        line.push(b' ' as u16);
        line.extend(quote(argument));
    }
    line.push(0);
    line
}
#[cfg(windows)]
fn quote(argument: &OsStr) -> Vec<u16> {
    let text: Vec<u16> = std::os::windows::ffi::OsStrExt::encode_wide(argument).collect();
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

/// Enable the administrator's existing backup privilege for READ-ONLY metadata
/// handles. This does not grant elevation, change ACLs, or enable restore/delete rights.
pub fn enable_backup_privilege() -> Result<()> {
    #[cfg(windows)]
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return Err(std::io::Error::last_os_error()).context("open privilege token");
        }
        struct Guard(HANDLE);
        impl Drop for Guard {
            fn drop(&mut self) {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
        let _guard = Guard(token);
        let mut luid: LUID = std::mem::zeroed();
        if LookupPrivilegeValueW(
            std::ptr::null(),
            wide("SeBackupPrivilege").as_ptr(),
            &mut luid,
        ) == 0
        {
            return Err(std::io::Error::last_os_error()).context("look up backup privilege");
        }
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        SetLastError(0);
        if AdjustTokenPrivileges(
            token,
            0,
            &privileges,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 0
            || GetLastError() == ERROR_NOT_ALL_ASSIGNED
        {
            return Err(std::io::Error::last_os_error())
                .context("enable read-only backup privilege");
        }
    }
    Ok(())
}
