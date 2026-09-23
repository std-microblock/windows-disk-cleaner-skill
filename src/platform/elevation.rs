//! Privilege detection only. The caller/agent obtains elevation; this process
//! never starts gsudo, launches UAC, changes cache policy or relaunches itself.
#[cfg(windows)]
use super::wide;
use anyhow::{Context, Result};
#[cfg(windows)]
use windows_sys::Win32::{Foundation::*, Security::*, System::Threading::*};

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
        "快速扫描需要管理员权限。请 agent 自行在管理员终端中重试同一命令（或使用已有提权工具）。本 CLI 不会自动提权、调用 gsudo 或弹出 UAC；如仅需普通目录枚举，可显式使用 --backend fs。"
    );
    Ok(())
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
