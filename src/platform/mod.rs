//! Narrow, read-only Win32 metadata helpers. Destructive APIs live in deletion.rs.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::os::windows::{
    ffi::{OsStrExt, OsStringExt},
    fs::OpenOptionsExt,
    io::{AsRawHandle, FromRawHandle},
};
use std::{
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::*,
    System::{IO::DeviceIoControl, Ioctl::*, ProcessStatus::*, Threading::GetCurrentProcess},
};

pub mod elevation;

pub fn modified_unix_ms(raw: i64) -> Option<i64> {
    #[cfg(windows)]
    {
        if raw <= 0 {
            None
        } else {
            Some(raw / 10_000 - 11_644_473_600_000)
        }
    }
    #[cfg(not(windows))]
    {
        raw.checked_mul(1000)
    }
}
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
#[cfg(windows)]
pub fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}
pub fn encode_name(s: &OsStr) -> Vec<u16> {
    #[cfg(windows)]
    {
        s.encode_wide().collect()
    }
    #[cfg(not(windows))]
    {
        s.to_string_lossy().encode_utf16().collect()
    }
}
pub fn decode_name(s: &[u16]) -> OsString {
    #[cfg(windows)]
    {
        OsString::from_wide(s)
    }
    #[cfg(not(windows))]
    {
        OsString::from(String::from_utf16_lossy(s))
    }
}
pub fn display_path(p: &Path) -> String {
    let s = p.to_string_lossy();
    s.strip_prefix(r"\\?\UNC\")
        .map(|s| format!(r"\\{s}"))
        .unwrap_or_else(|| s.strip_prefix(r"\\?\").unwrap_or(&s).to_owned())
}
/// Windows comparisons are component-aware, not vulnerable to C:\foo vs C:\foobar.
pub fn path_key(p: &Path) -> String {
    display_path(p)
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}
pub fn within(path: &Path, parent: &Path) -> bool {
    let p = path_key(path);
    let r = path_key(parent);
    p == r || p.strip_prefix(&r).is_some_and(|s| s.starts_with('\\'))
}
pub fn absolute(p: &Path) -> Result<PathBuf> {
    std::path::absolute(p).context("resolve absolute path")
}
pub fn canonical(p: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(p).with_context(|| format!("resolve {}", p.display()))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VolumeInfo {
    pub root: PathBuf,
    pub device: String,
    pub filesystem: String,
    pub serial: u32,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub cluster_bytes: u32,
}
#[cfg(windows)]
pub fn volume_info(path: &Path) -> Result<VolumeInfo> {
    let abs = absolute(path)?;
    let mut root = vec![0u16; 32768];
    unsafe {
        if GetVolumePathNameW(wide(&abs).as_ptr(), root.as_mut_ptr(), root.len() as u32) == 0 {
            return Err(std::io::Error::last_os_error()).context("GetVolumePathNameW");
        }
    }
    root.truncate(root.iter().position(|&v| v == 0).unwrap_or(root.len()));
    let root_path = PathBuf::from(decode_name(&root));
    let wr = wide(&root_path);
    let (mut fsname, mut guid) = ([0u16; 64], [0u16; 128]);
    let mut serial = 0;
    let (mut total, mut free) = (0, 0);
    let (mut sectors, mut sector_bytes, mut a, mut b) = (0, 0, 0, 0);
    unsafe {
        if GetVolumeInformationW(
            wr.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut serial,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            fsname.as_mut_ptr(),
            fsname.len() as u32,
        ) == 0
        {
            return Err(std::io::Error::last_os_error()).context("GetVolumeInformationW");
        }
        if GetDiskFreeSpaceExW(wr.as_ptr(), std::ptr::null_mut(), &mut total, &mut free) == 0 {
            return Err(std::io::Error::last_os_error()).context("GetDiskFreeSpaceExW");
        }
        GetDiskFreeSpaceW(wr.as_ptr(), &mut sectors, &mut sector_bytes, &mut a, &mut b);
        if GetVolumeNameForVolumeMountPointW(wr.as_ptr(), guid.as_mut_ptr(), guid.len() as u32) == 0
        {
            return Err(std::io::Error::last_os_error())
                .context("GetVolumeNameForVolumeMountPointW (local volumes only)");
        }
    }
    let filesystem = String::from_utf16_lossy(
        &fsname[..fsname.iter().position(|&x| x == 0).unwrap_or(fsname.len())],
    );
    let device =
        String::from_utf16_lossy(&guid[..guid.iter().position(|&x| x == 0).unwrap_or(guid.len())])
            .trim_end_matches('\\')
            .to_owned();
    Ok(VolumeInfo {
        root: root_path,
        device,
        filesystem,
        serial,
        total_bytes: total,
        free_bytes: free,
        cluster_bytes: sectors.saturating_mul(sector_bytes),
    })
}
#[cfg(not(windows))]
pub fn volume_info(path: &Path) -> Result<VolumeInfo> {
    Ok(VolumeInfo {
        root: canonical(path)?,
        filesystem: "portable".into(),
        cluster_bytes: 4096,
        ..Default::default()
    })
}
#[cfg(windows)]
pub fn volumes() -> Vec<VolumeInfo> {
    let mask = unsafe { GetLogicalDrives() };
    (0..26)
        .filter(|i| mask & (1 << i) != 0)
        .filter_map(|i| volume_info(Path::new(&format!("{}:\\", (b'A' + i) as char))).ok())
        .collect()
}
#[cfg(not(windows))]
pub fn volumes() -> Vec<VolumeInfo> {
    Vec::new()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub volume: u64,
    pub id: [u8; 16],
    pub length: u64,
    pub allocated: u64,
    pub modified: i64,
    pub attributes: u32,
    pub links: u32,
}
impl Identity {
    pub fn same_file(&self, other: &Self) -> bool {
        self.volume == other.volume && self.id == other.id
    }
    pub fn is_dir(&self) -> bool {
        self.attributes & 0x10 != 0
    }
    pub fn is_reparse(&self) -> bool {
        self.attributes & 0x400 != 0
    }
}
#[cfg(windows)]
pub fn metadata_handle(path: &Path, freeze_name: bool, delete_access: bool) -> Result<File> {
    let share =
        FILE_SHARE_READ | FILE_SHARE_WRITE | if freeze_name { 0 } else { FILE_SHARE_DELETE };
    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | if delete_access { DELETE } else { 0 })
        .share_mode(share)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("open metadata handle: {}", path.display()))
}
#[cfg(windows)]
pub fn identity_from_handle(file: &File) -> Result<Identity> {
    unsafe {
        let h = file.as_raw_handle();
        let mut id: FILE_ID_INFO = std::mem::zeroed();
        let mut basic: FILE_BASIC_INFO = std::mem::zeroed();
        let mut standard: FILE_STANDARD_INFO = std::mem::zeroed();
        if GetFileInformationByHandleEx(
            h,
            FileIdInfo,
            (&mut id as *mut FILE_ID_INFO).cast(),
            std::mem::size_of_val(&id) as u32,
        ) == 0
        {
            return Err(std::io::Error::last_os_error()).context("query 128-bit file identity");
        }
        if GetFileInformationByHandleEx(
            h,
            FileBasicInfo,
            (&mut basic as *mut FILE_BASIC_INFO).cast(),
            std::mem::size_of_val(&basic) as u32,
        ) == 0
        {
            return Err(std::io::Error::last_os_error()).context("query file attributes");
        }
        if GetFileInformationByHandleEx(
            h,
            FileStandardInfo,
            (&mut standard as *mut FILE_STANDARD_INFO).cast(),
            std::mem::size_of_val(&standard) as u32,
        ) == 0
        {
            return Err(std::io::Error::last_os_error()).context("query allocation");
        }
        let (logical, allocated) = if basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            (
                standard.EndOfFile.max(0) as u64,
                standard.AllocationSize.max(0) as u64,
            )
        } else {
            stream_sizes(file, basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0)?
        };
        Ok(Identity {
            volume: id.VolumeSerialNumber,
            id: id.FileId.Identifier,
            length: logical,
            allocated,
            modified: basic.LastWriteTime,
            attributes: basic.FileAttributes,
            links: standard.NumberOfLinks,
        })
    }
}
/// Includes alternate DATA streams. The buffer starts small and grows only for files
/// with many streams; this never reads file contents or hydrates cloud placeholders.
#[cfg(windows)]
pub fn stream_sizes(file: &File, is_directory: bool) -> Result<(u64, u64)> {
    let mut bytes = vec![0u8; 1024];
    loop {
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileStreamInfo,
                bytes.as_mut_ptr().cast(),
                bytes.len() as u32,
            )
        };
        if ok != 0 {
            break;
        }
        let code = unsafe { GetLastError() };
        if is_directory && (code == ERROR_HANDLE_EOF || code == ERROR_INVALID_PARAMETER) {
            return Ok((0, 0));
        }
        if (code == ERROR_MORE_DATA || code == ERROR_INSUFFICIENT_BUFFER)
            && bytes.len() < 1024 * 1024
        {
            bytes.resize(bytes.len() * 2, 0);
            continue;
        }
        return Err(std::io::Error::from_raw_os_error(code as i32))
            .context("query all DATA stream sizes");
    }
    let (mut logical, mut allocated, mut at) = (0u64, 0u64, 0usize);
    loop {
        anyhow::ensure!(at + 24 <= bytes.len(), "invalid stream-info entry");
        let next = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        let name_len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        anyhow::ensure!(
            name_len.is_multiple_of(2) && at + 24 + name_len <= bytes.len(),
            "invalid stream-info name"
        );
        let name = String::from_utf16_lossy(
            &bytes[at + 24..at + 24 + name_len]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_le_bytes(*b))
                .collect::<Vec<_>>(),
        );
        if name.ends_with(":$DATA") {
            let size = i64::from_le_bytes(bytes[at + 8..at + 16].try_into().unwrap()).max(0) as u64;
            let alloc =
                i64::from_le_bytes(bytes[at + 16..at + 24].try_into().unwrap()).max(0) as u64;
            logical = logical.checked_add(size).context("stream size overflow")?;
            allocated = allocated
                .checked_add(alloc)
                .context("stream allocation overflow")?;
        }
        if next == 0 {
            break;
        }
        anyhow::ensure!(
            next >= 24 && at + next < bytes.len(),
            "invalid stream-info next offset"
        );
        at += next;
    }
    Ok((logical, allocated))
}
#[cfg(windows)]
pub fn fast_sizes(file: &File, attributes: u32) -> Result<(u64, u64, u32)> {
    let mut standard: FILE_STANDARD_INFO = unsafe { std::mem::zeroed() };
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileStandardInfo,
            (&mut standard as *mut FILE_STANDARD_INFO).cast(),
            std::mem::size_of_val(&standard) as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("query allocation by ID");
    }
    let (logical, allocated) = if attributes & 0x400 != 0 {
        (
            standard.EndOfFile.max(0) as u64,
            standard.AllocationSize.max(0) as u64,
        )
    } else {
        stream_sizes(file, attributes & 0x10 != 0)?
    };
    Ok((logical, allocated, standard.NumberOfLinks))
}
#[cfg(windows)]
pub fn final_path(file: &File) -> Result<PathBuf> {
    let mut buf = vec![0u16; 32768];
    let n = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    anyhow::ensure!(
        n > 0 && (n as usize) < buf.len(),
        "GetFinalPathNameByHandleW failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(PathBuf::from(decode_name(&buf[..n as usize])))
}
#[cfg(windows)]
pub fn hardlink_paths(file: &File, volume_root: &Path) -> Result<Vec<PathBuf>> {
    let path = final_path(file)?;
    let wp = wide(&path);
    let mut buf = vec![0u16; 32768];
    let mut length = buf.len() as u32;
    let h = unsafe { FindFirstFileNameW(wp.as_ptr(), 0, &mut length, buf.as_mut_ptr()) };
    if h == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error()).context("enumerate hardlinks");
    }
    struct Guard(HANDLE);
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe {
                FindClose(self.0);
            }
        }
    }
    let _guard = Guard(h);
    let mut paths = Vec::new();
    loop {
        let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let mut relative = &buf[..n];
        while relative.first() == Some(&92) {
            relative = &relative[1..];
        }
        paths.push(volume_root.join(decode_name(relative)));
        length = buf.len() as u32;
        if unsafe { FindNextFileNameW(h, &mut length, buf.as_mut_ptr()) } == 0 {
            let e = unsafe { GetLastError() };
            if e == ERROR_HANDLE_EOF {
                break;
            }
            return Err(std::io::Error::from_raw_os_error(e as i32))
                .context("enumerate next hardlink");
        }
    }
    Ok(paths)
}

#[cfg(windows)]
pub fn identity(path: &Path) -> Result<Identity> {
    identity_from_handle(&metadata_handle(path, false, false)?)
}
#[cfg(not(windows))]
pub fn identity(path: &Path) -> Result<Identity> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path)?;
    Ok(Identity {
        volume: m.dev(),
        id: (m.ino() as u128).to_le_bytes(),
        length: m.len(),
        allocated: m.blocks() * 512,
        modified: m.mtime(),
        attributes: if m.is_dir() { 0x10 } else { 0 }
            | if m.file_type().is_symlink() { 0x400 } else { 0 },
        links: m.nlink() as u32,
    })
}
#[cfg(windows)]
pub fn open_by_id(volume: &File, id: [u8; 16], extended: bool) -> Result<File> {
    unsafe {
        let mut desc: FILE_ID_DESCRIPTOR = std::mem::zeroed();
        desc.dwSize = std::mem::size_of_val(&desc) as u32;
        if extended {
            desc.Type = ExtendedFileIdType;
            desc.Anonymous.ExtendedFileId.Identifier = id;
        } else {
            desc.Type = FileIdType;
            desc.Anonymous.FileId = i64::from_le_bytes(id[..8].try_into().unwrap());
        }
        let h = OpenFileById(
            volume.as_raw_handle(),
            &desc,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        );
        if h == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error()).context("OpenFileById");
        }
        Ok(File::from_raw_handle(h))
    }
}

/// Raw access is READ ONLY. The backing handle is serialized, avoiding File::try_clone's
/// shared seek cursor (including librefs::FileIo's duplicated-handle seek/read race).
pub struct RawReader {
    file: std::sync::Mutex<File>,
    pub length: u64,
    alignment: u64,
}
impl RawReader {
    pub fn image(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let length = file.metadata()?.len();
        Ok(Self {
            file: std::sync::Mutex::new(file),
            length,
            alignment: 1,
        })
    }
    #[cfg(windows)]
    pub fn volume(info: &VolumeInfo) -> Result<Self> {
        elevation::require_administrator()?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&info.device)
            .with_context(|| {
                format!(
                    "read-only raw volume {} (administrator required)",
                    info.device
                )
            })?;
        let mut length = 0i64;
        let mut returned = 0;
        if unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                IOCTL_DISK_GET_LENGTH_INFO,
                std::ptr::null(),
                0,
                (&mut length as *mut i64).cast(),
                8,
                &mut returned,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error()).context("query raw volume length");
        }
        Ok(Self {
            file: std::sync::Mutex::new(file),
            length: length.max(0) as u64,
            alignment: 512,
        })
    }
    #[cfg(not(windows))]
    pub fn volume(_: &VolumeInfo) -> Result<Self> {
        bail!("raw volumes require Windows")
    }
    pub fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> Result<()> {
        use std::io::{Read, Seek, SeekFrom};
        if dst.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(dst.len() as u64)
            .context("raw read overflow")?;
        if end > self.length {
            bail!("raw read outside volume: offset={offset} len={}", dst.len());
        }
        let start = offset / self.alignment * self.alignment;
        let aligned_end = end.div_ceil(self.alignment) * self.alignment;
        let mut f = self
            .file
            .lock()
            .map_err(|_| anyhow::anyhow!("raw-reader mutex poisoned"))?;
        f.seek(SeekFrom::Start(start))?;
        if start == offset && aligned_end == end {
            f.read_exact(dst)?;
        } else {
            let mut buf = vec![0u8; (aligned_end - start) as usize];
            f.read_exact(&mut buf)?;
            let i = (offset - start) as usize;
            dst.copy_from_slice(&buf[i..i + dst.len()]);
        }
        Ok(())
    }
    #[cfg(windows)]
    pub fn file_record(&self, record: u64, record_size: usize) -> Result<Vec<u8>> {
        let f = self
            .file
            .lock()
            .map_err(|_| anyhow::anyhow!("raw-reader mutex poisoned"))?;
        let mut input = record as i64;
        let mut out = vec![0u8; record_size + 32];
        let mut got = 0;
        if unsafe {
            DeviceIoControl(
                f.as_raw_handle(),
                FSCTL_GET_NTFS_FILE_RECORD,
                (&mut input as *mut i64).cast(),
                8,
                out.as_mut_ptr().cast(),
                out.len() as u32,
                &mut got,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error()).context("FSCTL_GET_NTFS_FILE_RECORD");
        }
        if got < 12
            || (u64::from_le_bytes(out[..8].try_into().unwrap()) & 0x0000ffffffffffff) != record
        {
            bail!("NTFS returned a different record for {record}");
        }
        let len = u32::from_le_bytes(out[8..12].try_into().unwrap()) as usize;
        if len != record_size || len + 12 > got as usize {
            bail!("invalid file-record reply length");
        }
        Ok(out[12..12 + len].to_vec())
    }
}
impl librefs::io::ReadAt for RawReader {
    fn read_into(&self, offset: u64, dst: &mut [u8]) -> librefs::RefsResult<usize> {
        if offset >= self.length {
            return Ok(0);
        }
        let n = dst.len().min((self.length - offset) as usize);
        self.read_exact_at(offset, &mut dst[..n]).map_err(|e| {
            librefs::RefsError::Io("raw read", std::io::Error::other(e.to_string()))
        })?;
        Ok(n)
    }
}
impl librefs::io::DeviceSize for RawReader {
    fn size(&self) -> librefs::RefsResult<u64> {
        Ok(self.length)
    }
}

pub fn peak_working_set() -> u64 {
    #[cfg(windows)]
    unsafe {
        let mut m: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        m.cb = std::mem::size_of_val(&m) as u32;
        if GetProcessMemoryInfo(GetCurrentProcess(), &mut m, m.cb) != 0 {
            return m.PeakWorkingSetSize as u64;
        }
    }
    0
}

/// Same-directory atomic replacement. Never truncate the live plan/cache.
pub fn atomic_replace(temp: &Path, destination: &Path) -> Result<()> {
    #[cfg(windows)]
    unsafe {
        if MoveFileExW(
            wide(temp).as_ptr(),
            wide(destination).as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        ) == 0
        {
            return Err(std::io::Error::last_os_error()).context("atomic replace");
        }
    }
    #[cfg(not(windows))]
    std::fs::rename(temp, destination)?;
    Ok(())
}
