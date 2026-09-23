//! Compact, lossless UTF-16 tree: no per-file full path, no retained raw MFT records.
use crate::platform::{self, VolumeInfo};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    fs::OpenOptions,
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
pub const NONE: u32 = u32::MAX;
pub const DIR: u16 = 1;
pub const REPARSE: u16 = 2;
pub const HARDLINK: u16 = 4;
pub const ESTIMATED: u16 = 8;
pub const INCOMPLETE: u16 = 16;
pub const VIRTUAL: u16 = 32;
pub const MTIME_UNKNOWN: u16 = 64;
pub const UNKNOWN_MTIME: i64 = i64::MIN;
pub fn oldest_known(a: i64, b: i64) -> i64 {
    if a == UNKNOWN_MTIME {
        b
    } else if b == UNKNOWN_MTIME {
        a
    } else {
        a.min(b)
    }
}
pub fn latest_known(a: i64, b: i64) -> i64 {
    if a == UNKNOWN_MTIME {
        b
    } else if b == UNKNOWN_MTIME {
        a
    } else {
        a.max(b)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    pub logical: u64,
    pub allocated: u64,
    /// Files: both values are their last-write UTC Unix milliseconds.
    /// Directories: min/max of descendant FILE last-write times only.
    /// Empty directories have UNKNOWN_MTIME; a directory's own timestamp is never included.
    pub oldest_modified_ms: i64,
    pub latest_modified_ms: i64,
    pub parent: u32,
    pub first_child: u32,
    pub next_sibling: u32,
    pub name_start: u32,
    pub name_len: u16,
    pub flags: u16,
    pub files: u32,
    pub dirs: u32,
}
impl Node {
    pub fn is_dir(&self) -> bool {
        self.flags & DIR != 0
    }
    pub fn is_reparse(&self) -> bool {
        self.flags & REPARSE != 0
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScanStats {
    pub backend: String,
    pub started_unix: u64,
    pub elapsed_ms: u64,
    pub threads: usize,
    pub records_read: u64,
    pub raw_bytes_read: u64,
    pub errors: u64,
    pub complete: bool,
    pub peak_working_set_bytes: u64,
    pub index_bytes: u64,
    pub warnings: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    pub root: PathBuf,
    pub volume: VolumeInfo,
    pub stats: ScanStats,
    pub nodes: Vec<Node>,
    pub names: Vec<u16>,
}
impl Snapshot {
    pub fn new(root: PathBuf, volume: VolumeInfo, backend: &str, threads: usize) -> Self {
        Self {
            version: 3,
            root,
            volume,
            stats: ScanStats {
                backend: backend.into(),
                started_unix: platform::now_unix(),
                threads,
                complete: true,
                ..Default::default()
            },
            nodes: vec![Node {
                logical: 0,
                allocated: 0,
                oldest_modified_ms: UNKNOWN_MTIME,
                latest_modified_ms: UNKNOWN_MTIME,
                parent: NONE,
                first_child: NONE,
                next_sibling: NONE,
                name_start: 0,
                name_len: 0,
                flags: DIR,
                files: 0,
                dirs: 1,
            }],
            names: Vec::new(),
        }
    }
    pub fn push(
        &mut self,
        parent: u32,
        name: &[u16],
        logical: u64,
        allocated: u64,
        flags: u16,
    ) -> Result<u32> {
        ensure!(
            self.nodes.len() < NONE as usize && self.names.len() + name.len() < u32::MAX as usize,
            "scan index exceeds 32-bit compact limits"
        );
        ensure!(name.len() <= u16::MAX as usize, "invalid overlong filename");
        let id = self.nodes.len() as u32;
        let start = self.names.len() as u32;
        self.names.extend_from_slice(name);
        self.nodes.push(Node {
            logical,
            allocated,
            oldest_modified_ms: UNKNOWN_MTIME,
            latest_modified_ms: UNKNOWN_MTIME,
            parent,
            first_child: NONE,
            next_sibling: NONE,
            name_start: start,
            name_len: name.len() as u16,
            flags,
            files: u32::from(flags & DIR == 0),
            dirs: u32::from(flags & DIR != 0),
        });
        Ok(id)
    }
    pub fn set_file_mtime(&mut self, id: u32, mtime_ms: Option<i64>) {
        let n = &mut self.nodes[id as usize];
        if !n.is_dir() {
            n.oldest_modified_ms = mtime_ms.unwrap_or(UNKNOWN_MTIME);
            n.latest_modified_ms = n.oldest_modified_ms;
            if mtime_ms.is_none() {
                n.flags |= MTIME_UNKNOWN;
            } else {
                n.flags &= !MTIME_UNKNOWN;
            }
        }
    }
    pub fn name_units(&self, id: u32) -> &[u16] {
        let n = &self.nodes[id as usize];
        &self.names[n.name_start as usize..n.name_start as usize + n.name_len as usize]
    }
    pub fn name(&self, id: u32) -> String {
        String::from_utf16_lossy(self.name_units(id))
    }
    pub fn path(&self, mut id: u32) -> PathBuf {
        let mut parts = Vec::new();
        for _ in 0..self.nodes.len() {
            if id == 0 || id == NONE {
                break;
            }
            parts.push(id);
            id = self.nodes[id as usize].parent;
        }
        let mut p = self.root.clone();
        for i in parts.into_iter().rev() {
            p.push(platform::decode_name(self.name_units(i)));
        }
        p
    }
    pub fn children(&self, id: u32) -> Children<'_> {
        Children {
            snapshot: self,
            next: self.nodes[id as usize].first_child,
        }
    }
    pub fn index_bytes(&self) -> u64 {
        (self.nodes.capacity() * std::mem::size_of::<Node>() + self.names.capacity() * 2) as u64
    }
    pub fn warn(&mut self, warning: String) {
        self.stats.errors += 1;
        self.stats.complete = false;
        if self.stats.warnings.len() < 24 {
            self.stats.warnings.push(warning);
        }
    }
    /// Build sibling links and propagate totals once, in O(n), irrespective of MFT order.
    pub fn finish(&mut self) -> Result<()> {
        let len = self.nodes.len();
        let mut remaining = vec![0u32; len];
        for i in 1..len {
            let p = self.nodes[i].parent as usize;
            ensure!(
                p < len && p != i && self.nodes[p].is_dir(),
                "invalid/cyclic parent in scan index at {i}"
            );
            self.nodes[i].next_sibling = self.nodes[p].first_child;
            self.nodes[p].first_child = i as u32;
            remaining[p] += 1;
        }
        let mut leaves: VecDeque<usize> = remaining
            .iter()
            .enumerate()
            .filter(|(_, c)| **c == 0)
            .map(|(i, _)| i)
            .collect();
        let mut visited = 0;
        while let Some(i) = leaves.pop_front() {
            visited += 1;
            if i == 0 {
                continue;
            }
            let n = self.nodes[i].clone();
            let p = &mut self.nodes[n.parent as usize];
            p.logical = p
                .logical
                .checked_add(n.logical)
                .context("logical size overflow")?;
            p.allocated = p
                .allocated
                .checked_add(n.allocated)
                .context("allocated size overflow")?;
            p.files = p
                .files
                .checked_add(n.files)
                .context("file count overflow")?;
            p.dirs = p
                .dirs
                .checked_add(n.dirs)
                .context("directory count overflow")?;
            p.oldest_modified_ms = oldest_known(p.oldest_modified_ms, n.oldest_modified_ms);
            p.latest_modified_ms = latest_known(p.latest_modified_ms, n.latest_modified_ms);
            p.flags |= n.flags & (ESTIMATED | INCOMPLETE | MTIME_UNKNOWN);
            let j = n.parent as usize;
            remaining[j] -= 1;
            if remaining[j] == 0 {
                leaves.push_back(j);
            }
        }
        ensure!(
            visited == len,
            "cycle in filesystem parent graph; refusing a misleading snapshot"
        );
        self.stats.index_bytes = self.index_bytes();
        Ok(())
    }
    pub fn find(&self, path: &Path) -> Result<u32> {
        let abs = platform::absolute(path)?;
        let rk = platform::path_key(&self.root);
        let pk = platform::path_key(&abs);
        ensure!(
            platform::within(&abs, &self.root),
            "{} is outside snapshot root {}",
            abs.display(),
            self.root.display()
        );
        if pk == rk {
            return Ok(0);
        }
        // Strip by path components rather than byte length (Unicode case folding may change length).
        let root_components = self.root.components().count();
        let display = PathBuf::from(platform::display_path(&abs));
        let display_root = PathBuf::from(platform::display_path(&self.root));
        let skip = if display_root.components().count() != root_components {
            display_root.components().count()
        } else {
            root_components
        };
        let mut id = 0;
        for component in display.components().skip(skip) {
            let name = component.as_os_str();
            let wanted = platform::encode_name(name);
            let matches: Vec<_> = self
                .children(id)
                .filter(|&c| self.name_units(c) == wanted)
                .collect();
            id = if matches.len() == 1 {
                matches[0]
            } else {
                let folded = name.to_string_lossy().to_lowercase();
                let m: Vec<_> = self
                    .children(id)
                    .filter(|&c| self.name(c).to_lowercase() == folded)
                    .collect();
                ensure!(
                    m.len() == 1,
                    "path not found or ambiguous in snapshot: {} (scan may be stale)",
                    path.display()
                );
                m[0]
            };
        }
        Ok(id)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 3 && !self.nodes.is_empty(),
            "unsupported/empty scan cache"
        );
        for (i, n) in self.nodes.iter().enumerate() {
            ensure!(
                (n.oldest_modified_ms == UNKNOWN_MTIME) == (n.latest_modified_ms == UNKNOWN_MTIME)
                    && n.oldest_modified_ms <= n.latest_modified_ms,
                "invalid modification range at {i}"
            );
            ensure!(
                n.is_dir() || n.oldest_modified_ms == n.latest_modified_ms,
                "file has inconsistent last-write times"
            );
            ensure!(
                (n.name_start as usize)
                    .checked_add(n.name_len as usize)
                    .is_some_and(|end| end <= self.names.len()),
                "invalid name range at {i}"
            );
            for p in [n.parent, n.first_child, n.next_sibling] {
                ensure!(
                    p == NONE || (p as usize) < self.nodes.len(),
                    "invalid node index at {i}"
                );
            }
        }
        // Verify all nodes are reachable exactly once, including sibling-chain cycle checks.
        let mut seen = vec![false; self.nodes.len()];
        let mut pending = vec![0u32];
        while let Some(i) = pending.pop() {
            ensure!(!seen[i as usize], "cycle/duplicate link in scan cache");
            seen[i as usize] = true;
            let mut c = self.nodes[i as usize].first_child;
            let mut count = 0;
            while c != NONE {
                count += 1;
                ensure!(
                    count <= self.nodes.len() && self.nodes[c as usize].parent == i,
                    "corrupt scan child chain"
                );
                pending.push(c);
                c = self.nodes[c as usize].next_sibling;
            }
        }
        ensure!(seen.iter().all(|x| *x), "unreachable nodes in scan cache");
        Ok(())
    }
    pub fn save(&self, destination: &Path) -> Result<()> {
        let destination = platform::absolute(destination)?;
        if destination.exists() {
            let mut f = std::fs::File::open(&destination)?;
            let mut magic = [0; 8];
            f.read_exact(&mut magic)?;
            ensure!(
                &magic == b"DCSCAN01" || &magic == b"DCSCAN02" || &magic == b"DCSCAN03",
                "refusing to overwrite a non-snapshot file"
            );
        }
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temp = destination.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let mut f = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&temp)?;
        f.write_all(b"DCSCAN03")?;
        f.write_all(&[0; 32])?;
        {
            let mut w = BufWriter::with_capacity(1024 * 1024, &mut f);
            bincode::serialize_into(&mut w, self)?;
            w.flush()?;
        }
        f.seek(SeekFrom::Start(40))?;
        let mut hash = blake3::Hasher::new();
        let mut buf = vec![0; 1024 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hash.update(&buf[..n]);
        }
        f.seek(SeekFrom::Start(8))?;
        f.write_all(hash.finalize().as_bytes())?;
        f.sync_all()?;
        drop(f);
        platform::atomic_replace(&temp, &destination)
    }
    pub fn load(path: &Path) -> Result<Self> {
        use bincode::Options;
        let mut f = std::fs::File::open(path)?;
        let len = f.metadata()?.len();
        ensure!(
            (40..=8 * 1024 * 1024 * 1024).contains(&len),
            "invalid snapshot length"
        );
        let mut header = [0; 40];
        f.read_exact(&mut header)?;
        ensure!(
            &header[..8] != b"DCSCAN01",
            "snapshot v1 has no modification timestamps; run scan again to create v3"
        );
        ensure!(
            &header[..8] == b"DCSCAN02" || &header[..8] == b"DCSCAN03",
            "not a supported disk-cleaner snapshot"
        );
        let mut hash = blake3::Hasher::new();
        let mut buf = vec![0; 1024 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hash.update(&buf[..n]);
        }
        ensure!(
            hash.finalize().as_bytes() == &header[8..40],
            "snapshot checksum mismatch"
        );
        f.seek(SeekFrom::Start(40))?;
        let options = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(len - 40);
        let s: Self = if &header[..8] == b"DCSCAN02" {
            let old: LegacySnapshotV2 = options.deserialize_from(BufReader::new(f))?;
            old.upgrade()?
        } else {
            options.deserialize_from(BufReader::new(f))?
        };
        s.validate()?;
        Ok(s)
    }
}

// v2 already contains each file's exact mtime. Derive max from those file values,
// rather than inventing it from a directory's old min or forcing a rescan.
#[derive(Serialize, Deserialize)]
struct LegacyNodeV2 {
    logical: u64,
    allocated: u64,
    oldest_modified_ms: i64,
    parent: u32,
    first_child: u32,
    next_sibling: u32,
    name_start: u32,
    name_len: u16,
    flags: u16,
    files: u32,
    dirs: u32,
}
#[derive(Serialize, Deserialize)]
struct LegacySnapshotV2 {
    version: u32,
    root: PathBuf,
    volume: VolumeInfo,
    stats: ScanStats,
    nodes: Vec<LegacyNodeV2>,
    names: Vec<u16>,
}
impl LegacySnapshotV2 {
    fn upgrade(self) -> Result<Snapshot> {
        ensure!(self.version == 2, "invalid v2 snapshot schema");
        let mut s = Snapshot {
            version: 3,
            root: self.root,
            volume: self.volume,
            stats: self.stats,
            names: self.names,
            nodes: self
                .nodes
                .into_iter()
                .map(|n| Node {
                    logical: n.logical,
                    allocated: n.allocated,
                    oldest_modified_ms: n.oldest_modified_ms,
                    latest_modified_ms: n.oldest_modified_ms,
                    parent: n.parent,
                    first_child: n.first_child,
                    next_sibling: n.next_sibling,
                    name_start: n.name_start,
                    name_len: n.name_len,
                    flags: n.flags,
                    files: n.files,
                    dirs: n.dirs,
                })
                .collect(),
        };
        s.validate()?;
        let mut order = Vec::with_capacity(s.nodes.len());
        let mut pending = vec![0];
        while let Some(id) = pending.pop() {
            order.push(id);
            pending.extend(s.children(id));
        }
        for n in &mut s.nodes {
            if n.is_dir() {
                n.oldest_modified_ms = UNKNOWN_MTIME;
                n.latest_modified_ms = UNKNOWN_MTIME;
            }
        }
        for &id in order.iter().rev() {
            if id == 0 {
                continue;
            }
            let n = s.nodes[id as usize].clone();
            let parent = &mut s.nodes[n.parent as usize];
            parent.oldest_modified_ms =
                oldest_known(parent.oldest_modified_ms, n.oldest_modified_ms);
            parent.latest_modified_ms =
                latest_known(parent.latest_modified_ms, n.latest_modified_ms);
        }
        s.stats.index_bytes = s.index_bytes();
        Ok(s)
    }
}

pub struct Children<'a> {
    snapshot: &'a Snapshot,
    next: u32,
}
impl Iterator for Children<'_> {
    type Item = u32;
    fn next(&mut self) -> Option<u32> {
        if self.next == NONE {
            return None;
        }
        let i = self.next;
        self.next = self.snapshot.nodes[i as usize].next_sibling;
        Some(i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tree() -> Snapshot {
        let mut s = Snapshot::new(PathBuf::from(r"C:\test"), VolumeInfo::default(), "test", 2);
        let a = s.push(0, &[65], 0, 0, DIR).unwrap();
        s.push(a, &[98], 10, 4096, 0).unwrap();
        s.push(0, &[99], 20, 8192, 0).unwrap();
        s.finish().unwrap();
        s
    }
    #[test]
    fn exact_rollup() {
        let s = tree();
        assert_eq!(s.nodes[0].logical, 30);
        assert_eq!(s.nodes[0].allocated, 12288);
        assert_eq!(s.nodes[0].files, 2);
        assert_eq!(s.nodes[0].dirs, 2);
        s.validate().unwrap();
    }
    #[test]
    fn min_max_file_timestamps_ignore_directory_and_order() {
        let mut s = Snapshot::new(PathBuf::from(r"C:\test"), VolumeInfo::default(), "test", 1);
        let dir = s.push(0, &[97], 0, 0, DIR).unwrap();
        let empty = s.push(dir, &[101], 0, 0, DIR).unwrap();
        let newer = s.push(dir, &[98], 1, 1, 0).unwrap();
        let older = s.push(dir, &[99], 1, 1, 0).unwrap();
        s.set_file_mtime(dir, Some(1));
        s.set_file_mtime(newer, Some(20000));
        s.set_file_mtime(older, Some(10000));
        s.finish().unwrap();
        assert_eq!(s.nodes[empty as usize].oldest_modified_ms, UNKNOWN_MTIME);
        assert_eq!(s.nodes[empty as usize].latest_modified_ms, UNKNOWN_MTIME);
        assert_eq!(s.nodes[dir as usize].oldest_modified_ms, 10000);
        assert_eq!(s.nodes[0].oldest_modified_ms, 10000);
        assert_eq!(s.nodes[dir as usize].latest_modified_ms, 20000);
        assert_eq!(s.nodes[0].latest_modified_ms, 20000);
        assert_eq!(
            s.nodes[older as usize].oldest_modified_ms,
            s.nodes[older as usize].latest_modified_ms
        );
    }
    #[test]
    fn compact_nodes() {
        assert!(std::mem::size_of::<Node>() <= 64);
    }
    #[test]
    fn roundtrip_and_corruption() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("scan.dcscan");
        tree().save(&p).unwrap();
        assert_eq!(Snapshot::load(&p).unwrap().nodes[0].logical, 30);
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"bad").unwrap();
        assert!(Snapshot::load(&p).is_err());
    }
    #[test]
    fn rejects_cycles() {
        let mut s = tree();
        s.nodes[1].next_sibling = 1;
        assert!(s.validate().is_err());
    }
    #[test]
    fn component_boundary() {
        assert!(!platform::within(
            Path::new(r"C:\foobar"),
            Path::new(r"C:\foo")
        ));
    }

    #[test]
    fn v2_cache_migration_derives_max_from_files() {
        let mut s = tree();
        s.set_file_mtime(2, Some(100));
        s.set_file_mtime(3, Some(900));
        let old = LegacySnapshotV2 {
            version: 2,
            root: s.root.clone(),
            volume: s.volume.clone(),
            stats: s.stats.clone(),
            names: s.names.clone(),
            nodes: s
                .nodes
                .iter()
                .map(|n| LegacyNodeV2 {
                    logical: n.logical,
                    allocated: n.allocated,
                    oldest_modified_ms: n.oldest_modified_ms,
                    parent: n.parent,
                    first_child: n.first_child,
                    next_sibling: n.next_sibling,
                    name_start: n.name_start,
                    name_len: n.name_len,
                    flags: n.flags,
                    files: n.files,
                    dirs: n.dirs,
                })
                .collect(),
        };
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("legacy.dcscan");
        let data = bincode::serialize(&old).unwrap();
        let mut bytes = b"DCSCAN02".to_vec();
        bytes.extend_from_slice(blake3::hash(&data).as_bytes());
        bytes.extend(data);
        std::fs::write(&path, bytes).unwrap();
        let loaded = Snapshot::load(&path).unwrap();
        assert_eq!(loaded.nodes[0].logical, 30);
        assert_eq!(loaded.nodes[0].oldest_modified_ms, 100);
        assert_eq!(loaded.nodes[0].latest_modified_ms, 900);
        assert_eq!(loaded.version, 3);
    }
    #[test]
    fn unknown_time_is_not_an_epoch_or_extreme_value() {
        assert_eq!(latest_known(UNKNOWN_MTIME, 10), 10);
        assert_eq!(oldest_known(10, UNKNOWN_MTIME), 10);
        assert_eq!(latest_known(UNKNOWN_MTIME, UNKNOWN_MTIME), UNKNOWN_MTIME);
    }
}
