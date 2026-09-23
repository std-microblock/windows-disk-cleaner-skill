//! Bounded parallel filesystem enumeration; never follows any reparse point.
use crate::{
    model::{DIR, ESTIMATED, HARDLINK, INCOMPLETE, REPARSE, Snapshot},
    platform::{self, Identity, VolumeInfo},
};
use anyhow::{Context, Result, bail};
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex, mpsc},
    time::{Duration, Instant, UNIX_EPOCH},
};
struct Job {
    path: PathBuf,
    parent: u32,
}
struct Queue {
    jobs: VecDeque<Job>,
    closed: bool,
}
struct Entry {
    name: Vec<u16>,
    identity: Identity,
}
enum Message {
    Batch(u32, PathBuf, Vec<Entry>),
    Error(String),
    Done,
}

/// Exact per-file sizes: one metadata handle per entry. Used by scan reports.
pub fn scan(
    root: &Path,
    volume: VolumeInfo,
    threads: usize,
    memory_limit: u64,
) -> Result<Snapshot> {
    walk(root, volume, threads, memory_limit, false, None)
}
/// Cheap review walk for a marked subtree: directory-listing metadata only, no
/// per-file handle, allocation rounded up to the cluster size and flagged as
/// estimated. Deletion re-verifies every reviewed object on its own handle.
pub fn scan_light(
    root: &Path,
    volume: VolumeInfo,
    threads: usize,
    memory_limit: u64,
    progress: Option<&dyn Fn(u64)>,
) -> Result<Snapshot> {
    walk(root, volume, threads, memory_limit, true, progress)
}
fn walk(
    root: &Path,
    volume: VolumeInfo,
    threads: usize,
    memory_limit: u64,
    light: bool,
    progress: Option<&dyn Fn(u64)>,
) -> Result<Snapshot> {
    let mut snapshot = Snapshot::new(
        root.to_path_buf(),
        volume.clone(),
        if light { "fs-light" } else { "fs-enumerate" },
        threads,
    );
    let root_meta = platform::identity(root)?;
    snapshot.nodes[0].logical = root_meta.length;
    snapshot.nodes[0].allocated = root_meta.allocated;
    if !root_meta.is_dir() || root_meta.is_reparse() {
        snapshot.nodes[0].flags = if root_meta.is_dir() { DIR } else { 0 }
            | if root_meta.is_reparse() { REPARSE } else { 0 };
        snapshot.nodes[0].logical = root_meta.length;
        snapshot.nodes[0].allocated = root_meta.allocated;
        snapshot.nodes[0].files = u32::from(!root_meta.is_dir());
        snapshot.nodes[0].dirs = u32::from(root_meta.is_dir());
        snapshot.set_file_mtime(0, platform::modified_unix_ms(root_meta.modified));
        return Ok(snapshot);
    }
    if root_meta.is_reparse() {
        bail!(
            "filesystem scan root is a reparse point; scan its explicitly resolved target instead"
        );
    }
    let cluster_bytes = volume.cluster_bytes;
    let shared = Arc::new((
        Mutex::new(Queue {
            jobs: VecDeque::from([Job {
                path: root.to_path_buf(),
                parent: 0,
            }]),
            closed: false,
        }),
        Condvar::new(),
    ));
    let (tx, rx) = mpsc::sync_channel::<Message>(threads * 2);
    let mut hardlinks = ahash::AHashSet::new();
    let result = std::thread::scope(|scope| -> Result<()> {
        for _ in 0..threads {
            let tx = tx.clone();
            let shared = shared.clone();
            scope.spawn(move || {
                loop {
                    let job = {
                        let (lock, cv) = &*shared;
                        let mut q = lock.lock().unwrap();
                        while q.jobs.is_empty() && !q.closed {
                            q = cv.wait(q).unwrap();
                        }
                        if q.closed {
                            return;
                        }
                        q.jobs.pop_front().unwrap()
                    };
                    let mut batch = Vec::with_capacity(256);
                    match std::fs::read_dir(&job.path) {
                        Ok(iter) => {
                            for item in iter {
                                let result = item.map_err(anyhow::Error::from).and_then(|e| {
                                    let identity = if light {
                                        light_identity(&e, cluster_bytes)?
                                    } else {
                                        platform::identity(&e.path())?
                                    };
                                    Ok(Entry {
                                        name: platform::encode_name(&e.file_name()),
                                        identity,
                                    })
                                });
                                match result {
                                    Ok(entry) => batch.push(entry),
                                    Err(e) => {
                                        if tx
                                            .send(Message::Error(format!(
                                                "{}: {e:#}",
                                                job.path.display()
                                            )))
                                            .is_err()
                                        {
                                            return;
                                        }
                                    }
                                }
                                if batch.len() == 256
                                    && tx
                                        .send(Message::Batch(
                                            job.parent,
                                            job.path.clone(),
                                            std::mem::replace(&mut batch, Vec::with_capacity(256)),
                                        ))
                                        .is_err()
                                {
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            if tx
                                .send(Message::Error(format!("{}: {e}", job.path.display())))
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                    if !batch.is_empty()
                        && tx
                            .send(Message::Batch(job.parent, job.path, batch))
                            .is_err()
                    {
                        return;
                    }
                    if tx.send(Message::Done).is_err() {
                        return;
                    }
                }
            });
        }
        drop(tx);
        let consume = (|| -> Result<()> {
            let mut pending = 1u64;
            let mut reported = Instant::now();
            while pending > 0 {
                match rx
                    .recv()
                    .context("filesystem workers stopped unexpectedly")?
                {
                    Message::Batch(parent, dir, entries) => {
                        let mut jobs = Vec::new();
                        for entry in entries {
                            let meta = entry.identity;
                            let mut flags = if meta.is_dir() { DIR } else { 0 }
                                | if meta.is_reparse() { REPARSE } else { 0 };
                            let mut allocated = meta.allocated;
                            if !meta.is_dir() && meta.links > 1 {
                                flags |= HARDLINK;
                                // Light walks have no file id, so only exact walks de-duplicate.
                                if !light && !hardlinks.insert((meta.volume, meta.id)) {
                                    allocated = 0;
                                }
                            }
                            if light && !meta.is_dir() {
                                flags |= ESTIMATED;
                            }
                            let id = snapshot.push(
                                parent,
                                &entry.name,
                                meta.length,
                                allocated,
                                flags,
                            )?;
                            snapshot.set_file_mtime(id, platform::modified_unix_ms(meta.modified));
                            if meta.is_dir() && !meta.is_reparse() {
                                jobs.push(Job {
                                    path: dir.join(platform::decode_name(&entry.name)),
                                    parent: id,
                                });
                                pending += 1;
                            }
                            snapshot.stats.records_read += 1;
                        }
                        if snapshot.index_bytes() + hardlinks.capacity() as u64 * 48 > memory_limit
                        {
                            bail!(
                                "index memory budget exceeded; increase --max-memory-mib or scan a smaller subtree"
                            );
                        }
                        if !jobs.is_empty() {
                            let (lock, cv) = &*shared;
                            lock.lock().unwrap().jobs.extend(jobs);
                            cv.notify_all();
                        }
                        if let Some(progress) = progress
                            && reported.elapsed() >= Duration::from_millis(250)
                        {
                            reported = Instant::now();
                            progress(snapshot.stats.records_read);
                        }
                    }
                    Message::Error(e) => snapshot.warn(e),
                    Message::Done => pending -= 1,
                }
            }
            Ok(())
        })();
        {
            let (lock, cv) = &*shared;
            lock.lock().unwrap().closed = true;
            cv.notify_all();
        }
        drop(rx);
        consume
    });
    result?;
    if !snapshot.stats.complete {
        snapshot.nodes[0].flags |= INCOMPLETE;
    }
    snapshot.finish()?;
    Ok(snapshot)
}

/// Directory-listing metadata only: no per-file handle and no file id, so the
/// allocation is rounded up to the cluster size and must stay marked estimated.
fn light_identity(entry: &std::fs::DirEntry, cluster_bytes: u32) -> Result<Identity> {
    let metadata = entry.metadata()?;
    #[cfg(windows)]
    let (attributes, links) = {
        use std::os::windows::fs::MetadataExt;
        // Link counts need an unstable API; light walks never de-duplicate anyway.
        (metadata.file_attributes(), 1)
    };
    #[cfg(not(windows))]
    let (attributes, links) = {
        use std::os::unix::fs::MetadataExt;
        (
            if metadata.is_dir() { 0x10 } else { 0 }
                | if metadata.file_type().is_symlink() {
                    0x400
                } else {
                    0
                },
            metadata.nlink() as u32,
        )
    };
    let is_dir = metadata.is_dir();
    let length = if is_dir { 0 } else { metadata.len() };
    let allocated = if is_dir || attributes & 0x400 != 0 || cluster_bytes == 0 {
        length
    } else {
        length.div_ceil(cluster_bytes as u64) * cluster_bytes as u64
    };
    Ok(Identity {
        volume: 0,
        id: [0; 16],
        length,
        allocated,
        modified: filetime(metadata.modified().ok()),
        attributes,
        links: links.max(1),
    })
}
/// Windows FILETIME scale, so both walks feed the same time conversion.
fn filetime(modified: Option<std::time::SystemTime>) -> i64 {
    modified
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| (d.as_millis() as i64 + 11_644_473_600_000) * 10_000)
        .unwrap_or(0)
}
