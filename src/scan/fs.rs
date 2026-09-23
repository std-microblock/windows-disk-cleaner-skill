//! Bounded parallel filesystem enumeration; never follows any reparse point.
use crate::{
    model::{DIR, HARDLINK, INCOMPLETE, REPARSE, Snapshot},
    platform::{self, Identity, VolumeInfo},
};
use anyhow::{Context, Result, bail};
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex, mpsc},
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

pub fn scan(
    root: &Path,
    volume: VolumeInfo,
    threads: usize,
    memory_limit: u64,
) -> Result<Snapshot> {
    Ok(capture(root, volume, threads, memory_limit, false)?.0)
}
pub fn capture(
    root: &Path,
    volume: VolumeInfo,
    threads: usize,
    memory_limit: u64,
    retain_identities: bool,
) -> Result<(Snapshot, Vec<Identity>)> {
    let mut snapshot = Snapshot::new(root.to_path_buf(), volume, "fs-enumerate", threads);
    let root_meta = platform::identity(root)?;
    snapshot.nodes[0].logical = root_meta.length;
    snapshot.nodes[0].allocated = root_meta.allocated;
    let mut identities = if retain_identities {
        vec![root_meta]
    } else {
        Vec::new()
    };
    if !root_meta.is_dir() || root_meta.is_reparse() {
        snapshot.nodes[0].flags = if root_meta.is_dir() { DIR } else { 0 }
            | if root_meta.is_reparse() { REPARSE } else { 0 };
        snapshot.nodes[0].logical = root_meta.length;
        snapshot.nodes[0].allocated = root_meta.allocated;
        snapshot.nodes[0].files = u32::from(!root_meta.is_dir());
        snapshot.nodes[0].dirs = u32::from(root_meta.is_dir());
        snapshot.set_file_mtime(0, platform::modified_unix_ms(root_meta.modified));
        return Ok((snapshot, identities));
    }
    if root_meta.is_reparse() {
        bail!(
            "filesystem scan root is a reparse point; scan its explicitly resolved target instead"
        );
    }
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
                                    let id = platform::identity(&e.path())?;
                                    Ok(Entry {
                                        name: platform::encode_name(&e.file_name()),
                                        identity: id,
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
                                if !hardlinks.insert((meta.volume, meta.id)) {
                                    allocated = 0;
                                }
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
                            if retain_identities {
                                identities.push(meta);
                            }
                            snapshot.stats.records_read += 1;
                        }
                        if snapshot.index_bytes()
                            + identities.capacity() as u64 * std::mem::size_of::<Identity>() as u64
                            + hardlinks.capacity() as u64 * 48
                            > memory_limit
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
    Ok((snapshot, identities))
}
