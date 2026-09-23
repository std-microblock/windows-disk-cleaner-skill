use crate::{model::Snapshot, platform};
use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use std::{path::Path, time::Instant};
pub mod fs;
pub mod ntfs;
pub mod refs;
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Backend {
    Auto,
    Ntfs,
    Refs,
    Fs,
}
#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub backend: Backend,
    pub threads: usize,
    pub buffer_mib: usize,
    pub max_memory_mib: usize,
}
impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            backend: Backend::Auto,
            threads: std::thread::available_parallelism()
                .map(|n| n.get().min(8))
                .unwrap_or(4),
            buffer_mib: 8,
            max_memory_mib: 1024,
        }
    }
}
/// Raw volume index for the review window. Needs administrator rights; callers
/// fall back to a directory walk when this fails or the index is incomplete.
pub fn volume_snapshot(
    volume: &platform::VolumeInfo,
    threads: usize,
    buffer_mib: usize,
    memory_limit: u64,
) -> Result<Snapshot> {
    if volume.filesystem.eq_ignore_ascii_case("NTFS") {
        ntfs::scan(volume, threads, buffer_mib, memory_limit)
    } else if volume.filesystem.eq_ignore_ascii_case("REFS") {
        refs::scan(volume, threads, memory_limit)
    } else {
        bail!("no raw backend for {}", volume.filesystem)
    }
}
pub fn scan(path: &Path, options: &ScanOptions) -> Result<Snapshot> {
    let start = Instant::now();
    let root = platform::canonical(path)?;
    let volume = platform::volume_info(&root)?;
    if !matches!(options.backend, Backend::Fs)
        && (matches!(options.backend, Backend::Ntfs | Backend::Refs)
            || volume.filesystem.eq_ignore_ascii_case("NTFS")
            || volume.filesystem.eq_ignore_ascii_case("ReFS"))
    {
        platform::elevation::require_administrator()?;
    }
    let threads = options.threads.clamp(1, 64);
    let limit = options.max_memory_mib as u64 * 1024 * 1024;
    let fast = |b: Backend| -> Result<Snapshot> {
        match b {
            Backend::Ntfs => {
                if !volume.filesystem.eq_ignore_ascii_case("NTFS") {
                    bail!(
                        "--backend ntfs requires NTFS; detected {}",
                        volume.filesystem
                    );
                }
                ntfs::scan(&volume, threads, options.buffer_mib, limit)
            }
            Backend::Refs => {
                if !volume.filesystem.eq_ignore_ascii_case("ReFS") {
                    bail!(
                        "--backend refs requires ReFS; detected {}",
                        volume.filesystem
                    );
                }
                refs::scan(&volume, threads, limit)
            }
            _ => fs::scan(&root, volume.clone(), threads, limit),
        }
    };
    let mut s = match options.backend {
        Backend::Auto => {
            let backend = match volume.filesystem.to_ascii_uppercase().as_str() {
                "NTFS" => Backend::Ntfs,
                "REFS" => Backend::Refs,
                _ => Backend::Fs,
            };
            match fast(backend) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "Fast scan failed ({e:#}); explicitly reporting filesystem-enumeration fallback."
                    );
                    let mut s = fs::scan(&root, volume.clone(), threads, limit)?;
                    s.stats
                        .warnings
                        .push(format!("FAST BACKEND FAILED; fs fallback: {e:#}"));
                    s
                }
            }
        }
        b => fast(b).with_context(|| format!("strict {b:?} backend failed; no silent fallback"))?,
    };
    s.stats.elapsed_ms = start.elapsed().as_millis() as u64;
    s.stats.peak_working_set_bytes = platform::peak_working_set();
    s.stats.index_bytes = s.index_bytes();
    Ok(s)
}
