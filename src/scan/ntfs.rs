//! Streaming NTFS MFT scanner, derived from the technique in Kudaes/MFTool
//! (Apache-2.0, commit 4441426e8c91a7acfe517ee42eb8130ad4a80cfc).
//! Rewritten here: bounds-checked parsing, bounded batches, Rayon, full FRNs,
//! attribute-list extensions and hardlinks; no encrypted/full-MFT/content cache.
use crate::{
    model::{DIR, ESTIMATED, HARDLINK, INCOMPLETE, REPARSE, Snapshot, UNKNOWN_MTIME, VIRTUAL},
    platform::{RawReader, VolumeInfo},
};
use ahash::{AHashMap, AHashSet};
use anyhow::{Context, Result, bail, ensure};
use rayon::prelude::*;
const MASK: u64 = 0x0000ffffffffffff;
fn u16at(b: &[u8], o: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(o..o + 2).context("truncated u16")?.try_into()?,
    ))
}
fn u32at(b: &[u8], o: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(o..o + 4).context("truncated u32")?.try_into()?,
    ))
}
fn u64at(b: &[u8], o: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(o..o + 8).context("truncated u64")?.try_into()?,
    ))
}
#[derive(Debug, Clone)]
struct Geometry {
    sector: usize,
    cluster: u64,
    record: usize,
    mft_offset: u64,
}
impl Geometry {
    fn parse(boot: &[u8]) -> Result<Self> {
        ensure!(
            boot.len() >= 512 && &boot[3..11] == b"NTFS    ",
            "NTFS boot signature missing"
        );
        let sector = u16at(boot, 11)? as usize;
        let spc = boot[13] as u64;
        ensure!(
            sector.is_power_of_two() && (512..=4096).contains(&sector) && spc.is_power_of_two(),
            "invalid NTFS geometry"
        );
        let cluster = (sector as u64)
            .checked_mul(spc)
            .context("cluster overflow")?;
        let c = boot[64] as i8;
        let record = if c < 0 {
            1usize
                .checked_shl(-(c as i32) as u32)
                .context("record shift overflow")?
        } else {
            (cluster as usize)
                .checked_mul(c as usize)
                .context("record overflow")?
        };
        ensure!(
            (512..=65536).contains(&record) && record % sector == 0,
            "invalid MFT record size {record}"
        );
        Ok(Self {
            sector,
            cluster,
            record,
            mft_offset: u64at(boot, 48)?
                .checked_mul(cluster)
                .context("MFT offset overflow")?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Run {
    vcn: u64,
    clusters: u64,
    lcn: Option<u64>,
}
fn runs(attr: &[u8]) -> Result<Vec<Run>> {
    ensure!(
        attr.len() >= 64 && attr[8] == 1,
        "invalid nonresident attribute"
    );
    let mut pos = u16at(attr, 32)? as usize;
    ensure!((64..attr.len()).contains(&pos), "invalid data-run offset");
    let mut vcn = u64at(attr, 16)?;
    let last = u64at(attr, 24)?;
    let mut lcn = 0i64;
    let mut out = Vec::new();
    loop {
        let h = *attr.get(pos).context("unterminated data runs")?;
        pos += 1;
        if h == 0 {
            break;
        }
        let n = (h & 15) as usize;
        let m = (h >> 4) as usize;
        ensure!((1..=8).contains(&n) && m <= 8, "invalid data-run widths");
        ensure!(pos + n + m <= attr.len(), "truncated data run");
        let mut len = [0; 8];
        len[..n].copy_from_slice(&attr[pos..pos + n]);
        pos += n;
        let clusters = u64::from_le_bytes(len);
        ensure!(clusters > 0, "zero-length data run");
        let physical = if m == 0 {
            None
        } else {
            let mut delta = if attr[pos + m - 1] & 128 != 0 {
                [255; 8]
            } else {
                [0; 8]
            };
            delta[..m].copy_from_slice(&attr[pos..pos + m]);
            pos += m;
            lcn = lcn
                .checked_add(i64::from_le_bytes(delta))
                .context("LCN delta overflow")?;
            ensure!(lcn >= 0, "negative physical LCN");
            Some(lcn as u64)
        };
        let next = vcn.checked_add(clusters).context("VCN overflow")?;
        ensure!(
            next <= last.checked_add(1).context("last VCN overflow")?,
            "run exceeds attribute VCN range"
        );
        out.push(Run {
            vcn,
            clusters,
            lcn: physical,
        });
        vcn = next;
    }
    ensure!(
        vcn == last + 1 || out.is_empty() && last == 0,
        "incomplete data runs"
    );
    Ok(out)
}
fn fixup(record: &mut [u8], sector: usize) -> Result<()> {
    ensure!(
        record.len() >= 48 && &record[..4] == b"FILE",
        "invalid FILE record signature"
    );
    let offset = u16at(record, 4)? as usize;
    let count = u16at(record, 6)? as usize;
    ensure!(
        count == record.len() / sector + 1 && offset >= 8 && offset + count * 2 <= record.len(),
        "invalid update sequence array"
    );
    let seq = [record[offset], record[offset + 1]];
    for i in 1..count {
        let tail = i * sector - 2;
        ensure!(
            record[tail..tail + 2] == seq,
            "torn/live-changing MFT record (USA mismatch)"
        );
        let repl = [record[offset + i * 2], record[offset + i * 2 + 1]];
        record[tail..tail + 2].copy_from_slice(&repl);
    }
    Ok(())
}
fn attributes(record: &[u8]) -> Result<Vec<&[u8]>> {
    let used = u32at(record, 24)? as usize;
    ensure!(
        used <= record.len() && used >= 48,
        "invalid record used length"
    );
    let mut p = u16at(record, 20)? as usize;
    ensure!(p >= 42 && p < used, "invalid first attribute offset");
    let mut result = Vec::new();
    while p + 4 <= used {
        if u32at(record, p)? == 0xffffffff {
            return Ok(result);
        }
        let len = u32at(record, p + 4)? as usize;
        ensure!(
            len >= 24 && len.is_multiple_of(8) && p + len <= used,
            "invalid attribute length"
        );
        result.push(&record[p..p + len]);
        p += len;
    }
    bail!("missing attribute terminator")
}
fn resident(attr: &[u8]) -> Result<&[u8]> {
    ensure!(attr.len() >= 24 && attr[8] == 0, "not a resident attribute");
    let start = u16at(attr, 20)? as usize;
    let len = u32at(attr, 16)? as usize;
    ensure!(start >= 24, "invalid resident offset");
    attr.get(start..start.checked_add(len).context("resident overflow")?)
        .context("truncated resident value")
}
fn read_stream(
    raw: &RawReader,
    extents: &[Run],
    cluster: u64,
    mut offset: u64,
    mut dst: &mut [u8],
) -> Result<()> {
    while !dst.is_empty() {
        let vcn = offset / cluster;
        let run = extents
            .iter()
            .find(|r| r.vcn <= vcn && vcn < r.vcn + r.clusters)
            .context("MFT stream has a missing extent")?;
        let within = offset - run.vcn * cluster;
        let n = (run.clusters * cluster - within).min(dst.len() as u64) as usize;
        if let Some(lcn) = run.lcn {
            raw.read_exact_at(
                lcn.checked_mul(cluster)
                    .and_then(|x| x.checked_add(within))
                    .context("physical offset overflow")?,
                &mut dst[..n],
            )?;
        } else {
            dst[..n].fill(0);
        }
        offset += n as u64;
        dst = &mut dst[n..];
    }
    Ok(())
}
fn mft_extents(raw: &RawReader, g: &Geometry) -> Result<(Vec<Run>, u64)> {
    let mut first = vec![0; g.record];
    raw.read_exact_at(g.mft_offset, &mut first)?;
    fixup(&mut first, g.sector)?;
    let mut extents = Vec::new();
    let mut length = 0;
    let mut list = Vec::new();
    for attr in attributes(&first)? {
        match u32at(attr, 0)? {
            0x80 if attr[9] == 0 => {
                ensure!(attr[8] == 1, "MFT DATA must be nonresident");
                if u64at(attr, 16)? == 0 {
                    length = u64at(attr, 48)?;
                }
                extents.extend(runs(attr)?);
            }
            0x20 => {
                if attr[8] == 0 {
                    list = resident(attr)?.to_vec();
                } else {
                    let len = u64at(attr, 48)?;
                    ensure!(len <= 64 * 1024 * 1024, "excessive MFT attribute list");
                    list.resize(len as usize, 0);
                    read_stream(raw, &runs(attr)?, g.cluster, 0, &mut list)?;
                }
            }
            _ => {}
        }
    }
    ensure!(
        length > 0 && length % g.record as u64 == 0 && !extents.is_empty(),
        "missing/invalid MFT data stream"
    );
    let mut p = 0;
    let mut needed = Vec::new();
    while p + 26 <= list.len() {
        let kind = u32at(&list, p)?;
        let n = u16at(&list, p + 4)? as usize;
        if kind == 0xffffffff || kind == 0 {
            break;
        }
        ensure!(
            n >= 26 && p + n <= list.len(),
            "invalid MFT attribute-list entry"
        );
        if kind == 0x80 && list[p + 6] == 0 {
            let frn = u64at(&list, p + 16)?;
            if frn & MASK != 0 {
                needed.push((u64at(&list, p + 8)?, frn, u16at(&list, p + 24)?));
            }
        }
        p += n;
    }
    needed.sort_unstable();
    let mut visited = AHashSet::new();
    for (_, frn, _) in needed {
        if !visited.insert(frn) {
            continue;
        }
        let mut record = vec![0; g.record];
        let on_disk = read_stream(
            raw,
            &extents,
            g.cluster,
            (frn & MASK) * g.record as u64,
            &mut record,
        )
        .and_then(|()| fixup(&mut record, g.sector));
        if let Err(error) = on_disk {
            #[cfg(windows)]
            {
                record = raw
                    .file_record(frn & MASK, g.record)
                    .with_context(|| format!("read MFT extent record: {error:#}"))?;
                let usa = u16at(&record, 4)? as usize;
                if record.get(g.sector - 2..g.sector) == record.get(usa..usa + 2) {
                    fixup(&mut record, g.sector)?;
                }
            }
            #[cfg(not(windows))]
            return Err(error);
        }
        ensure!(
            u16at(&record, 16)? as u64 == frn >> 48,
            "reused MFT extent record"
        );
        for a in attributes(&record)? {
            if u32at(a, 0)? == 0x80 && a[9] == 0 && a[8] == 1 {
                extents.extend(runs(a)?);
            }
        }
    }
    extents.sort_by_key(|r| r.vcn);
    extents.dedup();
    let mut next = 0;
    for r in &extents {
        ensure!(
            r.vcn == next && r.lcn.is_some(),
            "MFT extent gap/overlap/sparse run"
        );
        next += r.clusters;
    }
    ensure!(
        next.checked_mul(g.cluster).is_some_and(|n| n >= length),
        "MFT extents shorter than data length"
    );
    Ok((extents, length))
}
#[derive(Debug)]
struct Name {
    parent: u64,
    text: Vec<u16>,
}
#[derive(Debug)]
struct Record {
    modified_ms: i64,
    frn: u64,
    base: u64,
    flags: u16,
    complex: bool,
    names: Vec<Name>,
    logical: u64,
    allocated: u64,
    has_data: bool,
    fallback: (u64, u64),
}
fn parse_record(record: &mut [u8], index: u64, sector: usize) -> Result<Option<Record>> {
    if record.iter().all(|b| *b == 0) {
        return Ok(None);
    }
    if record.get(..4) != Some(b"FILE") {
        bail!("non-FILE MFT record {index}");
    }
    if u16at(record, 22)? & 1 == 0 {
        return Ok(None);
    }
    fixup(record, sector)?;
    let mut out = Record {
        modified_ms: UNKNOWN_MTIME,
        frn: index | ((u16at(record, 16)? as u64) << 48),
        base: u64at(record, 32)?,
        flags: if u16at(record, 22)? & 2 != 0 { DIR } else { 0 },
        complex: false,
        names: Vec::new(),
        logical: 0,
        allocated: 0,
        has_data: false,
        fallback: (0, 0),
    };
    for a in attributes(record)? {
        match u32at(a, 0)? {
            0x10 => {
                let v = resident(a)?;
                out.modified_ms = i64::try_from(u64at(v, 8)?)
                    .ok()
                    .and_then(crate::platform::modified_unix_ms)
                    .unwrap_or(UNKNOWN_MTIME);
                if u32at(v, 32)? & 0x400 != 0 {
                    out.flags |= REPARSE;
                }
            }
            0x20 => out.complex = true,
            0x30 => {
                let v = resident(a)?;
                ensure!(v.len() >= 66, "short FILE_NAME");
                let n = v[64] as usize;
                ensure!(66 + n * 2 <= v.len(), "truncated FILE_NAME");
                if v[65] != 2 {
                    let text = v[66..66 + n * 2]
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|p| u16::from_le_bytes(*p))
                        .collect();
                    out.names.push(Name {
                        parent: u64at(v, 0)?,
                        text,
                    });
                    out.fallback = (u64at(v, 48)?, u64at(v, 40)?);
                }
            }
            0x80 => {
                let (logical, allocated) = if a[8] == 0 {
                    {
                        let len = resident(a)?.len() as u64;
                        (len, len.div_ceil(8) * 8)
                    }
                } else {
                    if u64at(a, 16)? != 0 {
                        continue;
                    }
                    let flags = u16at(a, 12)?;
                    let alloc =
                        if flags & 0x8001 != 0 && a.len() >= 72 && u16at(a, 32)? as usize >= 72 {
                            u64at(a, 64)?
                        } else {
                            u64at(a, 40)?
                        };
                    (u64at(a, 48)?, alloc)
                };
                out.logical = out
                    .logical
                    .checked_add(logical)
                    .context("stream size overflow")?;
                out.allocated = out
                    .allocated
                    .checked_add(allocated)
                    .context("stream allocation overflow")?;
                out.has_data = true;
            }
            0xc0 => out.flags |= REPARSE,
            _ => {}
        }
    }
    Ok(Some(out))
}
fn merge(base: &mut Record, mut other: Record) -> Result<()> {
    base.names.append(&mut other.names);
    base.modified_ms = crate::model::oldest_known(base.modified_ms, other.modified_ms);
    base.flags |= other.flags;
    base.logical = base
        .logical
        .checked_add(other.logical)
        .context("extension size overflow")?;
    base.allocated = base
        .allocated
        .checked_add(other.allocated)
        .context("extension allocation overflow")?;
    base.has_data |= other.has_data;
    Ok(())
}

pub fn scan(
    volume: &VolumeInfo,
    threads: usize,
    buffer_mib: usize,
    memory_limit: u64,
) -> Result<Snapshot> {
    let raw = RawReader::volume(volume)?;
    scan_raw(&raw, volume, threads, buffer_mib, memory_limit)
}
pub fn scan_raw(
    raw: &RawReader,
    volume: &VolumeInfo,
    threads: usize,
    buffer_mib: usize,
    memory_limit: u64,
) -> Result<Snapshot> {
    let mut boot = [0; 512];
    raw.read_exact_at(0, &mut boot)?;
    let g = Geometry::parse(&boot)?;
    let (extents, length) = mft_extents(raw, &g)?;
    let mut s = Snapshot::new(volume.root.clone(), volume.clone(), "ntfs-mft", threads);
    let mut parents: Vec<(u32, u64)> = Vec::new();
    let mut dirs = AHashMap::new();
    let mut complex: AHashMap<u64, Record> = AHashMap::new();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()?;
    let mut buffer =
        vec![0u8; (buffer_mib.clamp(1, 64) * 1024 * 1024 / g.record).max(1) * g.record];
    let mut offset = 0;
    while offset < length {
        let n = buffer.len().min((length - offset) as usize);
        read_stream(raw, &extents, g.cluster, offset, &mut buffer[..n])?;
        let parsed: Vec<_> = pool.install(|| {
            buffer[..n]
                .par_chunks_mut(g.record)
                .enumerate()
                .map(|(i, bytes)| {
                    parse_record(bytes, offset / g.record as u64 + i as u64, g.sector)
                })
                .collect()
        });
        for item in parsed {
            match item {
                Ok(Some(record)) => {
                    if record.base != 0 || record.complex {
                        let key = if record.base != 0 {
                            record.base
                        } else {
                            record.frn
                        };
                        if let Some(existing) = complex.get_mut(&key) {
                            merge(existing, record)?;
                        } else {
                            complex.insert(key, record);
                        }
                    } else {
                        add_record(record, &mut s, &mut parents, &mut dirs)?;
                    }
                }
                Ok(None) => {}
                Err(e) => s.warn(e.to_string()),
            }
        }
        offset += n as u64;
        s.stats.records_read += n as u64 / g.record as u64;
        let used = s.index_bytes()
            + parents.capacity() as u64 * 16
            + dirs.capacity() as u64 * 24
            + buffer.len() as u64;
        ensure!(
            used <= memory_limit,
            "MFT index memory budget exceeded ({} MiB); use --max-memory-mib or --backend fs on a subtree",
            used / 1024 / 1024
        );
    }
    for (key, mut record) in complex {
        record.frn = key;
        record.base = 0;
        add_record(record, &mut s, &mut parents, &mut dirs)?;
    }
    let mut orphan = None;
    let mut orphan_count = 0;
    for (node, frn) in parents {
        let parent = if let Some(p) = dirs.get(&frn) {
            *p
        } else {
            orphan_count += 1;
            match orphan {
                Some(i) => i,
                None => {
                    let id = s.push(
                        0,
                        &"[unresolved metadata]".encode_utf16().collect::<Vec<_>>(),
                        0,
                        0,
                        DIR | VIRTUAL | INCOMPLETE,
                    )?;
                    orphan = Some(id);
                    id
                }
            }
        };
        s.nodes[node as usize].parent = parent;
    }
    if orphan_count > 0 {
        s.warn(format!("{orphan_count} metadata names have missing/stale parent references; live volume changed or metadata unsupported"));
    }
    s.stats.raw_bytes_read = length;
    s.stats.warnings.push("Live metadata, not an atomic filesystem snapshot. Hardlink allocations are charged once; alternate DATA streams included. Reparse points are not followed.".into());
    s.finish()?;
    Ok(s)
}
fn add_record(
    mut r: Record,
    s: &mut Snapshot,
    parents: &mut Vec<(u32, u64)>,
    dirs: &mut AHashMap<u64, u32>,
) -> Result<()> {
    if r.frn & MASK == 5 {
        dirs.insert(r.frn, 0);
        return Ok(());
    }
    if r.names.is_empty() && (12..=15).contains(&(r.frn & MASK)) {
        return Ok(());
    } // Reserved MFT records are not namespace entries.
    if r.names.is_empty() {
        s.warn(format!("MFT record {} has no supported name", r.frn & MASK));
        return Ok(());
    }
    r.names
        .sort_by(|a, b| (a.parent, &a.text).cmp(&(b.parent, &b.text)));
    r.names
        .dedup_by(|a, b| a.parent == b.parent && a.text == b.text);
    if !r.has_data && r.flags & DIR == 0 && r.fallback.0 > 0 {
        r.logical = r.fallback.0;
        r.allocated = r.fallback.1;
        r.flags |= ESTIMATED;
        s.warn(format!(
            "MFT {} uses stale FILE_NAME sizes; DATA unavailable",
            r.frn & MASK
        ));
    }
    let links = r.names.len();
    for (index, name) in r.names.into_iter().enumerate() {
        ensure!(
            !name.text.contains(&47) && !name.text.contains(&92) && !name.text.contains(&0),
            "invalid NTFS filename component"
        );
        let flags = r.flags | if links > 1 { HARDLINK } else { 0 };
        let id = s.push(
            0,
            &name.text,
            r.logical,
            if index == 0 { r.allocated } else { 0 },
            flags,
        )?;
        s.set_file_mtime(
            id,
            if r.modified_ms == UNKNOWN_MTIME {
                None
            } else {
                Some(r.modified_ms)
            },
        );
        parents.push((id, name.parent));
        if r.flags & DIR != 0 {
            dirs.entry(r.frn).or_insert(id);
        }
    }
    Ok(())
}
