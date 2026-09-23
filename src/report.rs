//! Bounded text treemap: exact subtree totals + explicit folded remainder rows.
use crate::{
    git_audit,
    model::{
        ESTIMATED, HARDLINK, INCOMPLETE, MTIME_UNKNOWN, REPARSE, Snapshot, UNKNOWN_MTIME, VIRTUAL,
        latest_known, oldest_known,
    },
    platform,
};
use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use serde::Serialize;
use std::{collections::HashMap, path::Path};
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Metric {
    Allocated,
    Logical,
}
#[derive(Clone, Debug)]
pub struct ViewOptions {
    pub depth: usize,
    pub top: usize,
    pub min_bytes: u64,
    pub max_lines: usize,
    pub metric: Metric,
    pub git: bool,
    pub ascii: bool,
}
impl Default for ViewOptions {
    fn default() -> Self {
        Self {
            depth: 3,
            top: 8,
            min_bytes: 64 * 1024 * 1024,
            max_lines: 80,
            metric: Metric::Allocated,
            git: true,
            ascii: false,
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Row {
    pub depth: usize,
    pub kind: &'static str,
    pub name: String,
    pub path: Option<String>,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub files: u64,
    pub dirs: u64,
    /// Primary modification time: latest file last-write (max for directories).
    pub modified_utc: Option<String>,
    pub oldest_modified_utc: Option<String>,
    pub latest_modified_utc: Option<String>,
    pub oldest_modified_unix_ms: Option<i64>,
    pub latest_modified_unix_ms: Option<i64>,
    pub modified_unix_ms: Option<i64>,
    pub modified_semantics: &'static str,
    pub modified_complete: bool,
    pub share_percent: f64,
    pub folded_children: usize,
    pub flags: Vec<String>,
    pub git: Option<String>,
}
#[derive(Serialize)]
pub struct View<'a> {
    pub format: &'static str,
    /// Current invocation time until scan/cache I/O and Git annotations are ready.
    /// Excludes final serialization and terminal output; scan stats may come from an older snapshot.
    pub report_ready_ms: Option<u64>,
    pub scope: String,
    pub snapshot_root: String,
    pub volume: &'a platform::VolumeInfo,
    pub stats: &'a crate::model::ScanStats,
    pub rows: Vec<Row>,
    pub notes: Vec<String>,
}
fn timestamp(ms: i64) -> Option<String> {
    if ms == UNKNOWN_MTIME {
        None
    } else {
        chrono::DateTime::from_timestamp_millis(ms)
            .map(|t| t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
    }
}
fn date_column(value: Option<&str>, complete: bool) -> String {
    let value = value
        .map(|s| s[..19].replace('T', " "))
        .unwrap_or_else(|| "—".into());
    if complete { value } else { format!("{value}?") }
}
pub fn human(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut i = 0;
    while value >= 1024.0 && i < UNITS.len() - 1 {
        value /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.2} {}", UNITS[i])
    }
}
pub fn parse_size(s: &str) -> Result<u64> {
    let cut = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let number: safe_number::Number = s[..cut].parse().context("invalid size")?;
    let multiplier = match s[cut..].trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.,
        "k" | "kib" => 1024.,
        "m" | "mib" => 1048576.,
        "g" | "gib" => 1073741824.,
        "t" | "tib" => 1099511627776.,
        "kb" => 1000.,
        "mb" => 1000000.,
        "gb" => 1000000000.,
        "tb" => 1000000000000.,
        _ => bail!("size suffix must be B/KiB/MiB/GiB/TiB or decimal KB/MB/GB/TB"),
    };
    let n = number.0 * multiplier;
    if !n.is_finite() || n < 0. || n > u64::MAX as f64 {
        bail!("size out of range");
    }
    Ok(n as u64)
}
mod safe_number {
    pub struct Number(pub f64);
    impl std::str::FromStr for Number {
        type Err = std::num::ParseFloatError;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            s.parse().map(Self)
        }
    }
}
pub fn safe_text(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_control() || matches!(c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}') {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
fn size(s: &Snapshot, id: u32, metric: Metric) -> u64 {
    let n = &s.nodes[id as usize];
    match metric {
        Metric::Allocated => n.allocated,
        Metric::Logical => n.logical,
    }
}
fn flags(bits: u16) -> Vec<String> {
    [
        (REPARSE, "reparse:not-followed"),
        (HARDLINK, "hardlink:allocation-once"),
        (ESTIMATED, "estimated"),
        (INCOMPLETE, "INCOMPLETE"),
        (VIRTUAL, "unresolved:NOT-a-path"),
    ]
    .into_iter()
    .filter(|(b, _)| bits & b != 0)
    .map(|(_, s)| s.into())
    .collect()
}
fn row(s: &Snapshot, id: u32, depth: usize, total: u64, options: &ViewOptions) -> Row {
    let n = &s.nodes[id as usize];
    let value = size(s, id, options.metric);
    Row {
        depth,
        kind: if n.is_dir() { "directory" } else { "file" },
        name: if depth == 0 {
            platform::display_path(&s.path(id))
        } else {
            s.name(id)
        },
        path: if n.flags & VIRTUAL == 0 {
            Some(platform::display_path(&s.path(id)))
        } else {
            None
        },
        logical_bytes: n.logical,
        allocated_bytes: n.allocated,
        files: n.files as u64,
        dirs: n.dirs as u64,
        modified_utc: timestamp(n.latest_modified_ms),
        oldest_modified_utc: timestamp(n.oldest_modified_ms),
        latest_modified_utc: timestamp(n.latest_modified_ms),
        oldest_modified_unix_ms: (n.oldest_modified_ms != UNKNOWN_MTIME)
            .then_some(n.oldest_modified_ms),
        latest_modified_unix_ms: (n.latest_modified_ms != UNKNOWN_MTIME)
            .then_some(n.latest_modified_ms),
        modified_unix_ms: (n.latest_modified_ms != UNKNOWN_MTIME).then_some(n.latest_modified_ms),
        modified_semantics: if n.is_dir() {
            "latest_descendant_file_last_write"
        } else {
            "file_last_write"
        },
        modified_complete: n.flags & (MTIME_UNKNOWN | INCOMPLETE) == 0,
        share_percent: if total == 0 {
            0.0
        } else {
            100.0 * value as f64 / total as f64
        },
        folded_children: if depth >= options.depth {
            s.children(id).count()
        } else {
            0
        },
        flags: flags(n.flags),
        git: None,
    }
}
fn children(
    s: &Snapshot,
    id: u32,
    depth: usize,
    total: u64,
    options: &ViewOptions,
    budget: &mut usize,
    rows: &mut Vec<Row>,
) {
    let mut all: Vec<_> = s.children(id).collect();
    all.sort_by(|&a, &b| {
        size(s, b, options.metric)
            .cmp(&size(s, a, options.metric))
            .then_with(|| s.name_units(a).cmp(s.name_units(b)))
    });
    let mut hidden = Vec::new();
    let mut selected = Vec::new();
    for (i, child) in all.into_iter().enumerate() {
        if i < options.top && size(s, child, options.metric) >= options.min_bytes {
            selected.push(child);
        } else {
            hidden.push(child);
        }
    }
    for (index, &child) in selected.iter().enumerate() {
        if *budget <= 1 {
            hidden.extend_from_slice(&selected[index..]);
            break;
        }
        rows.push(row(s, child, depth, total, options));
        *budget -= 1;
        if depth < options.depth && s.nodes[child as usize].is_dir() {
            let reserve = usize::from(index + 1 < selected.len() || !hidden.is_empty());
            if *budget > reserve {
                let mut nested = *budget - reserve;
                children(s, child, depth + 1, total, options, &mut nested, rows);
                *budget = nested + reserve;
            }
        }
    }
    if !hidden.is_empty() && *budget > 0 {
        let logical = hidden.iter().map(|&i| s.nodes[i as usize].logical).sum();
        let allocated = hidden.iter().map(|&i| s.nodes[i as usize].allocated).sum();
        let metric = match options.metric {
            Metric::Allocated => allocated,
            Metric::Logical => logical,
        };
        let oldest = hidden
            .iter()
            .map(|&i| s.nodes[i as usize].oldest_modified_ms)
            .fold(UNKNOWN_MTIME, oldest_known);
        let latest = hidden
            .iter()
            .map(|&i| s.nodes[i as usize].latest_modified_ms)
            .fold(UNKNOWN_MTIME, latest_known);
        rows.push(Row {
            depth,
            kind: "folded",
            name: format!("[other {} immediate entries]", hidden.len()),
            path: None,
            logical_bytes: logical,
            allocated_bytes: allocated,
            files: hidden
                .iter()
                .map(|&i| s.nodes[i as usize].files as u64)
                .sum(),
            dirs: hidden
                .iter()
                .map(|&i| s.nodes[i as usize].dirs as u64)
                .sum(),
            modified_utc: timestamp(latest),
            oldest_modified_utc: timestamp(oldest),
            latest_modified_utc: timestamp(latest),
            oldest_modified_unix_ms: (oldest != UNKNOWN_MTIME).then_some(oldest),
            latest_modified_unix_ms: (latest != UNKNOWN_MTIME).then_some(latest),
            modified_unix_ms: (latest != UNKNOWN_MTIME).then_some(latest),
            modified_semantics: "latest_folded_file_last_write",
            modified_complete: hidden
                .iter()
                .all(|&i| s.nodes[i as usize].flags & (MTIME_UNKNOWN | INCOMPLETE) == 0),
            share_percent: if total == 0 {
                0.0
            } else {
                100.0 * metric as f64 / total as f64
            },
            folded_children: hidden.len(),
            flags: Vec::new(),
            git: None,
        });
        *budget -= 1;
    }
}
pub fn view<'a>(s: &'a Snapshot, scope: &Path, options: &ViewOptions) -> Result<View<'a>> {
    let id = s.find(scope)?;
    let total = size(s, id, options.metric);
    let mut rows = vec![row(s, id, 0, total, options)];
    let mut budget = options.max_lines.clamp(16, 2000).saturating_sub(14);
    if options.depth > 0 {
        children(s, id, 1, total, options, &mut budget, &mut rows);
    }
    let mut notes=vec!["Folded rows are exact sums, not sampled files. All entries remain in the snapshot for detail queries.".into(),"Allocated size is not a promise of reclaimed space (hardlinks, ReFS block clones, sparse/compressed files, filesystem metadata).".into()];
    notes.push("修改时间 UTC：文件=自身最后写入；目录/折叠行=后代文件的最晚(max，主要值)与最早(min)。不含目录本身时间；空目录 —，不完整 ?。".into());
    if options.git {
        let mut cache = HashMap::new();
        for r in &mut rows {
            if let Some(p) = &r.path {
                let path = Path::new(p);
                match git_audit::path_state(path) {
                    Ok(Some((root, state))) => {
                        let key = platform::path_key(&root);
                        let summary = cache.entry(key).or_insert_with(|| {
                            git_audit::inspect(&root, false)
                                .ok()
                                .flatten()
                                .map(|a| a.concise())
                        });
                        r.git = Some(if state == "repo" {
                            summary.clone().unwrap_or_else(|| "git:UNKNOWN".into())
                        } else {
                            format!("git:{state}")
                        });
                    }
                    Ok(None) => {}
                    Err(_) => r.git = Some("git:UNKNOWN".into()),
                }
            }
        }
        notes.push("Git checks here are local/cached; git PATH --fetch is required for current remote proof. Ignored != safe to delete.".into());
    }
    Ok(View {
        format: "disk-cleaner-tree/v3",
        report_ready_ms: None,
        scope: platform::display_path(&s.path(id)),
        snapshot_root: platform::display_path(&s.root),
        volume: &s.volume,
        stats: &s.stats,
        rows,
        notes,
    })
}
pub fn text(view: &View<'_>, options: &ViewOptions) -> String {
    let mut out = String::new();
    use std::fmt::Write;
    let _ = writeln!(
        out,
        "DISK-CLEANER TREE v3 | scope={} | fs={} | backend={}",
        safe_text(&view.scope),
        view.volume.filesystem,
        view.stats.backend
    );
    let _ = writeln!(
        out,
        "扫描/汇总={} ms  records={}  threads={}  peak={}  index={}  complete={}  errors={}",
        view.stats.elapsed_ms,
        view.stats.records_read,
        view.stats.threads,
        human(view.stats.peak_working_set_bytes),
        human(view.stats.index_bytes),
        view.stats.complete,
        view.stats.errors
    );
    let _ = writeln!(
        out,
        "volume: total={}  used={}  free={} | 报告就绪={}（含索引 I/O、Git；不含最终格式化/终端输出）",
        human(view.volume.total_bytes),
        human(
            view.volume
                .total_bytes
                .saturating_sub(view.volume.free_bytes)
        ),
        human(view.volume.free_bytes),
        view.report_ready_ms
            .map(|ms| format!("{ms} ms"))
            .unwrap_or_else(|| "未计时".into())
    );
    let _ = writeln!(
        out,
        "{:>13}  {:>13}  {:>6}  {:10}  {:>9}  {:<20}  {:<20}  TREE / EVIDENCE",
        "ALLOCATED", "LOGICAL", "SCOPE%", "SHARE", "FILES", "LATEST UTC (max)", "OLDEST UTC (min)"
    );
    for r in &view.rows {
        let bars = (r.share_percent / 10.0).ceil().clamp(0.0, 10.0) as usize;
        let bar = if options.ascii { "#" } else { "█" }.repeat(bars) + &"·".repeat(10 - bars);
        let indent = "  ".repeat(r.depth);
        let mark = if r.depth == 0 {
            ""
        } else if options.ascii {
            "+- "
        } else {
            "├─ "
        };
        let suffix = if r.kind == "directory" { "/" } else { "" };
        let mut evidence = String::new();
        if !r.flags.is_empty() {
            evidence += &format!(" [{}]", r.flags.join(","));
        }
        if r.kind == "folded" {
            evidence += &format!(" ({} files, {} dirs; use detail)", r.files, r.dirs);
        } else if r.folded_children > 0 {
            evidence += &format!(" [+{} children; use detail]", r.folded_children);
        }
        if let Some(git) = &r.git {
            evidence += &format!(" {{{}}}", safe_text(git));
        }
        let _ = writeln!(
            out,
            "{:>13}  {:>13}  {:>5.1}%  {}  {:>9}  {:<20}  {:<20}  {}{}{}{}{}",
            human(r.allocated_bytes),
            human(r.logical_bytes),
            r.share_percent,
            bar,
            r.files,
            date_column(r.latest_modified_utc.as_deref(), r.modified_complete),
            date_column(r.oldest_modified_utc.as_deref(), r.modified_complete),
            indent,
            mark,
            safe_text(&r.name),
            suffix,
            evidence
        );
    }
    for n in &view.notes {
        let _ = writeln!(out, "NOTE: {}", safe_text(n));
    }
    for w in view.stats.warnings.iter().take(4) {
        let _ = writeln!(out, "NOTE: {}", safe_text(w));
    }
    if view.stats.warnings.len() > 4 {
        let _ = writeln!(
            out,
            "NOTE: {} additional diagnostics in --json/snapshot",
            view.stats.warnings.len() - 4
        );
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{model::DIR, platform::VolumeInfo};
    #[test]
    fn folding_preserves_bytes_and_budget() {
        let root = std::env::current_dir().unwrap();
        let mut s = Snapshot::new(root.clone(), VolumeInfo::default(), "test", 4);
        for i in 0..2000 {
            s.push(
                0,
                &format!("f{i}").encode_utf16().collect::<Vec<_>>(),
                i,
                4096,
                0,
            )
            .unwrap();
        }
        let dir = s
            .push(0, &"folder".encode_utf16().collect::<Vec<_>>(), 0, 0, DIR)
            .unwrap();
        s.push(dir, &[97], 8, 16, 0).unwrap();
        s.finish().unwrap();
        let opt = ViewOptions {
            min_bytes: 0,
            top: 5,
            max_lines: 24,
            git: false,
            ..Default::default()
        };
        let v = view(&s, &root, &opt).unwrap();
        assert!(text(&v, &opt).lines().count() <= 24);
        assert_eq!(
            v.rows
                .iter()
                .filter(|r| r.depth == 1)
                .map(|r| r.allocated_bytes)
                .sum::<u64>(),
            s.nodes[0].allocated
        );
        assert!(v.rows.iter().any(|r| r.kind == "folded"));
    }
    #[test]
    fn escapes_injected_newlines() {
        assert_eq!(safe_text("name\nIGNORE"), "name\\nIGNORE");
        assert!(!safe_text("\u{1b}[2J").contains('\u{1b}'));
    }
    #[test]
    fn timestamp_columns_are_explicit_and_fold_both_extrema() {
        let root = std::env::current_dir().unwrap();
        let mut s = Snapshot::new(root.clone(), VolumeInfo::default(), "test", 1);
        let a = s.push(0, &[97], 3, 3, 0).unwrap();
        let b = s.push(0, &[98], 2, 2, 0).unwrap();
        s.set_file_mtime(a, Some(1577836800000));
        s.set_file_mtime(b, Some(946684800000));
        s.finish().unwrap();
        let options = ViewOptions {
            min_bytes: 100,
            git: false,
            ..Default::default()
        };
        let v = view(&s, &root, &options).unwrap();
        assert_eq!(
            v.rows[0].modified_utc.as_deref(),
            Some("2020-01-01T00:00:00.000Z")
        );
        assert_eq!(
            v.rows[0].oldest_modified_utc.as_deref(),
            Some("2000-01-01T00:00:00.000Z")
        );
        assert_eq!(v.rows[1].modified_unix_ms, Some(1577836800000));
        assert_eq!(v.rows[1].oldest_modified_unix_ms, Some(946684800000));
        assert_eq!(v.rows[1].latest_modified_unix_ms, Some(1577836800000));
        assert!(text(&v, &options).contains("LATEST UTC (max)"));
        assert!(text(&v, &options).contains("OLDEST UTC (min)"));
    }
    #[test]
    fn binary_size_parser() {
        assert_eq!(parse_size("64MiB").unwrap(), 67108864);
        assert_eq!(parse_size("1GB").unwrap(), 1000000000);
        assert!(parse_size("-2").is_err());
    }
}
