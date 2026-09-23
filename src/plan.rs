//! Staging only. No filesystem deletion is reachable from rm or undo-rm.
use crate::{
    git_audit::{self, GitAudit},
    model::Snapshot,
    platform::{self, Identity},
    scan,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    path::{Component, Path, PathBuf},
};
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Summary {
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    pub files: u64,
    pub dirs: u64,
    pub errors: u64,
}
impl Summary {
    pub fn from_snapshot(s: &Snapshot) -> Self {
        let n = &s.nodes[0];
        Self {
            logical_bytes: n.logical,
            allocated_bytes: n.allocated,
            files: n.files as u64,
            dirs: n.dirs as u64,
            errors: s.stats.errors,
        }
    }
}
/// Severity of an agent-authored note. Notes only draw the human's attention to
/// something rm could not settle; they never authorize and never block deletion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Warn,
    Critical,
}
impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Level::Warn => "WARN",
            Level::Critical => "CRITICAL",
        }
    }
    pub fn flag(self) -> &'static str {
        match self {
            Level::Warn => "--warn",
            Level::Critical => "--critical",
        }
    }
    /// Worst first: the review window and the text view both list CRITICAL notes first.
    pub const WORST_FIRST: [Level; 2] = [Level::Critical, Level::Warn];
}
/// One note written by rm --warn/--critical. Text is stored verbatim and escaped
/// with report::safe_text for display, exactly like reasons and scanned names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub level: Level,
    pub text: String,
}
pub const MAX_ALERTS: usize = 16;
pub const MAX_ALERT_CHARS: usize = 300;
/// Build the note list for one rm invocation. Empty or oversized text is rejected
/// here rather than in the review window, so a typo cannot silently vanish.
pub fn notes(warn: &[String], critical: &[String]) -> Result<Vec<Alert>> {
    let mut alerts: Vec<Alert> = Vec::new();
    for (level, texts) in [(Level::Warn, warn), (Level::Critical, critical)] {
        for text in texts {
            let text = text.trim();
            ensure!(
                !text.is_empty(),
                "{} needs text describing what the human must check",
                level.flag()
            );
            ensure!(
                text.chars().count() <= MAX_ALERT_CHARS,
                "{} text is limited to {} characters",
                level.flag(),
                MAX_ALERT_CHARS
            );
            let alert = Alert {
                level,
                text: text.to_owned(),
            };
            if !alerts.contains(&alert) {
                alerts.push(alert);
            }
        }
    }
    ensure!(
        alerts.len() <= MAX_ALERTS,
        "too many notes; at most {MAX_ALERTS} per rm invocation"
    );
    Ok(alerts)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Target {
    pub id: uuid::Uuid,
    pub path: PathBuf,
    pub reason: String,
    pub marked_unix: u64,
    pub identity: Identity,
    pub summary: Summary,
    pub git: Option<GitAudit>,
    /// Attention notes written by rm --warn/--critical. Absent in older plans.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alerts: Vec<Alert>,
}
impl Target {
    /// Worst note severity, or None when rm recorded no note for this target.
    pub fn severity(&self) -> Option<Level> {
        self.alerts.iter().map(|a| a.level).max()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plan {
    pub schema_version: u32,
    pub revision: uuid::Uuid,
    pub created_unix: u64,
    pub updated_unix: u64,
    pub targets: Vec<Target>,
}
impl Default for Plan {
    fn default() -> Self {
        let now = platform::now_unix();
        Self {
            schema_version: 1,
            revision: uuid::Uuid::new_v4(),
            created_unix: now,
            updated_unix: now,
            targets: Vec::new(),
        }
    }
}
pub struct Store {
    pub path: PathBuf,
    lock: File,
    pub plan: Plan,
}
impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let path = platform::absolute(path)?;
        let parent = path.parent().context("plan needs a parent directory")?;
        std::fs::create_dir_all(parent)?;
        reject_reparse_ancestors(parent, true)?;
        let lock_path = path.with_extension("json.lock");
        if lock_path.exists() {
            ensure!(
                !platform::identity(&lock_path)?.is_reparse(),
                "plan lock must not be a reparse point"
            );
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(
                windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
            );
        }
        let lock = options.open(&lock_path)?;
        fs2::FileExt::try_lock_exclusive(&lock)
            .context("plan is in use by another disk-cleaner process")?;
        let plan = if path.exists() {
            ensure!(
                !platform::identity(&path)?.is_reparse(),
                "plan must not be a reparse point"
            );
            let f = File::open(&path)?;
            ensure!(
                f.metadata()?.len() < 64 * 1024 * 1024,
                "plan is unexpectedly large"
            );
            let p: Plan = serde_json::from_reader(BufReader::new(f))
                .context("read plan JSON (not executable instructions)")?;
            ensure!(p.schema_version == 1, "unsupported plan schema");
            ensure!(p.targets.len() <= 10000, "too many targets");
            // Notes are advisory, but a hand-edited plan must not smuggle megabytes
            // of text into the review window or the console.
            for t in &p.targets {
                ensure!(
                    t.alerts.len() <= MAX_ALERTS,
                    "too many notes on a staged target"
                );
                for a in &t.alerts {
                    ensure!(
                        !a.text.trim().is_empty() && a.text.chars().count() <= MAX_ALERT_CHARS,
                        "invalid note text in plan"
                    );
                }
            }
            p
        } else {
            Plan::default()
        };
        Ok(Self { path, lock, plan })
    }
    pub fn save(&mut self) -> Result<()> {
        self.plan.revision = uuid::Uuid::new_v4();
        self.plan.updated_unix = platform::now_unix();
        let tmp = self
            .path
            .with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let f = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
        {
            let mut w = BufWriter::new(&f);
            serde_json::to_writer_pretty(&mut w, &self.plan)?;
            w.write_all(b"\n")?;
            w.flush()?;
        }
        f.sync_all()?;
        drop(f);
        platform::atomic_replace(&tmp, &self.path)
    }
}
impl Drop for Store {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.lock);
    }
}

/// Reject device namespaces, ADS, globbing and relative-drive aliases up front.
pub fn literal_absolute(input: &Path) -> Result<PathBuf> {
    let s = input.to_str().context(
        "non-Unicode command paths are not supported for cleanup; no lossy conversion allowed",
    )?;
    ensure!(!s.contains('\0'), "NUL in cleanup path");
    #[cfg(windows)]
    {
        let s = s.strip_prefix(r"\\?\").unwrap_or(s);
        ensure!(
            !s.starts_with(r"\\") && !s.to_ascii_uppercase().starts_with("GLOBALROOT"),
            "only local drive-letter paths are accepted for cleanup"
        );
        ensure!(
            !s.contains('*') && !s.contains('?'),
            "cleanup targets are literal paths, never globs"
        );
        for (i, c) in s.chars().enumerate() {
            ensure!(
                c != ':' || i == 1,
                "alternate data streams/device names are not cleanup targets"
            );
        }
        if s.as_bytes().get(1) == Some(&b':') {
            ensure!(
                s.as_bytes()
                    .get(2)
                    .is_some_and(|c| *c == b'\\' || *c == b'/'),
                "drive-relative paths such as C:foo are ambiguous"
            );
        }
    }
    let absolute = platform::absolute(input)?;
    let mut normalized = PathBuf::new();
    for c in absolute.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                ensure!(normalized.pop(), "cleanup path escapes its root");
            }
            _ => normalized.push(c.as_os_str()),
        }
    }
    Ok(normalized)
}
/// No traversal through junctions/symlinks/mount points. The leaf may be a link:
/// it will be unlinked as a leaf, never traversed.
pub fn reject_reparse_ancestors(path: &Path, include_leaf: bool) -> Result<()> {
    let end = if include_leaf {
        path
    } else {
        path.parent().context("target has no parent")?
    };
    let mut chain: Vec<_> = end.ancestors().collect();
    chain.reverse();
    for p in chain {
        if p.as_os_str().is_empty() {
            continue;
        }
        let id =
            platform::identity(p).with_context(|| format!("validate ancestor {}", p.display()))?;
        ensure!(
            !id.is_reparse(),
            "refusing to traverse reparse-point ancestor {}",
            p.display()
        );
    }
    Ok(())
}
pub fn validate_target(input: &Path, plan_path: &Path) -> Result<(PathBuf, Identity)> {
    let path = literal_absolute(input)?;
    reject_reparse_ancestors(&path, false)?;
    let parent = platform::canonical(path.parent().context("volume roots cannot be removed")?)?;
    let name = path.file_name().context("volume roots cannot be removed")?;
    let canonical = parent.join(name);
    let identity = platform::identity(&canonical)?;
    let volume = platform::volume_info(&canonical)?;
    ensure!(
        platform::path_key(&canonical) != platform::path_key(&volume.root),
        "volume roots are protected"
    );
    for protected in [
        std::env::current_dir()?,
        std::env::current_exe()?,
        platform::absolute(plan_path)?,
    ] {
        ensure!(
            !platform::within(&protected, &canonical),
            "target contains the current workspace, running executable, or active plan: {}",
            protected.display()
        );
    }
    for key in ["SystemRoot", "WINDIR"] {
        if let Some(p) = std::env::var_os(key) {
            ensure!(
                !platform::within(&canonical, Path::new(&p)),
                "Windows system directories are protected"
            );
        }
    }
    for key in [
        "USERPROFILE",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramData",
    ] {
        if let Some(p) = std::env::var_os(key) {
            ensure!(
                platform::path_key(&canonical) != platform::path_key(Path::new(&p)),
                "profile/application root is protected"
            );
        }
    }
    let display = PathBuf::from(platform::display_path(&canonical));
    let components: Vec<_> = display
        .components()
        .filter_map(|c| {
            if let Component::Normal(s) = c {
                Some(s.to_string_lossy().to_lowercase())
            } else {
                None
            }
        })
        .collect();
    ensure!(
        !components.iter().any(|s| s == ".git"),
        "direct removal inside .git is forbidden; stage the entire repository instead"
    );
    if let Some(first) = components.first() {
        ensure!(
            ![
                "windows",
                "system volume information",
                "$recycle.bin",
                "$extend",
                "$mft",
                "$mftmirr",
                "$logfile",
                "$bitmap",
                "$boot",
                "$secure",
                "pagefile.sys",
                "hiberfil.sys",
                "swapfile.sys",
                "boot",
                "recovery"
            ]
            .contains(&first.as_str()),
            "OS/volume-managed paths are protected"
        );
        if components.len() == 1 {
            ensure!(
                ![
                    "users",
                    "program files",
                    "program files (x86)",
                    "programdata"
                ]
                .contains(&first.as_str()),
                "system container root is protected"
            );
        }
    }
    Ok((canonical, identity))
}
pub fn stage(
    plan_path: &Path,
    paths: &[PathBuf],
    recursive: bool,
    force: bool,
    reason: &str,
    alerts: &[Alert],
    threads: usize,
) -> Result<Vec<Target>> {
    ensure!(
        reason.chars().count() <= 2000,
        "reason is limited to 2000 characters"
    );
    let mut store = Store::open(plan_path)?;
    let mut additions = Vec::new();
    for path in paths {
        if force {
            match std::fs::symlink_metadata(path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e).context("inspect staged target"),
                Ok(_) => {}
            }
        }
        let (path, identity) = validate_target(path, &store.path)?;
        ensure!(
            !identity.is_dir() || identity.is_reparse() || recursive,
            "directory requires -r/--recursive (still stage-only)"
        );
        for existing in store.plan.targets.iter().chain(additions.iter()) {
            ensure!(
                !platform::within(&path, &existing.path)
                    && !platform::within(&existing.path, &path),
                "overlapping target already staged: {}; undo-rm it first",
                existing.path.display()
            );
        }
        let summary = if identity.is_dir() && !identity.is_reparse() {
            Summary::from_snapshot(&scan::fs::scan(
                &path,
                platform::volume_info(&path)?,
                threads,
                512 * 1024 * 1024,
            )?)
        } else {
            Summary {
                logical_bytes: identity.length,
                allocated_bytes: identity.allocated,
                files: 1,
                ..Default::default()
            }
        };
        let git = git_audit::inspect(&path, false).unwrap_or_else(|e| {
            Some(GitAudit {
                root: path.clone(),
                risks: vec![format!("Git check failed: {e:#}")],
                ..Default::default()
            })
        });
        additions.push(Target {
            id: uuid::Uuid::new_v4(),
            path,
            reason: reason.into(),
            marked_unix: platform::now_unix(),
            identity,
            summary,
            git,
            alerts: alerts.to_vec(),
        });
    }
    store.plan.targets.extend(additions.clone());
    if !additions.is_empty() {
        store.save()?;
    }
    Ok(additions)
}
pub fn undo(plan_path: &Path, paths: &[PathBuf], all: bool) -> Result<usize> {
    let mut store = Store::open(plan_path)?;
    let keys = paths
        .iter()
        .map(|p| literal_absolute(p).map(|p| platform::path_key(&p)))
        .collect::<Result<Vec<_>>>()?;
    let before = store.plan.targets.len();
    store
        .plan
        .targets
        .retain(|t| !all && !keys.contains(&platform::path_key(&t.path)));
    let removed = before - store.plan.targets.len();
    if removed > 0 {
        store.save()?;
    }
    Ok(removed)
}
