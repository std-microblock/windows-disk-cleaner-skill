//! Human-only Fluent review. All destructive approvals originate in these callbacks.
use crate::{
    deletion::{self, Approval, Event, LockDecision, Outcome, Prepared},
    plan, platform, report,
    review_tree::{Forest, Location, PAGE_SIZE},
    selection::TreeSelection,
};
use anyhow::{Context, Result};
use slint::{ComponentHandle, ModelRc, VecModel};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    path::{Path, PathBuf},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender, SyncSender},
    },
    time::Duration,
};
slint::include_modules!();
struct State {
    prepared: Option<Arc<Prepared>>,
    choices: Vec<TreeSelection>,
    forest: Forest,
    expanded: BTreeMap<i32, usize>,
    selected: Option<i32>,
    pending_promotion: Option<i32>,
    snapshot_identity: Option<platform::Identity>,
    lock_response: Option<SyncSender<LockDecision>>,
    cancel: Arc<AtomicBool>,
    path: PathBuf,
    snapshot: Option<PathBuf>,
    source: crate::deletion::IndexSource,
    sender: Sender<Event>,
    threads: usize,
}
fn snapshots(p: &Prepared) -> Vec<&crate::model::Snapshot> {
    p.targets.iter().map(|t| &t.tree).collect()
}
fn target_has_git(p: &Prepared, target: usize) -> bool {
    p.git.iter().any(|g| {
        platform::within(&g.root, &p.targets[target].target.path)
            || platform::within(&p.targets[target].target.path, &g.root)
    })
}
fn target_git_risk(p: &Prepared, target: usize) -> bool {
    p.git.iter().any(|g| {
        g.needs_confirmation()
            && (platform::within(&g.root, &p.targets[target].target.path)
                || platform::within(&p.targets[target].target.path, &g.root))
    })
}
/// 0 = no note, 1 = warn, 2 = critical. Notes live on the staged target, so they
/// also mark every ancestor group row and cannot hide in a collapsed subtree.
fn severity_of(target: &plan::Target) -> i32 {
    match target.severity() {
        Some(plan::Level::Critical) => 2,
        Some(plan::Level::Warn) => 1,
        None => 0,
    }
}
/// Row text for the worst notes of one target; hidden lower notes are counted.
fn alert_text(target: &plan::Target) -> String {
    let severity = severity_of(target);
    if severity == 0 {
        return String::new();
    }
    let level = if severity == 2 {
        plan::Level::Critical
    } else {
        plan::Level::Warn
    };
    let mut texts: Vec<String> = target
        .alerts
        .iter()
        .filter(|a| a.level == level)
        .map(|a| report::safe_text(&a.text))
        .collect();
    let hidden = target.alerts.len() - texts.len();
    let mut row = if texts.is_empty() {
        String::new()
    } else {
        texts.remove(0)
    };
    if hidden > 0 {
        row.push_str(&format!(" (+{hidden})"));
    }
    row
}
fn file_icon(name: &str, directory: bool, reparse: bool) -> &'static str {
    if reparse {
        return "link";
    }
    if directory {
        return "folder";
    }
    let extension = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match extension.as_str() {
        "zip" | "7z" | "rar" | "tar" | "gz" | "bz2" | "xz" => "archive",
        "rs" | "c" | "h" | "cpp" | "hpp" | "cs" | "js" | "mjs" | "ts" | "tsx" | "jsx" | "py"
        | "go" | "java" | "swift" | "html" | "css" | "slint" => "code",
        "json" | "toml" | "yaml" | "yml" | "xml" | "ini" | "cfg" | "lock" => "settings",
        "txt" | "md" | "log" | "csv" | "pdf" | "doc" | "docx" => "text",
        "png" | "jpg" | "jpeg" | "gif" | "svg" | "webp" | "bmp" | "avif" => "image",
        "mp4" | "mkv" | "webm" | "mov" | "avi" => "video",
        "mp3" | "wav" | "flac" | "m4a" | "ogg" => "audio",
        _ => "file",
    }
}
fn make_rows(
    p: &Prepared,
    forest: &Forest,
    choices: &[TreeSelection],
    expanded: &BTreeMap<i32, usize>,
) -> Vec<TreeRow> {
    enum Work {
        Node(i32, i32),
        More(i32, i32, usize),
    }
    struct Rows<'a> {
        p: &'a Prepared,
        trees: Vec<&'a crate::model::Snapshot>,
        forest: &'a Forest,
        choices: &'a [TreeSelection],
        expanded: &'a BTreeMap<i32, usize>,
        rows: Vec<TreeRow>,
    }
    impl Rows<'_> {
        fn append(&mut self, key: i32, depth: i32, stack: &mut Vec<Work>) {
            let Some(location) = self.forest.locate(key) else {
                return;
            };
            let (selected, total) = self.forest.tally(&self.trees, self.choices, key);
            let open = self.expanded.contains_key(&key);
            let (name, reason, directory, expandable, icon, warning, git, severity) = match location
            {
                Location::Group(group) => {
                    let g = &self.forest.groups[group];
                    (
                        g.name.clone(),
                        if g.drive {
                            format!("{} 个已标记目标", g.targets.len())
                        } else {
                            String::new()
                        },
                        true,
                        !g.children.is_empty(),
                        if g.drive { "drive" } else { "group-folder" },
                        g.targets.iter().any(|&t| target_git_risk(self.p, t)),
                        false,
                        g.targets
                            .iter()
                            .map(|&t| severity_of(&self.p.targets[t].target))
                            .max()
                            .unwrap_or(0),
                    )
                }
                Location::Entry { target, node } => {
                    let t = &self.p.targets[target];
                    let n = &t.tree.nodes[node as usize];
                    let name = if node == 0 {
                        t.target
                            .path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into_owned()
                    } else {
                        t.tree.name(node)
                    };
                    let reason = if node == 0 {
                        t.target.reason.clone()
                    } else if n.is_reparse() {
                        "重解析点 · 不跟随".into()
                    } else {
                        String::new()
                    };
                    let icon = file_icon(&name, n.is_dir(), n.is_reparse());
                    (
                        name,
                        reason,
                        n.is_dir(),
                        n.first_child != crate::model::NONE,
                        icon,
                        node == 0 && target_git_risk(self.p, target),
                        node == 0 && target_has_git(self.p, target),
                        if node == 0 { severity_of(&t.target) } else { 0 },
                    )
                }
            };
            let alert = match location {
                Location::Entry { target, node: 0 } => alert_text(&self.p.targets[target].target),
                _ => String::new(),
            };
            self.rows.push(TreeRow {
                key,
                depth,
                name: report::safe_text(&name).into(),
                size: format!(
                    "{} / {}",
                    report::human(selected.allocated),
                    report::human(total.allocated)
                )
                .into(),
                files: format!("{} / {}", selected.files, total.files).into(),
                check_state: self.forest.check_state(&self.trees, self.choices, key),
                reason: report::safe_text(&reason).into(),
                directory,
                group: matches!(location, Location::Group(_)),
                expandable,
                expanded: open,
                more: false,
                warning,
                git,
                icon: icon.into(),
                severity,
                alert: alert.into(),
            });
            if open {
                let children = self.forest.children(&self.trees, key);
                let limit = self.expanded[&key];
                if children.len() > limit {
                    stack.push(Work::More(key, depth + 1, children.len() - limit));
                }
                for &child in children.iter().take(limit).rev() {
                    stack.push(Work::Node(child, depth + 1));
                }
            }
        }
    }
    let mut view = Rows {
        p,
        trees: snapshots(p),
        forest,
        choices,
        expanded,
        rows: Vec::new(),
    };
    let mut stack: Vec<_> = forest
        .roots
        .iter()
        .rev()
        .map(|&key| Work::Node(key, 0))
        .collect();
    while let Some(work) = stack.pop() {
        match work {
            Work::Node(key, depth) => view.append(key, depth, &mut stack),
            Work::More(key, depth, left) => view.rows.push(TreeRow {
                key,
                depth,
                name: format!("再显示 {PAGE_SIZE} 项 · 还有 {left} 项").into(),
                reason: "折叠 / 分页不影响勾选范围".into(),
                size: "".into(),
                files: "".into(),
                check_state: 0,
                directory: false,
                group: false,
                expandable: false,
                expanded: false,
                more: true,
                warning: false,
                git: false,
                icon: "add".into(),
                severity: 0,
                alert: "".into(),
            }),
        }
    }

    view.rows
}
fn space_rows(p: &Prepared, choices: &[TreeSelection], outcome: Option<&Outcome>) -> Vec<SpaceRow> {
    p.volumes
        .iter()
        .map(|volume| {
            let before = outcome
                .and_then(|o| o.before.iter().find(|v| v.serial == volume.serial))
                .unwrap_or(volume);
            let candidate: u64 = p
                .targets
                .iter()
                .zip(choices)
                .filter(|(t, _)| t.tree.volume.serial == volume.serial)
                .map(|(_, s)| s.totals(0).allocated)
                .sum();
            let after = outcome
                .and_then(|o| o.after.iter().find(|v| v.serial == volume.serial))
                .map(|v| v.free_bytes)
                .unwrap_or_else(|| {
                    before
                        .free_bytes
                        .saturating_add(candidate)
                        .min(before.total_bytes)
                });
            SpaceRow {
                drive: platform::display_path(&volume.root).into(),
                before: report::human(before.free_bytes).into(),
                after: report::human(after).into(),
                result: if outcome.is_some() {
                    "实测"
                } else {
                    "预计"
                }
                .into(),
                before_ratio: if before.total_bytes == 0 {
                    0.
                } else {
                    1. - before.free_bytes as f32 / before.total_bytes as f32
                },
                after_ratio: if before.total_bytes == 0 {
                    0.
                } else {
                    1. - after as f32 / before.total_bytes as f32
                },
            }
        })
        .collect()
}
fn show_selection(ui: &ReviewWindow, s: &State) {
    let (Some(p), Some(key)) = (&s.prepared, s.selected) else {
        ui.set_can_unmark(false);
        return;
    };
    let trees = snapshots(p);
    let Some(path) = s.forest.path(&trees, key) else {
        ui.set_can_unmark(false);
        return;
    };
    ui.set_selected_key(key);
    ui.set_selected_path(platform::display_path(&path).into());
    let (explanation, alerts, preview, note_count, severity) = match s.forest.locate(key).unwrap() {
        Location::Group(group) => {
            let targets = &s.forest.groups[group].targets;
            let note_count: usize = targets
                .iter()
                .map(|&ti| p.targets[ti].target.alerts.len())
                .sum();
            let preview = plan::Level::WORST_FIRST
                .iter()
                .find_map(|&level| {
                    targets.iter().find_map(|&ti| {
                        p.targets[ti]
                            .target
                            .alerts
                            .iter()
                            .find(|a| a.level == level)
                            .map(|a| report::safe_text(&a.text))
                    })
                })
                .unwrap_or_default();
            let mut notes = Vec::new();
            for level in plan::Level::WORST_FIRST {
                for &ti in targets {
                    let t = &p.targets[ti].target;
                    for a in t.alerts.iter().filter(|a| a.level == level) {
                        if notes.len() < 32 {
                            notes.push(format!(
                                "{}  ·  {}\n{}",
                                a.level.label(),
                                platform::display_path(&t.path),
                                report::safe_text(&a.text)
                            ));
                        }
                    }
                }
            }
            if note_count > notes.len() {
                notes.push(format!(
                    "另有 {} 条提示；选择具体对象查看。",
                    note_count - notes.len()
                ));
            }
            let severity = targets
                .iter()
                .map(|&ti| severity_of(&p.targets[ti].target))
                .max()
                .unwrap_or(0);
            (
                String::new(),
                notes.join("\n\n"),
                preview,
                note_count,
                severity,
            )
        }
        Location::Entry { target, node } => {
            let t = &p.targets[target].target;
            let preview = plan::Level::WORST_FIRST
                .iter()
                .find_map(|&level| {
                    t.alerts
                        .iter()
                        .find(|a| a.level == level)
                        .map(|a| report::safe_text(&a.text))
                })
                .unwrap_or_default();
            (
                if node == 0 {
                    if t.reason.is_empty() {
                        String::new()
                    } else {
                        format!("原因：{}", t.reason)
                    }
                } else {
                    String::new()
                },
                if node == 0 {
                    t.alerts
                        .iter()
                        .map(|a| format!("{}\n{}", a.level.label(), report::safe_text(&a.text)))
                        .collect::<Vec<_>>()
                        .join("\n\n")
                } else {
                    String::new()
                },
                if node == 0 { preview } else { String::new() },
                if node == 0 { t.alerts.len() } else { 0 },
                if node == 0 { severity_of(t) } else { 0 },
            )
        }
    };
    ui.set_alerts_expanded(false);
    ui.set_selected_severity(severity);
    ui.set_selected_alert_count(note_count as i32);
    ui.set_selected_alert_preview(preview.into());
    ui.set_selected_alerts(alerts.into());
    ui.set_selected_reason(explanation.into());
    ui.set_can_unmark(!s.forest.target_indices(key).is_empty());
}

fn refresh_selection(ui: &ReviewWindow, s: &State) {
    if let Some(p) = &s.prepared {
        ui.set_rows(ModelRc::new(VecModel::from(make_rows(
            p,
            &s.forest,
            &s.choices,
            &s.expanded,
        ))));
        ui.set_spaces(ModelRc::new(VecModel::from(space_rows(
            p, &s.choices, None,
        ))));
        let bytes: u64 = s.choices.iter().map(|c| c.totals(0).allocated).sum();
        let files: u64 = s.choices.iter().map(|c| c.totals(0).files as u64).sum();
        let dirs: u64 = s.choices.iter().map(|c| c.totals(0).dirs as u64).sum();
        ui.set_total_size(
            format!(
                "{} / {}",
                report::human(bytes),
                report::human(p.allocated_upper_bound)
            )
            .into(),
        );
        ui.set_item_count(
            format!(
                "已选 {files} / {} 文件、{dirs} / {} 文件夹",
                p.targets
                    .iter()
                    .map(|t| t.tree.nodes[0].files as u64)
                    .sum::<u64>(),
                p.targets
                    .iter()
                    .map(|t| t.tree.nodes[0].dirs as u64)
                    .sum::<u64>()
            )
            .into(),
        );
        ui.set_can_delete(p.can_delete() && files + dirs > 0);
        ui.set_reviewed(false);
    }
}

fn refresh(ui: &ReviewWindow, state: &Rc<RefCell<State>>, fetch: bool) {
    ui.set_busy(true);
    ui.set_deleting(false);
    ui.set_finished(false);
    ui.set_can_delete(false);
    ui.set_reviewed(false);
    ui.set_modal_kind("".into());
    ui.set_progress(0.);
    ui.set_status("正在准备只读审阅快照…".into());
    let mut s = state.borrow_mut();
    s.cancel = Arc::new(AtomicBool::new(false));
    s.prepared = None;
    s.choices.clear();
    s.forest = Forest::default();
    s.expanded.clear();
    s.selected = None;
    s.pending_promotion = None;
    let path = s.path.clone();
    let snapshot = s.snapshot.clone();
    let source = s.source;
    let sender = s.sender.clone();
    let threads = s.threads;
    let cancel = s.cancel.clone();
    std::thread::spawn(move || {
        match deletion::prepare(&path, snapshot.as_deref(), source, fetch, threads, &sender) {
            Ok(p) => {
                if cancel.load(Ordering::Relaxed) {
                    let _ = sender.send(Event::Fatal("准备已停止，没有删除文件。".into()));
                } else {
                    let _ = sender.send(Event::Ready(Arc::new(p)));
                }
            }
            Err(e) => {
                let _ = sender.send(Event::Fatal(format!("{e:#}")));
            }
        }
    });
}
/// Only retire the task-local scan index after every marked target was handled.
/// Never remove an arbitrary external snapshot or one replaced during review.
fn cleanup_snapshot_after_success(s: &State, outcome: &Outcome) -> Option<String> {
    if outcome.cancelled || outcome.failed > 0 || !outcome.errors.is_empty() {
        return None;
    }
    let snapshot = s.snapshot.as_ref()?;
    let original = s.snapshot_identity.as_ref()?;
    if snapshot.extension().is_none_or(|ext| ext != "dcscan") {
        return None;
    }
    let plan_parent = s.path.parent()?;
    let actual_parent = platform::canonical(snapshot.parent()?).ok()?;
    let actual_plan_parent = platform::canonical(plan_parent).ok()?;
    if !platform::within(&actual_parent, &actual_plan_parent) {
        return None;
    }
    let store = plan::Store::open(&s.path).ok()?;
    if !store.plan.targets.is_empty() {
        return None;
    }
    drop(store);
    let current = platform::identity(snapshot).ok()?;
    if current.is_reparse()
        || !current.same_file(original)
        || current.length != original.length
        || current.modified != original.modified
    {
        return None;
    }
    match std::fs::remove_file(snapshot) {
        Ok(()) => Some("任务快照已自动清理。".into()),
        Err(e) => Some(format!("快照清理失败（删除结果不受影响）：{e}")),
    }
}

fn begin_delete(ui: &ReviewWindow, state: &Rc<RefCell<State>>, git_ack: bool) {
    if ui.get_busy() || ui.get_preview() || !ui.get_reviewed() {
        return;
    }
    let mut s = state.borrow_mut();
    let Some(p) = s.prepared.clone() else {
        return;
    };
    let approval = match Approval::from_gui(&p, &s.choices, git_ack) {
        Ok(a) => a,
        Err(e) => {
            ui.set_modal_title("不能开始删除".into());
            ui.set_modal_body(e.to_string().into());
            ui.set_modal_kind("error".into());
            return;
        }
    };
    s.cancel = Arc::new(AtomicBool::new(false));
    let cancel = s.cancel.clone();
    let tx = s.sender.clone();
    ui.set_modal_kind("".into());
    ui.set_busy(true);
    ui.set_deleting(true);
    ui.set_can_delete(false);
    ui.set_progress(0.);
    ui.set_status("正在复核标记目录；随后逐项按句柄核对并删除".into());
    std::thread::spawn(
        move || match deletion::execute(p, approval, cancel, tx.clone()) {
            Ok(o) => {
                let _ = tx.send(Event::Finished(o));
            }
            Err(e) => {
                let _ = tx.send(Event::Fatal(format!("{e:#}")));
            }
        },
    );
}
pub fn run(
    path: &Path,
    snapshot: Option<&Path>,
    source: deletion::IndexSource,
    fetch: bool,
) -> Result<()> {
    let index = snapshot.map(platform::absolute).transpose()?;
    let snapshot_identity = index.as_ref().map(|p| platform::identity(p)).transpose()?;
    let ui = ReviewWindow::new()?;
    let (tx, rx) = mpsc::channel();
    let path = platform::absolute(path)?;
    ui.set_plan_path(format!("计划：{}", platform::display_path(&path)).into());
    let state = Rc::new(RefCell::new(State {
        prepared: None,
        choices: Vec::new(),
        forest: Forest::default(),
        expanded: BTreeMap::new(),
        selected: None,
        pending_promotion: None,
        snapshot_identity,
        lock_response: None,
        cancel: Arc::new(AtomicBool::new(false)),
        path,
        snapshot: index,
        source,
        sender: tx,
        threads: 8,
    }));
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_refresh(move |fetch| {
            if let Some(ui) = weak.upgrade() {
                refresh(&ui, &state, fetch);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_toggle_row(move |key, more| {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let mut s = state.borrow_mut();
            let Some(p) = s.prepared.clone() else {
                return;
            };
            if s.forest.locate(key).is_none() {
                return;
            }
            if more {
                *s.expanded.entry(key).or_insert(PAGE_SIZE) += PAGE_SIZE;
            } else if s.expanded.remove(&key).is_none() {
                s.expanded.insert(key, PAGE_SIZE);
            }
            ui.set_rows(ModelRc::new(VecModel::from(make_rows(
                &p,
                &s.forest,
                &s.choices,
                &s.expanded,
            ))));
            show_selection(&ui, &s);
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_select_row(move |key| {
            if let Some(ui) = weak.upgrade() {
                let mut s = state.borrow_mut();
                s.selected = s.forest.locate(key).map(|_| key);
                show_selection(&ui, &s);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_unmark_selected(move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let s = state.borrow();
            let Some(p) = &s.prepared else {
                return;
            };
            let Some(key) = s.selected else {
                return;
            };
            let paths: Vec<_> = s
                .forest
                .target_indices(key)
                .iter()
                .map(|&ti| p.targets[ti].target.path.clone())
                .collect();
            let result = plan::undo(&s.path, &paths, false);
            drop(s);
            match result {
                Ok(_) => refresh(&ui, &state, false),
                Err(e) => {
                    ui.set_modal_title("取消标记失败".into());
                    ui.set_modal_body(format!("{e:#}").into());
                    ui.set_modal_kind("error".into());
                }
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_promote_group(move |key| {
            let Some(ui) = weak.upgrade() else { return; };
            if ui.get_busy() || ui.get_finished() || ui.get_preview() { return; }
            let mut s = state.borrow_mut();
            let Some(Location::Group(group)) = s.forest.locate(key) else { return; };
            if s.forest.groups[group].drive { return; }
            let path = platform::display_path(&s.forest.groups[group].path);
            let count = s.forest.groups[group].targets.len();
            s.pending_promotion = Some(key);
            ui.set_modal_title("扩大删除标记范围？".into());
            ui.set_modal_body(format!(
                "当前分组：{path}\n\n目前的复选框只控制下方 {count} 个已标记目标；分组目录本身不会被删除。\n\n升级后将撤销这些子目标标记，改为标记整个目录，包括当前未标记的文件和子目录。窗口会重新读取清单，所有勾选与永久删除确认均需重新进行。\n\n仅在你确认整个目录都不再需要时继续。"
            ).into());
            ui.set_modal_kind("promote".into());
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_confirm_promotion(move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            if ui.get_modal_kind() != "promote" || ui.get_busy() || ui.get_preview() {
                return;
            }
            let mut s = state.borrow_mut();
            let (Some(key), Some(p)) = (s.pending_promotion.take(), s.prepared.as_ref()) else {
                return;
            };
            let Some(Location::Group(group)) = s.forest.locate(key) else {
                return;
            };
            if s.forest.groups[group].drive {
                return;
            }
            let group_path = s.forest.groups[group].path.clone();
            let revision = p.plan.revision;
            let path = s.path.clone();
            let snapshot = s.snapshot.clone();
            let threads = s.threads;
            let tx = s.sender.clone();
            s.cancel = Arc::new(AtomicBool::new(false));
            let cancel = s.cancel.clone();
            ui.set_modal_kind("".into());
            ui.set_busy(true);
            ui.set_can_delete(false);
            ui.set_reviewed(false);
            ui.set_status("正在核对整个目录并更新标记（没有删除文件）…".into());
            std::thread::spawn(move || {
                let result = plan::promote_group(
                    &path,
                    &group_path,
                    revision,
                    snapshot.as_deref(),
                    threads,
                    &cancel,
                )
                .map(|_| ())
                .map_err(|e| format!("{e:#}"));
                let _ = tx.send(Event::PromotionResult(result));
            });
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_request_delete(move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            if ui.get_busy() || !ui.get_reviewed() {
                return;
            }
            let Some(p) = state.borrow().prepared.clone() else {
                return;
            };
            if deletion::selected_git_risk(&p, &state.borrow().choices) {
                let mut body = String::from("以下仓库存在未同步、本地独有或无法核实的数据。忽略项也可能包含重要文件；它们不会因为被 gitignore 就变得安全。\n\n");
                for g in deletion::selected_git(&p, &state.borrow().choices) {
                    if g.needs_confirmation() {
                        body += &format!(
                            "{}\n{}\n{}\n\n",
                            platform::display_path(&g.root),
                            g.concise(),
                            g.risks.join("\n")
                        );
                    }
                }
                body += "继续后，这些标记路径中的本地内容将被永久删除。";
                ui.set_modal_title("Git 数据需要第二次确认".into());
                ui.set_modal_body(body.into());
                ui.set_modal_kind("git".into());
            } else {
                begin_delete(&ui, &state, false);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_confirm_git(move || {
            if let Some(ui) = weak.upgrade()
                && ui.get_modal_kind() == "git"
            {
                begin_delete(&ui, &state, true);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_lock_choice(move |choice| {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let mut s = state.borrow_mut();
            if let Some(tx) = s.lock_response.take() {
                let action = match choice {
                    1 => LockDecision::Retry,
                    2 => LockDecision::CloseGracefully,
                    3 => LockDecision::ForceClose,
                    _ => LockDecision::Skip,
                };
                let _ = tx.send(action);
            }
            ui.set_modal_kind("".into());
            ui.set_force_close(false);
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_cancel_work(move || {
            if let Some(ui) = weak.upgrade() {
                let mut s = state.borrow_mut();
                if ui.get_busy() {
                    s.cancel.store(true, Ordering::Relaxed);
                    if let Some(tx) = s.lock_response.take() {
                        let _ = tx.send(LockDecision::Skip);
                    }
                    ui.set_modal_kind("".into());
                    ui.set_status("正在安全停止；已完成的删除无法撤销…".into());
                } else {
                    let _ = ui.hide();
                }
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.window().on_close_requested(move || {
            let Some(ui) = weak.upgrade() else {
                return slint::CloseRequestResponse::HideWindow;
            };
            if ui.get_busy() {
                let mut s = state.borrow_mut();
                s.cancel.store(true, Ordering::Relaxed);
                if let Some(tx) = s.lock_response.take() {
                    let _ = tx.send(LockDecision::Skip);
                }
                ui.set_modal_kind("".into());
                ui.set_status("正在安全停止，完成当前操作后可关闭。".into());
                slint::CloseRequestResponse::KeepWindowShown
            } else {
                slint::CloseRequestResponse::HideWindow
            }
        });
    }

    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_check_row(move |key, checked| {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            if ui.get_busy() || ui.get_finished() || !ui.get_modal_kind().is_empty() {
                return;
            }
            let mut s = state.borrow_mut();
            let Some(p) = s.prepared.clone() else {
                return;
            };
            if s.forest.locate(key).is_some() {
                let trees = snapshots(&p);
                let State {
                    forest, choices, ..
                } = &mut *s;
                forest.check(&trees, choices, key, checked);
                refresh_selection(&ui, &s);
                show_selection(&ui, &s);
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_check_all(move |checked| {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            if ui.get_busy() || ui.get_finished() || !ui.get_modal_kind().is_empty() {
                return;
            }
            let mut s = state.borrow_mut();
            let Some(p) = s.prepared.clone() else {
                return;
            };
            for (t, c) in p.targets.iter().zip(&mut s.choices) {
                c.set_subtree(&t.tree, 0, checked);
            }
            refresh_selection(&ui, &s);
            show_selection(&ui, &s);
        });
    }

    let timer = slint::Timer::default();
    {
        let weak = ui.as_weak();
        let state = state.clone();
        timer.start(slint::TimerMode::Repeated,Duration::from_millis(40),move||{let Some(ui)=weak.upgrade()else{return;};for event in rx.try_iter(){match event{
        Event::Preparing(message)=>ui.set_status(message.into()),
        Event::PromotionResult(result)=>match result { Ok(())=>refresh(&ui,&state,false), Err(error)=>{ui.set_busy(false);ui.set_can_delete(false);ui.set_modal_title("扩大标记失败".into());ui.set_modal_body(format!("{error}\n\n没有删除文件；请刷新后重新审阅标记。" ).into());ui.set_modal_kind("error".into());} },
        Event::Ready(p)=>{
            let mut s=state.borrow_mut();s.choices=p.targets.iter().map(|t|TreeSelection::all(&t.tree)).collect();match Forest::new(&snapshots(&p)){Ok(forest)=>{s.expanded=forest.initial_expansion();s.forest=forest;},Err(e)=>{ui.set_busy(false);ui.set_can_delete(false);ui.set_modal_title("无法构建文件树".into());ui.set_modal_body(format!("{e:#}").into());ui.set_modal_kind("error".into());continue;}}ui.set_rows(ModelRc::new(VecModel::from(make_rows(&p,&s.forest,&s.choices,&s.expanded))));ui.set_spaces(ModelRc::new(VecModel::from(space_rows(&p,&s.choices,None))));ui.set_total_size(report::human(p.allocated_upper_bound).into());ui.set_target_count(p.targets.len().to_string().into());ui.set_item_count(format!("{} 个文件 / 文件夹对象",p.total_items).into());let risks=p.git.iter().filter(|g|g.needs_confirmation()).count();ui.set_git_risk(risks>0);ui.set_git_title(if risks>0{format!("{risks} 处待确认")}else{"检查完成".into()}.into());ui.set_git_detail(if p.git.is_empty(){"未发现相关 Git 仓库"}else if risks>0{"包含本地数据或尚未核实远端"}else{"本次检查未发现未同步内容"}.into());ui.set_busy(false);ui.set_deleting(false);ui.set_can_delete(p.can_delete());ui.set_status(if p.problems.is_empty(){"请展开检查目标，然后勾选确认。".into()}else{format!("{} 项安全校验未通过，禁止执行。",p.problems.len()).into()});ui.set_progress_label("尚未删除任何文件".into());if !p.problems.is_empty(){ui.set_modal_title("需要先处理这些问题".into());ui.set_modal_body(p.problems.join("\n\n").into());ui.set_modal_kind("error".into());}s.selected=s.forest.roots.first().copied();s.prepared=Some(p);refresh_selection(&ui,&s);show_selection(&ui,&s);
        },
        Event::Progress{done,total,removed,failed,current}=>{ui.set_status(current.into());ui.set_progress(if total==0{0.}else{done as f32/total as f32});ui.set_progress_label(format!("{done}/{total} · 已删 {removed} · 失败 {failed}").into());},
        Event::Locked{path,owners,detail,response}=>{let mut s=state.borrow_mut();s.lock_response=Some(response);let mut body=format!("目标：{path}\n\n{detail}\n\nWindows Restart Manager 检测到：\n");if owners.is_empty(){body+="无法安全识别占用者。请手动关闭相关程序，再点重试；不会盲目关闭进程。";}for o in &owners{body+=&format!("• {}  (PID {}){}\n",o.name,o.pid,if o.critical{" [关键进程 / 服务：不会关闭]"}else{""});}body+="\n关闭应用可能影响其他已打开的文件，请先保存工作。";ui.set_modal_title("文件正在使用，需要你的决定".into());ui.set_modal_body(body.into());ui.set_can_close_owners(!owners.is_empty()&&owners.iter().all(|o|!o.critical));ui.set_force_close(false);ui.set_modal_kind("lock".into());},
        Event::Finished(outcome)=>{let snapshot_note=cleanup_snapshot_after_success(&state.borrow(),&outcome);ui.set_busy(false);ui.set_deleting(false);ui.set_finished(true);ui.set_can_delete(false);ui.set_reviewed(false);ui.set_modal_kind("".into());ui.set_status(if outcome.cancelled{"已按要求停止。未处理的标记保留，已删除内容不能恢复。"}else{"操作结束。未成功删除的目标仍保留在标记列表中。"}.into());ui.set_progress_label(format!("已删除 {} · 失败 {}{}",outcome.removed,outcome.failed,snapshot_note.as_deref().map(|n|format!(" · {n}")).unwrap_or_default()).into());if !outcome.cancelled{ui.set_progress(1.);}
            if let Some(p)=&state.borrow().prepared{ui.set_spaces(ModelRc::new(VecModel::from(space_rows(p,&state.borrow().choices,Some(&outcome)))));}
            if !outcome.errors.is_empty(){ui.set_modal_title("部分条目未删除".into());ui.set_modal_body(outcome.errors.join("\n").into());ui.set_modal_kind("error".into());}eprintln!("Cleanup result: {}",serde_json::to_string(&outcome).unwrap_or_default());},
        Event::Fatal(error)=>{ui.set_busy(false);ui.set_deleting(false);ui.set_can_delete(false);ui.set_modal_title("操作已停止".into());ui.set_modal_body(format!("{error}\n\n请刷新后重新审阅。已完成的删除无法撤销。").into());ui.set_modal_kind("error".into());ui.set_status("没有继续处理其他文件。".into());eprintln!("Review stopped: {error}");},
    }}});
    }
    refresh(&ui, &state, fetch);
    ui.run()?;
    state.borrow().cancel.store(true, Ordering::Relaxed);
    Ok(())
}

/// Representative metadata only. This creates NO files and shares the production
/// forest/selection/row builder, so previews cannot conceal grouping regressions.
fn example_prepared() -> Prepared {
    use crate::{
        deletion::PreparedTarget,
        git_audit::GitAudit,
        model::{DIR, Snapshot},
        plan::{Alert, Level, Plan, Summary, Target},
        platform::{Identity, VolumeInfo},
    };
    let gib = 1024 * 1024 * 1024u64;
    let mib = 1024 * 1024u64;
    let d = VolumeInfo {
        root: r"D:\".into(),
        filesystem: "NTFS".into(),
        serial: 1,
        total_bytes: 200 * gib,
        free_bytes: 6 * gib,
        ..Default::default()
    };
    let c = VolumeInfo {
        root: r"C:\".into(),
        filesystem: "NTFS".into(),
        serial: 2,
        total_bytes: 2 * 1024 * gib,
        free_bytes: 1024 * gib,
        ..Default::default()
    };
    let mut build = Snapshot::new(
        r"D:\Projects\target".into(),
        d.clone(),
        "example-metadata",
        1,
    );
    let debug = build
        .push(0, &"debug".encode_utf16().collect::<Vec<_>>(), 0, 0, DIR)
        .unwrap();
    build
        .push(
            debug,
            &"sample-app.exe".encode_utf16().collect::<Vec<_>>(),
            2 * gib,
            2 * gib,
            0,
        )
        .unwrap();
    build
        .push(
            debug,
            &"sample-app.pdb".encode_utf16().collect::<Vec<_>>(),
            gib,
            gib,
            0,
        )
        .unwrap();
    let release = build
        .push(0, &"release".encode_utf16().collect::<Vec<_>>(), 0, 0, DIR)
        .unwrap();
    build
        .push(
            release,
            &"sample-app.exe".encode_utf16().collect::<Vec<_>>(),
            gib,
            gib,
            0,
        )
        .unwrap();
    build
        .push(
            0,
            &"build.log".encode_utf16().collect::<Vec<_>>(),
            24 * mib,
            24 * mib,
            0,
        )
        .unwrap();
    build.finish().unwrap();
    let mut cache = Snapshot::new(
        r"D:\Cache\build-history".into(),
        d.clone(),
        "example-metadata",
        1,
    );
    cache
        .push(
            0,
            &"old-build.zip".encode_utf16().collect::<Vec<_>>(),
            gib,
            gib,
            0,
        )
        .unwrap();
    cache
        .push(
            0,
            &"build.json".encode_utf16().collect::<Vec<_>>(),
            2 * mib,
            2 * mib,
            0,
        )
        .unwrap();
    cache.finish().unwrap();
    let mut download = Snapshot::new(
        r"C:\Downloads\archive.zip".into(),
        c.clone(),
        "example-metadata",
        1,
    );
    download.nodes[0].flags = 0;
    download.nodes[0].files = 1;
    download.nodes[0].dirs = 0;
    download.nodes[0].logical = 4 * gib;
    download.nodes[0].allocated = 4 * gib;
    download.finish().unwrap();
    let items = [
        (
            build,
            "可重建的 Rust 编译产物",
            vec![Alert {
                level: Level::Warn,
                text: "示例：不确定是否仍用于本地调试；用户已确认可重建".into(),
            }],
        ),
        (
            cache,
            "过期的构建缓存",
            vec![Alert {
                level: Level::Critical,
                text: "示例：无法核实其中是否含唯一产物，删除前请再确认一次".into(),
            }],
        ),
        (download, "已解压，确认不再需要", Vec::new()),
    ];
    let mut targets = Vec::new();
    let mut plan = Plan::default();
    for (tree, reason, alerts) in items {
        let target = Target {
            id: uuid::Uuid::new_v4(),
            path: tree.root.clone(),
            reason: reason.into(),
            marked_unix: 0,
            identity: Identity::default(),
            summary: Summary::from_snapshot(&tree),
            git: None,
            alerts,
        };
        plan.targets.push(target.clone());
        targets.push(PreparedTarget { target, tree });
    }
    let total_items = targets.iter().map(|t| t.tree.nodes.len() as u64).sum();
    let allocated_upper_bound = targets.iter().map(|t| t.tree.nodes[0].allocated).sum();
    Prepared {
        plan_path: r"D:\example-plan.json".into(),
        plan,
        targets,
        git: vec![GitAudit {
            root: r"D:\Projects".into(),
            risks: vec!["示例：未核实远端".into()],
            ..GitAudit::default()
        }],
        problems: Vec::new(),
        volumes: vec![d, c],
        total_items,
        allocated_upper_bound,
    }
}

/// Render a read-only screenshot. No deletion or process-shutdown callbacks exist.
pub fn preview(output: &Path, state_name: &str) -> Result<()> {
    use slint::platform::{
        Platform, WindowAdapter,
        software_renderer::{MinimalSoftwareWindow, RepaintBufferType},
    };
    struct Headless(Rc<MinimalSoftwareWindow>);
    impl Platform for Headless {
        fn create_window_adapter(
            &self,
        ) -> std::result::Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
            Ok(self.0.clone())
        }
    }
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(Headless(window.clone())))
        .map_err(|e| anyhow::anyhow!("headless platform: {e}"))?;
    let ui = ReviewWindow::new()?;
    let p = Arc::new(example_prepared());
    let trees = snapshots(&p);
    let forest = Forest::new(&trees)?;
    let mut choices: Vec<_> = trees.iter().map(|t| TreeSelection::all(t)).collect();
    // One file intentionally unchecked: demonstrate parent/drive mixed states and
    // selected-byte rollup with real values rather than fabricated row labels.
    choices[0].set_subtree(trees[0], 3, false);
    let mut expanded = forest.initial_expansion();
    expanded.insert(forest.entry_key(0, 0).unwrap(), PAGE_SIZE);
    expanded.insert(forest.entry_key(0, 1).unwrap(), PAGE_SIZE);
    let (tx, _) = mpsc::channel();
    let selected = forest
        .groups
        .iter()
        .position(|g| g.path == Path::new(r"D:\"))
        .and_then(|i| forest.group_key(i).ok());
    let state = State {
        prepared: Some(p.clone()),
        choices,
        forest,
        expanded,
        selected,
        pending_promotion: None,
        snapshot_identity: None,
        lock_response: None,
        cancel: Arc::new(AtomicBool::new(false)),
        snapshot: None,
        source: crate::deletion::IndexSource::Volume,
        path: PathBuf::new(),
        sender: tx,
        threads: 1,
    };
    ui.set_preview(true);
    ui.set_busy(false);
    ui.set_plan_path("示例数据；不会读取或删除真实文件".into());
    refresh_selection(&ui, &state);
    show_selection(&ui, &state);
    if state_name == "notes-expanded" {
        ui.set_alerts_expanded(true);
    }
    if state_name == "git" {
        ui.set_modal_kind("git".into());
        ui.set_modal_title("Git 数据需要第二次确认".into());
        ui.set_modal_body("D:\\Projects\n\n分支 feature/local-work 含尚未同步的提交。\n另有 2 个未跟踪文件和 1 组 Git 忽略项。\n\n忽略项不代表可以删除。这里只处理树中已勾选的内容。\n\n此画面是示例，不会执行任何删除。".into());
    }
    if state_name == "lock" {
        ui.set_modal_kind("lock".into());
        ui.set_modal_title("文件正在使用，需要你的决定".into());
        ui.set_modal_body("目标：D:\\Cache\\build-history\\build.log\n\n占用程序：Example Editor (PID 4242)\n\n请先保存工作。只有你明确同意后才会请求应用关闭。\n\n此画面是示例，不会关闭进程。".into());
        ui.set_can_close_owners(true);
    }
    if state_name == "progress" {
        ui.set_deleting(true);
        ui.set_busy(true);
        ui.set_progress(0.64);
        ui.set_status(r"D:\Cache\build-history\build.json".into());
        ui.set_progress_label("7 / 11 · 示例进度".into());
    }
    let size = slint::PhysicalSize::new(1040, 790);
    window.set_size(size);
    ui.show()?;
    slint::platform::update_timers_and_animations();
    let mut buffer = vec![slint::Rgb8Pixel::default(); (size.width * size.height) as usize];
    window.draw_if_needed(|renderer| {
        renderer.render(&mut buffer, size.width as usize);
    });
    let bytes: Vec<u8> = buffer.iter().flat_map(|p| [p.r, p.g, p.b]).collect();
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    image::save_buffer(
        output,
        &bytes,
        size.width,
        size.height,
        image::ColorType::Rgb8,
    )
    .context("save UI preview")?;
    Ok(())
}
