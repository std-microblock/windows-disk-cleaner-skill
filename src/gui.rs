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
    time::{Duration, Instant},
};
slint::include_modules!();
mod dialogs;
mod eta;
use dialogs::Dialog;
struct State {
    prepared: Option<Arc<Prepared>>,
    choices: Vec<TreeSelection>,
    forest: Forest,
    expanded: BTreeMap<i32, usize>,
    selected: Option<i32>,
    pending_promotion: Option<i32>,
    snapshot_identity: Option<platform::Identity>,
    lock_response: Option<SyncSender<LockDecision>>,
    eta: Option<eta::DeleteEta>,
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
    ui.set_eta_label("".into());
    ui.set_progress_label("尚未删除任何文件".into());
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
            Dialog::approval_error(&e.to_string()).show(ui);
            return;
        }
    };
    s.cancel = Arc::new(AtomicBool::new(false));
    s.eta = Some(eta::DeleteEta::new(Instant::now()));
    let cancel = s.cancel.clone();
    let tx = s.sender.clone();
    ui.set_modal_kind("".into());
    ui.set_busy(true);
    ui.set_deleting(true);
    ui.set_can_delete(false);
    ui.set_progress(0.);
    ui.set_eta_label("".into());
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
fn apply_event(ui: &ReviewWindow, state: &Rc<RefCell<State>>, event: Event) {
    match event {
        Event::Preparing(message) => ui.set_status(message.into()),
        Event::PromotionResult(result) => match result {
            Ok(()) => refresh(ui, state, false),
            Err(error) => {
                ui.set_busy(false);
                ui.set_can_delete(false);
                Dialog::error(
                    "扩大标记失败",
                    "目录标记没有更新，请刷新后重新审阅。",
                    &[error],
                    "没有删除文件。",
                )
                .show(ui);
            }
        },
        Event::Ready(prepared) => {
            let mut s = state.borrow_mut();
            s.choices = prepared
                .targets
                .iter()
                .map(|t| TreeSelection::all(&t.tree))
                .collect();
            match Forest::new(&snapshots(&prepared)) {
                Ok(forest) => {
                    s.expanded = forest.initial_expansion();
                    s.forest = forest;
                }
                Err(error) => {
                    ui.set_busy(false);
                    ui.set_can_delete(false);
                    Dialog::error(
                        "无法构建文件树",
                        "审阅清单不完整，不能开始删除。请刷新后重试。",
                        &[format!("{error:#}")],
                        "没有删除文件。",
                    )
                    .show(ui);
                    return;
                }
            }
            ui.set_rows(ModelRc::new(VecModel::from(make_rows(
                &prepared,
                &s.forest,
                &s.choices,
                &s.expanded,
            ))));
            ui.set_spaces(ModelRc::new(VecModel::from(space_rows(
                &prepared, &s.choices, None,
            ))));
            ui.set_total_size(report::human(prepared.allocated_upper_bound).into());
            ui.set_target_count(prepared.targets.len().to_string().into());
            ui.set_item_count(format!("{} 个文件 / 文件夹对象", prepared.total_items).into());
            let risks = prepared
                .git
                .iter()
                .filter(|g| g.needs_confirmation())
                .count();
            ui.set_git_risk(risks > 0);
            ui.set_git_title(
                if risks > 0 {
                    format!("{risks} 处待确认")
                } else {
                    "检查完成".into()
                }
                .into(),
            );
            ui.set_git_detail(
                if prepared.git.is_empty() {
                    "未发现相关 Git 仓库"
                } else if risks > 0 {
                    "包含本地数据或尚未核实远端"
                } else {
                    "本次检查未发现未同步内容"
                }
                .into(),
            );
            ui.set_busy(false);
            ui.set_deleting(false);
            ui.set_can_delete(prepared.can_delete());
            ui.set_status(if prepared.problems.is_empty() {
                "请展开检查目标，然后勾选确认。".into()
            } else {
                format!("{} 项安全校验未通过，禁止执行。", prepared.problems.len()).into()
            });
            ui.set_progress_label("尚未删除任何文件".into());
            ui.set_eta_label("".into());
            if !prepared.problems.is_empty() {
                Dialog::error(
                    "需要先处理这些问题",
                    format!(
                        "{} 项安全问题阻止删除。请逐项检查，修复后刷新。",
                        prepared.problems.len()
                    ),
                    &prepared.problems,
                    "在问题解决之前，不会允许删除。",
                )
                .show(ui);
            }
            s.selected = s.forest.roots.first().copied();
            s.prepared = Some(prepared);
            refresh_selection(ui, &s);
            show_selection(ui, &s);
        }
        Event::Progress {
            done,
            total,
            removed,
            failed,
            current,
        } => {
            ui.set_status(current.into());
            ui.set_progress(if total == 0 {
                0.
            } else {
                done as f32 / total as f32
            });
            ui.set_progress_label(
                format!("{done}/{total} · 已删 {removed} · 失败 {failed}").into(),
            );
            let mut s = state.borrow_mut();
            let estimate = if s.cancel.load(Ordering::Relaxed) {
                String::new()
            } else {
                s.eta
                    .as_mut()
                    .map(|eta| eta.observe(Instant::now(), done, total))
                    .unwrap_or_default()
            };
            ui.set_eta_label(estimate.into());
        }
        Event::Locked {
            path,
            owners,
            detail,
            response,
        } => {
            let mut s = state.borrow_mut();
            s.lock_response = Some(response);
            if let Some(eta) = s.eta.as_mut() {
                eta.pause(Instant::now());
            }
            ui.set_eta_label("".into());
            Dialog::locked(&path, &owners, &detail).show(ui);
        }
        Event::Finished(outcome) => {
            let snapshot_note = cleanup_snapshot_after_success(&state.borrow(), &outcome);
            state.borrow_mut().eta = None;
            ui.set_busy(false);
            ui.set_deleting(false);
            ui.set_finished(true);
            ui.set_can_delete(false);
            ui.set_reviewed(false);
            ui.set_modal_kind("".into());
            ui.set_eta_label("".into());
            ui.set_status(
                if outcome.cancelled {
                    "已按要求停止。未处理的标记保留，已删除内容不能恢复。"
                } else {
                    "操作结束。未成功删除的目标仍保留在标记列表中。"
                }
                .into(),
            );
            ui.set_progress_label(
                format!(
                    "已删除 {} · 失败 {}{}",
                    outcome.removed,
                    outcome.failed,
                    snapshot_note
                        .as_deref()
                        .map(|n| format!(" · {n}"))
                        .unwrap_or_default(),
                )
                .into(),
            );
            if !outcome.cancelled {
                ui.set_progress(1.);
            }
            let s = state.borrow();
            if let Some(prepared) = &s.prepared {
                ui.set_spaces(ModelRc::new(VecModel::from(space_rows(
                    prepared,
                    &s.choices,
                    Some(&outcome),
                ))));
            }
            drop(s);
            if !outcome.errors.is_empty() {
                Dialog::partial_outcome(&outcome).show(ui);
            }
            eprintln!(
                "Cleanup result: {}",
                serde_json::to_string(&outcome).unwrap_or_default()
            );
        }
        Event::Fatal(error) => {
            let was_deleting = ui.get_deleting();
            state.borrow_mut().eta = None;
            ui.set_busy(false);
            ui.set_deleting(false);
            ui.set_can_delete(false);
            ui.set_eta_label("".into());
            ui.set_status("没有继续处理其他文件。".into());
            Dialog::error(
                "操作已停止",
                "已停止处理其他文件。请刷新并重新审阅，再决定是否重试。",
                std::slice::from_ref(&error),
                if was_deleting {
                    "已完成的删除无法撤销。"
                } else {
                    "尚未开始删除。"
                },
            )
            .show(ui);
            eprintln!("Review stopped: {error}");
        }
    }
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
        eta: None,
        cancel: Arc::new(AtomicBool::new(false)),
        path,
        snapshot: index,
        source,
        sender: tx,
        threads: 8,
    }));
    {
        let weak = ui.as_weak();
        ui.on_show_about(move || {
            if let Some(ui) = weak.upgrade()
                && !ui.get_busy()
            {
                Dialog::about().show(&ui);
            }
        });
    }
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
                    Dialog::error(
                        "取消标记失败",
                        "标记没有更改，请检查问题后重试。",
                        &[format!("{e:#}")],
                        "没有删除文件。",
                    )
                    .show(&ui);
                }
            }
        });
    }
    {
        let weak = ui.as_weak();
        let state = state.clone();
        ui.on_promote_group(move |key| {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            if ui.get_busy() || ui.get_finished() || ui.get_preview() {
                return;
            }
            let mut s = state.borrow_mut();
            let Some(Location::Group(group)) = s.forest.locate(key) else {
                return;
            };
            if s.forest.groups[group].drive {
                return;
            }
            let path = s.forest.groups[group].path.clone();
            let count = s.forest.groups[group].targets.len();
            s.pending_promotion = Some(key);
            Dialog::promotion(&path, count).show(&ui);
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
            let s = state.borrow();
            let Some(p) = s.prepared.as_ref() else {
                return;
            };
            let risks: Vec<_> = deletion::selected_git(p, &s.choices)
                .into_iter()
                .filter(|g| g.needs_confirmation())
                .collect();
            if !risks.is_empty() {
                Dialog::git(&risks).show(&ui);
            } else {
                drop(s);
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
            if let Some(eta) = s.eta.as_mut() {
                eta.resume(Instant::now());
                ui.set_eta_label("".into());
            }
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
                    if ui.get_deleting() {
                        ui.set_eta_label("".into());
                    }
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
                if ui.get_deleting() {
                    ui.set_eta_label("".into());
                }
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
        timer.start(
            slint::TimerMode::Repeated,
            Duration::from_millis(80),
            move || {
                let Some(ui) = weak.upgrade() else {
                    return;
                };
                for event in rx.try_iter() {
                    apply_event(&ui, &state, event);
                }
                if ui.get_deleting() && ui.get_modal_kind().is_empty() {
                    let s = state.borrow();
                    if !s.cancel.load(Ordering::Relaxed)
                        && s.eta
                            .as_ref()
                            .is_some_and(|eta| eta.is_stalled(Instant::now()))
                    {
                        ui.set_eta_label("".into());
                    }
                }
            },
        );
    }
    refresh(&ui, &state, fetch);
    ui.run()?;
    state.borrow().cancel.store(true, Ordering::Relaxed);
    Ok(())
}

/// Representative metadata only. This creates NO files and shares the production
/// forest/selection/row builder, so previews cannot conceal grouping regressions.
///
/// Paths, reasons and sizes mirror one real review; filler objects keep the
/// "selected / total" counts honest, because a real build tree holds thousands of
/// small objects and the published screenshots should show a genuine review.
fn example_prepared() -> Prepared {
    assemble().expect("build the example review snapshot")
}

fn assemble() -> Result<Prepared> {
    use crate::{
        deletion::PreparedTarget,
        git_audit::GitAudit,
        model::{DIR, Snapshot},
        plan::{Alert, Level, Plan, Summary, Target},
        platform::{Identity, VolumeInfo},
    };
    let gib = 1024 * 1024 * 1024u64;
    let mib = 1024 * 1024u64;
    let kib = 1024u64;
    fn dir(tree: &mut Snapshot, parent: u32, name: &str) -> Result<u32> {
        tree.push(parent, &name.encode_utf16().collect::<Vec<_>>(), 0, 0, DIR)
    }
    fn file(tree: &mut Snapshot, parent: u32, name: &str, bytes: u64) -> Result<u32> {
        tree.push(
            parent,
            &name.encode_utf16().collect::<Vec<_>>(),
            bytes,
            bytes,
            0,
        )
    }
    // Thousands of small objects, exactly like a real build tree. The review window
    // only renders their rolled-up rows, but the counts have to stay believable.
    fn pad(
        tree: &mut Snapshot,
        parent: u32,
        count: u32,
        seed: u64,
        min: u64,
        max: u64,
        name: impl Fn(u32) -> String,
    ) -> Result<()> {
        let mut state = seed | 1;
        for index in 0..count {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let size = min + (state >> 17) % (max - min + 1);
            let hash = (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 33;
            file(tree, parent, &name(hash as u32), size)?;
        }
        Ok(())
    }
    let d = VolumeInfo {
        root: r"D:\".into(),
        filesystem: "NTFS".into(),
        serial: 0x3f21_a904,
        total_bytes: 1863 * gib,
        free_bytes: 6 * gib + 194 * mib,
        cluster_bytes: 4096,
        ..Default::default()
    };
    let c = VolumeInfo {
        root: r"C:\".into(),
        filesystem: "NTFS".into(),
        serial: 0x1d2e_7b40,
        total_bytes: 953 * gib,
        free_bytes: 58 * gib + 52 * mib,
        cluster_bytes: 4096,
        ..Default::default()
    };
    let mut target = Snapshot::new(
        r"D:\celeste-research\MicroblocksQolUtils\target".into(),
        d.clone(),
        "ntfs",
        8,
    );
    let debug = dir(&mut target, 0, "debug")?;
    let deps = dir(&mut target, debug, "deps")?;
    pad(
        &mut target,
        deps,
        5412,
        0x9e37_79b9,
        48 * kib,
        2 * mib,
        |h| format!("libceleste_tools-{h:08x}.rlib"),
    )?;
    let incremental = dir(&mut target, debug, "incremental")?;
    pad(
        &mut target,
        incremental,
        4806,
        0x85eb_ca6b,
        16 * kib,
        512 * kib,
        |h| format!("s-h3df1zx02y-{h:08x}.bin"),
    )?;
    let fingerprint = dir(&mut target, debug, ".fingerprint")?;
    pad(
        &mut target,
        fingerprint,
        1214,
        0xc2b2_ae35,
        kib,
        64 * kib,
        |h| format!("celeste-tools-{h:08x}.json"),
    )?;
    let build = dir(&mut target, debug, "build")?;
    pad(
        &mut target,
        build,
        312,
        0x27d4_eb2f,
        8 * kib,
        256 * kib,
        |h| format!("build-script-build-{h:08x}.exe"),
    )?;
    file(&mut target, debug, "celeste-tools.exe", 486 * mib)?;
    file(&mut target, debug, "celeste-tools.pdb", gib + 186 * mib)?;
    file(&mut target, debug, "celeste_tools.d", 2 * mib + 96 * kib)?;
    let release = dir(&mut target, 0, "release")?;
    let release_deps = dir(&mut target, release, "deps")?;
    pad(
        &mut target,
        release_deps,
        146,
        0x1656_67b1,
        96 * kib,
        8 * mib,
        |h| format!("libceleste_tools-{h:08x}.rlib"),
    )?;
    file(
        &mut target,
        release,
        "celeste-tools.exe",
        38 * mib + 512 * kib,
    )?;
    file(&mut target, release, "celeste_tools.d", 2 * mib + 96 * kib)?;
    file(&mut target, 0, ".rustc_info.json", 1236)?;
    target.finish()?;

    let mut venv = Snapshot::new(
        r"D:\celeste-research\celeste-next-gym-ai\.venv".into(),
        d.clone(),
        "ntfs",
        8,
    );
    let lib = dir(&mut venv, 0, "Lib")?;
    let site = dir(&mut venv, lib, "site-packages")?;
    pad(
        &mut venv,
        site,
        18244,
        0x2545_f491,
        4 * kib,
        512 * kib,
        |h| format!("{h:08x}.cp312-win_amd64.pyd"),
    )?;
    let scripts = dir(&mut venv, 0, "Scripts")?;
    pad(
        &mut venv,
        scripts,
        46,
        0x7f4a_7c15,
        16 * kib,
        6 * mib,
        |h| format!("entry-{h:08x}.exe"),
    )?;
    file(&mut venv, 0, "pyvenv.cfg", 119)?;
    venv.finish()?;

    let mut archive = Snapshot::new(
        r"C:\Users\mbcloud\Downloads\celeste-next-gym-ai-ckpt-2026-08.zip".into(),
        c.clone(),
        "ntfs",
        8,
    );
    archive.nodes[0].flags = 0;
    archive.nodes[0].files = 1;
    archive.nodes[0].dirs = 0;
    archive.nodes[0].logical = 4 * gib + 288 * mib;
    archive.nodes[0].allocated = 4 * gib + 288 * mib;
    archive.finish()?;

    let items = [
        (
            target,
            "Rust 构建产物（cargo target）",
            vec![Alert {
                level: Level::Warn,
                text: "可由源码重建；删除后首次编译需重编全部依赖（本机约 12 分钟）".into(),
            }],
        ),
        (
            venv,
            "Python 虚拟环境（.venv）",
            vec![Alert {
                level: Level::Critical,
                text: "无法核实其中是否含手工安装、未写入 requirements 的包；删除后无法恢复".into(),
            }],
        ),
        (archive, "已归档到 D 盘，确认不再需要", Vec::new()),
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
    Ok(Prepared {
        plan_path: r"D:\celeste-research\clean-targets.json".into(),
        plan,
        targets,
        git: vec![
            GitAudit {
                root: r"D:\celeste-research\MicroblocksQolUtils".into(),
                branch: Some("main".into()),
                modified: 2,
                untracked: 3,
                ignored: 1,
                local_only_refs: vec!["tag:v3-vector-dataset".into()],
                remotes: vec!["origin".into()],
                risks: vec![
                    "tracked changes/conflicts exist only locally".into(),
                    "untracked worktree entries are not in Git".into(),
                    "ignored entries are LOCAL-ONLY too; ignore does not mean disposable".into(),
                    "remote refs are CACHED, not proof of current remote contents; run git --fetch to verify".into(),
                ],
                ..GitAudit::default()
            },
            GitAudit {
                root: r"D:\celeste-research\celeste-next-gym-ai".into(),
                branch: Some("main".into()),
                modified: 1,
                untracked: 2,
                ignored: 4,
                stashes: 1,
                local_only_refs: vec!["branch:experiment/vr-baseline".into()],
                remotes: vec!["origin".into()],
                risks: vec![
                    "ignored entries are LOCAL-ONLY too; ignore does not mean disposable".into(),
                    "local stashes are not protected by ordinary push".into(),
                    "remote origin unavailable/unverified: connection timed out".into(),
                ],
                ..GitAudit::default()
            },
        ],
        problems: Vec::new(),
        volumes: vec![d, c],
        total_items,
        allocated_upper_bound,
    })
}

/// Render a read-only screenshot. No deletion or process-shutdown callbacks exist.
pub fn preview(output: &Path, state_name: &str, dark: bool, compact: bool) -> Result<()> {
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
    if dark {
        ui.invoke_preview_dark();
    }
    let p = Arc::new(example_prepared());
    let trees = snapshots(&p);
    let forest = Forest::new(&trees)?;
    let mut choices: Vec<_> = trees.iter().map(|t| TreeSelection::all(t)).collect();
    // The release profile stays behind on purpose: it produces half-checked ancestors
    // and a "selected / total" rollup with the numbers a real review shows.
    let release = trees[0].find(Path::new(
        r"D:\celeste-research\MicroblocksQolUtils\target\release",
    ))?;
    choices[0].set_subtree(trees[0], release, false);
    let mut expanded = forest.initial_expansion();
    expanded.insert(forest.entry_key(0, 0).unwrap(), PAGE_SIZE);
    let (tx, _) = mpsc::channel();
    let selected = forest.entry_key(0, 0);
    let state = State {
        prepared: Some(p.clone()),
        choices,
        forest,
        expanded,
        selected,
        pending_promotion: None,
        snapshot_identity: None,
        lock_response: None,
        eta: None,
        cancel: Arc::new(AtomicBool::new(false)),
        snapshot: None,
        source: crate::deletion::IndexSource::Volume,
        path: PathBuf::new(),
        sender: tx,
        threads: 1,
    };
    ui.set_preview(true);
    ui.set_busy(false);
    ui.set_plan_path(format!("计划：{}", p.plan_path.display()).into());
    refresh_selection(&ui, &state);
    show_selection(&ui, &state);
    if state_name == "notes-expanded" {
        ui.set_alerts_expanded(true);
    }
    match state_name {
        "git" | "git-details" | "git-branch-long" => {
            let mut examples = p.git.clone();
            if state_name == "git-branch-long" {
                examples[0].branch =
                    Some("feature/vr-baseline-rework-with-vector-dataset-cache".into());
            }
            let audits: Vec<_> = examples.iter().collect();
            Dialog::git(&audits).show(&ui);
        }
        "git-long" | "git-scrolled" => {
            let mut audits = p.git.clone();
            audits[0].modified = 38;
            audits[0].untracked = 7;
            audits[0].ignored = 30;
            audits[0].risks.push(
                "2 linked worktree(s); their private state is not covered by this report".into(),
            );
            audits[1].root =
                r"D:\celeste-research\celeste-next-gym-ai\apps\desktop\packages\local-builds\unpublished-work"
                    .into();
            audits.push(crate::git_audit::GitAudit {
                root: r"D:\celeste-research\celeste-agent\node_modules\.pnpm\generated".into(),
                branch: Some("master".into()),
                modified: 10,
                untracked: 3,
                ignored: 8,
                remotes: vec!["origin".into()],
                risks: vec!["remote origin unavailable/unverified: connection timed out".into()],
                ..Default::default()
            });
            let refs: Vec<_> = audits.iter().collect();
            Dialog::git(&refs).show(&ui);
        }
        "lock" | "lock-details" | "lock-owner-long" | "lock-long" | "lock-scrolled"
        | "lock-unknown" | "lock-critical" | "lock-path-long" => {
            let owners = if state_name == "lock"
                || state_name == "lock-details"
                || state_name == "lock-owner-long"
            {
                vec![crate::locks::Owner {
                    pid: 21472,
                    name: if state_name == "lock-owner-long" {
                        "Microsoft Visual Studio Code — Insiders 扩展宿主、Renderer、Pylance 与远程隧道"
                            .into()
                    } else {
                        "python.exe".into()
                    },
                    service: String::new(),
                    critical: false,
                    restartable: true,
                    started: 0,
                }]
            } else if state_name == "lock-unknown" {
                Vec::new()
            } else if state_name == "lock-critical" {
                vec![crate::locks::Owner {
                    pid: 3960,
                    name: "Antimalware Service Executable".into(),
                    service: "WinDefend".into(),
                    critical: true,
                    restartable: false,
                    started: 0,
                }]
            } else {
                [
                    ("python.exe", 21472),
                    ("Code.exe", 38764),
                    ("jupyter-lab.exe", 21480),
                    ("explorer.exe", 4112),
                    ("msedgewebview2.exe", 19004),
                    ("Everything.exe", 9236),
                    ("SearchIndexer.exe", 6288),
                    ("Docker Desktop.exe", 15840),
                    ("WindowsTerminal.exe", 26712),
                    ("rclone.exe", 31044),
                    ("notepad++.exe", 17220),
                    ("TotalCMD64.exe", 40412),
                ]
                .iter()
                .map(|(name, pid)| crate::locks::Owner {
                    pid: *pid,
                    name: (*name).into(),
                    service: String::new(),
                    critical: false,
                    restartable: false,
                    started: 0,
                })
                .collect()
            };
            let path = if state_name == "lock-path-long" {
                r"D:\celeste-research\celeste-next-gym-ai\.venv\Lib\site-packages\torch\lib\cuda-precompiled-2026.08.14-windows-x64\torch_cuda.dll"
            } else {
                r"D:\celeste-research\celeste-next-gym-ai\.venv\Lib\site-packages\torch\lib\torch_cuda.dll"
            };
            Dialog::locked(
                path,
                &owners,
                "无法打开删除句柄：另一个进程正在使用此文件。(os error 32, ERROR_SHARING_VIOLATION)",
            )
            .show(&ui);
        }
        "promote" => {
            Dialog::promotion(Path::new(r"D:\celeste-research\celeste-next-gym-ai"), 1).show(&ui)
        }
        "error" | "error-scrolled" => {
            let errors: Vec<_> = (0..15)
                .map(|i| match i % 3 {
                    0 => format!(
                        r"D:\celeste-research\celeste-next-gym-ai\.venv\Lib\site-packages\torch\lib\torch_cuda-{i}.dll: file modification time changed after review; refresh required"
                    ),
                    1 => format!(
                        r"D:\celeste-research\celeste-next-gym-ai\.venv\Lib\site-packages\nvidia\cublas\lib\cublasLt64-{i}.dll: skipped occupied item"
                    ),
                    _ => format!(
                        r"D:\celeste-research\MicroblocksQolUtils\target\debug\deps\libceleste_tools-{i:08x}.rlib: file size changed after review; refresh required"
                    ),
                })
                .collect();
            Dialog::error(
                "部分项目未删除",
                "已删除 3412 项，失败 15 项。失败项目仍保留在标记中。",
                &errors,
                "已完成的删除无法撤销。",
            )
            .show(&ui);
        }
        "error-single" => Dialog::error(
            "不能开始删除",
            "安全校验未通过。请检查标记和 Git 风险。",
            &[
                r"D:\celeste-research\MicroblocksQolUtils\target: plan changed while window was open; refresh and confirm again"
                    .into(),
            ],
            "没有开始删除。",
        )
        .show(&ui),
        "about" => Dialog::about().show(&ui),
        "progress" => {
            ui.set_deleting(true);
            ui.set_busy(true);
            ui.set_progress(0.68);
            ui.set_status(
                r"D:\celeste-research\celeste-next-gym-ai\.venv\Lib\site-packages\torch\lib\torch_cuda.dll"
                    .into(),
            );
            ui.set_progress_label("3516/5142 · 已删 3512 · 失败 4".into());
            ui.set_eta_label("1m 25s".into());
        }
        "result" => {
            let mut after = p.volumes.clone();
            for volume in &mut after {
                let freed: u64 = p
                    .targets
                    .iter()
                    .zip(&state.choices)
                    .filter(|(t, _)| t.tree.volume.serial == volume.serial)
                    .map(|(_, s)| s.totals(0).allocated)
                    .sum();
                volume.free_bytes = (volume.free_bytes + freed).min(volume.total_bytes);
            }
            let removed_bytes = after
                .iter()
                .zip(&p.volumes)
                .map(|(a, b)| a.free_bytes - b.free_bytes)
                .sum();
            let outcome = Outcome {
                processed: 30_101,
                removed: 30_099,
                failed: 2,
                removed_bytes,
                cancelled: false,
                errors: vec![
                    r"D:\celeste-research\celeste-next-gym-ai\.venv\Lib\site-packages\nvidia\cublas\lib\cublasLt64-3.dll: skipped occupied item".into(),
                    r"D:\celeste-research\MicroblocksQolUtils\target\debug\deps\libceleste_tools-0000062b.rlib: file size changed after review; refresh required".into(),
                ],
                before: p.volumes.clone(),
                after,
            };
            ui.set_finished(true);
            ui.set_busy(false);
            ui.set_deleting(false);
            ui.set_can_delete(false);
            ui.set_reviewed(false);
            ui.set_progress(1.0);
            ui.set_status("操作结束。未成功删除的目标仍保留在标记列表中。".into());
            ui.set_progress_label(
                format!("已删除 {} · 失败 {}", outcome.removed, outcome.failed).into(),
            );
            ui.set_spaces(ModelRc::new(VecModel::from(space_rows(
                &p,
                &state.choices,
                Some(&outcome),
            ))));
        }
        _ => {}
    }
    let size = if compact {
        slint::PhysicalSize::new(900, 560)
    } else {
        slint::PhysicalSize::new(1180, 890)
    };
    window.set_size(size);
    ui.show()?;
    slint::platform::update_timers_and_animations();
    if state_name.ends_with("-details") {
        ui.set_modal_details_expanded(true);
        slint::platform::update_timers_and_animations();
    }
    if state_name.ends_with("-scrolled") {
        ui.invoke_preview_scroll_end();
        slint::platform::update_timers_and_animations();
    }
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
