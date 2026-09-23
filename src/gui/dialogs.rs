//! Human-readable, structured data for review decisions. The UI lays these out as
//! compact facts; raw diagnostics are available only on explicit expansion.
use super::{DialogRow, ReviewWindow};
use crate::{deletion::Outcome, git_audit::GitAudit, locks::Owner, platform, report};
use slint::{ModelRc, VecModel};
use std::path::Path;

fn entry(
    kind: &str,
    label: impl AsRef<str>,
    value: impl AsRef<str>,
    path: impl AsRef<str>,
    severity: i32,
) -> DialogRow {
    DialogRow {
        kind: kind.into(),
        label: report::safe_text(label.as_ref()).into(),
        value: report::safe_text(value.as_ref()).into(),
        path: report::safe_text(path.as_ref()).into(),
        severity,
    }
}

pub(super) struct Dialog {
    kind: &'static str,
    title: String,
    summary: String,
    path: String,
    notice: String,
    rows: Vec<DialogRow>,
    technical: String,
    can_close_owners: bool,
}

impl Dialog {
    pub(super) fn show(self, ui: &ReviewWindow) {
        ui.set_modal_kind("".into());
        ui.set_modal_scroll_y(0.0);
        ui.set_modal_details_expanded(false);
        ui.set_modal_title(self.title.into());
        ui.set_modal_summary(self.summary.into());
        ui.set_modal_path(report::safe_text(&self.path).into());
        ui.set_modal_warning(self.notice.into());
        ui.set_modal_technical(
            self.technical
                .lines()
                .map(report::safe_text)
                .collect::<Vec<_>>()
                .join("\n")
                .into(),
        );
        ui.set_modal_items(ModelRc::new(VecModel::from(self.rows)));
        ui.set_can_close_owners(self.can_close_owners);
        ui.set_force_close(false);
        ui.set_modal_kind(self.kind.into());
    }

    pub(super) fn about() -> Self {
        Self {
            kind: "about",
            title: "Disk Cleaner".into(),
            summary: "Windows 磁盘分析与人工确认清理".into(),
            path: String::new(),
            notice: String::new(),
            rows: vec![
                entry("fact", "版本", env!("CARGO_PKG_VERSION"), "", 0),
                entry(
                    "fact",
                    "扫描后端",
                    "NTFS / ReFS 卷原始索引；fs 为普通目录枚举",
                    "",
                    0,
                ),
                entry(
                    "fact",
                    "删除方式",
                    "先标记、再审阅；命令行不会删除文件。",
                    "",
                    0,
                ),
            ],
            technical: String::new(),
            can_close_owners: false,
        }
    }

    pub(super) fn promotion(path: &Path, count: usize) -> Self {
        Self {
            kind: "promote",
            title: "标记整个目录？".into(),
            summary: "只更改标记，不会立即删除文件。".into(),
            path: platform::display_path(path),
            notice: "更改后会重新读取清单，并要求你再次勾选确认。".into(),
            rows: vec![
                entry("fact", "当前", format!("{count} 个已标记目标"), "", 0),
                entry("fact", "更改后", "整个目录，包括尚未标记的内容", "", 1),
            ],
            technical: String::new(),
            can_close_owners: false,
        }
    }

    pub(super) fn git(audits: &[&GitAudit]) -> Self {
        let mut rows = Vec::new();
        let mut technical = Vec::new();
        for (index, audit) in audits.iter().enumerate() {
            let branch = audit.branch.as_deref().unwrap_or(if audit.detached {
                "分离的 HEAD"
            } else {
                "分支未知"
            });
            let remote = if audit.remote_verified {
                "远端已核实"
            } else {
                "远端未核实"
            };
            rows.push(entry(
                "repo",
                format!("仓库 {} · {branch}", index + 1),
                remote,
                platform::display_path(&audit.root),
                0,
            ));
            if audit.modified + audit.staged + audit.conflicts > 0 {
                rows.push(entry(
                    "fact",
                    "工作区",
                    format!(
                        "{} 项改动 · {} 项暂存 · {} 项冲突",
                        audit.modified, audit.staged, audit.conflicts
                    ),
                    "",
                    1,
                ));
            }
            if audit.untracked + audit.ignored > 0 {
                rows.push(entry(
                    "fact",
                    "本地文件",
                    format!("{} 项未跟踪 · {} 项被忽略", audit.untracked, audit.ignored),
                    "",
                    1,
                ));
            }
            if audit.stashes > 0 || !audit.local_only_refs.is_empty() {
                rows.push(entry(
                    "fact",
                    "本地记录",
                    format!(
                        "{} 个 stash · {} 个分支或标签未证实已在远端",
                        audit.stashes,
                        audit.local_only_refs.len()
                    ),
                    "",
                    1,
                ));
            }
            if !audit.remote_verified {
                rows.push(entry(
                    "fact",
                    "远端状态",
                    if audit.remotes.is_empty() {
                        "没有配置远端"
                    } else {
                        "尚未在线核实，缓存不能证明远端已有备份"
                    },
                    "",
                    1,
                ));
            }
            for risk in &audit.risks {
                if let Some(extra) = additional_git_risk(risk) {
                    rows.push(extra);
                }
            }
            if audit.risks.is_empty()
                && audit.modified + audit.staged + audit.untracked + audit.ignored + audit.stashes
                    == 0
                && audit.local_only_refs.is_empty()
            {
                rows.push(entry(
                    "fact",
                    "检查结果",
                    "不能证明这些本地内容可从远端恢复",
                    "",
                    1,
                ));
            }
            technical.push(format!(
                "{}\n{}",
                platform::display_path(&audit.root),
                audit.risks.join("\n")
            ));
            if !audit.local_only_refs.is_empty() {
                technical.push(format!("本地引用：{}", audit.local_only_refs.join("、")));
            }
        }
        Self {
            kind: "git",
            title: "Git 数据可能只在本机".into(),
            summary: format!(
                "{} 个相关仓库需要确认。继续将永久删除已勾选的内容。",
                audits.len()
            ),
            path: String::new(),
            notice: "以上是仓库整体状态；实际删除范围以树中勾选的项目为准。".into(),
            rows,
            technical: technical.join("\n\n"),
            can_close_owners: false,
        }
    }

    pub(super) fn locked(path: &str, owners: &[Owner], detail: &str) -> Self {
        let can_close = !owners.is_empty() && owners.iter().all(|owner| !owner.critical);
        let mut rows = Vec::new();
        if owners.is_empty() {
            rows.push(entry(
                "note",
                "未识别占用程序",
                "请手动关闭可能正在使用此文件的应用，再重试或跳过。",
                "",
                1,
            ));
        } else {
            rows.push(entry(
                "caption",
                "占用程序",
                format!("{} 个", owners.len()),
                "",
                0,
            ));
            for owner in owners {
                let name = if owner.name.is_empty() {
                    "未知程序"
                } else {
                    &owner.name
                };
                rows.push(entry(
                    "owner",
                    name,
                    if owner.critical {
                        format!("系统进程 · PID {}", owner.pid)
                    } else {
                        format!("PID {}", owner.pid)
                    },
                    "",
                    i32::from(owner.critical),
                ));
            }
            if !can_close {
                rows.push(entry(
                    "note",
                    "不能自动关闭",
                    "列表中包含系统进程或服务。请手动处理，或跳过此项。",
                    "",
                    1,
                ));
            }
        }
        Self {
            kind: "lock",
            title: "文件无法访问".into(),
            summary: "删除已暂停。请先保存相关应用中的工作。".into(),
            path: path.into(),
            notice: if can_close {
                "请求关闭应用可能影响其打开的其他文件。".into()
            } else {
                String::new()
            },
            rows,
            technical: detail.into(),
            can_close_owners: can_close,
        }
    }

    pub(super) fn error(
        title: &str,
        summary: impl Into<String>,
        errors: &[String],
        warning: &str,
    ) -> Self {
        let rows = errors
            .iter()
            .enumerate()
            .map(|(index, error)| {
                // Drive-letter colons are not separators: only ": " splits the path.
                let (path, detail) = error
                    .split_once(": ")
                    .filter(|(path, _)| path.contains('\\') || path.contains('/'))
                    .unwrap_or(("", error.as_str()));
                entry("issue", format!("{:02}", index + 1), detail, path, 1)
            })
            .collect();
        Self {
            kind: "error",
            title: title.into(),
            summary: summary.into(),
            path: String::new(),
            notice: warning.into(),
            rows,
            technical: String::new(),
            can_close_owners: false,
        }
    }

    pub(super) fn approval_error(error: &str) -> Self {
        Self::error(
            "不能开始删除",
            "安全校验未通过。请检查标记和 Git 风险。",
            &[error.into()],
            "没有开始删除。",
        )
    }

    pub(super) fn partial_outcome(outcome: &Outcome) -> Self {
        Self::error(
            "部分项目未删除",
            format!(
                "已删除 {} 项，失败 {} 项。失败项目仍保留在标记中。",
                outcome.removed, outcome.failed
            ),
            &outcome.errors,
            "已完成的删除无法撤销。",
        )
    }
}

fn additional_git_risk(risk: &str) -> Option<DialogRow> {
    if risk.starts_with("remote refs are CACHED")
        || risk == "no remote configured"
        || risk == "tracked changes/conflicts exist only locally"
        || risk == "untracked worktree entries are not in Git"
        || risk.starts_with("ignored entries are LOCAL-ONLY")
        || risk == "local stashes are not protected by ordinary push"
        || risk.starts_with("local refs/commits/tags are not proven")
    {
        return None;
    }
    let (label, value): (&str, String) = if risk.starts_with("repository operation in progress:") {
        ("仓库操作", "合并或变基等操作尚未结束".into())
    } else if risk.contains("linked worktree(s)") {
        ("关联工作树", "另有工作树的本地状态尚未核实".into())
    } else if risk.contains("submodule(s):") {
        ("子模块", "嵌套仓库需要单独检查".into())
    } else if risk.starts_with("Git metadata is outside this worktree") {
        ("Git 元数据", "位于此工作树之外".into())
    } else if let Some(rest) = risk.strip_prefix("remote ") {
        if let Some((name, _)) = rest.split_once(" unavailable/unverified:") {
            ("远端连接", format!("{name} 无法核实"))
        } else {
            ("远端检查", "状态未知，请查看技术详情".into())
        }
    } else if risk.starts_with("worktree status unknown:") {
        ("工作区", "无法判断本地改动状态".into())
    } else if risk.starts_with("stash status unknown:") {
        ("stash", "无法读取本地记录".into())
    } else if risk.starts_with("unborn or unreadable HEAD") {
        ("当前分支", "HEAD 不可读或仓库尚无提交".into())
    } else if risk.starts_with("Git safety unknown:") || risk.starts_with("Git check failed:") {
        ("Git 检查", "未完成，不能确认远端备份".into())
    } else {
        ("其他风险", "状态未知，请查看技术详情".into())
    };
    Some(entry("fact", label, value, "", 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_dialog_is_structured_and_keeps_raw_diagnostics_separate() {
        let audit = GitAudit {
            root: r"D:\repo".into(), branch: Some("master".into()),
            modified: 38, untracked: 7, ignored: 30, stashes: 1,
            local_only_refs: vec!["branch:local".into()],
            risks: vec!["remote refs are CACHED, not proof of current remote contents; run git --fetch to verify".into()],
            ..Default::default()
        };
        let data = Dialog::git(&[&audit]);
        let labels: Vec<_> = data.rows.iter().map(|r| r.label.to_string()).collect();
        assert!(labels.iter().any(|s| s == "工作区"));
        assert!(labels.iter().any(|s| s == "本地文件"));
        assert!(labels.iter().any(|s| s == "本地记录"));
        assert!(data.technical.contains("remote refs are CACHED"));
        assert!(!data.rows.iter().any(|r| r.value.contains("remote=")));
    }

    #[test]
    fn locked_without_owner_never_offers_shutdown() {
        let data = Dialog::locked(r"C:\long\file", &[], "sharing violation");
        assert!(!data.can_close_owners);
        assert_eq!(data.rows.len(), 1);
        assert_eq!(data.technical, "sharing violation");
    }

    #[test]
    fn remote_failure_has_human_label() {
        let entry =
            additional_git_risk("remote origin unavailable/unverified: connection timed out")
                .unwrap();
        assert_eq!(entry.label.as_str(), "远端连接");
        assert_eq!(entry.value.as_str(), "origin 无法核实");
    }
}
