#[cfg(not(feature = "gui"))]
use anyhow::bail;
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use disk_cleaner::{
    git_audit,
    model::Snapshot,
    plan, platform,
    report::{self, Metric, ViewOptions},
    scan::{self, Backend, ScanOptions},
};
use std::{ffi::OsString, io::Write, path::PathBuf, time::Instant};
#[derive(Parser)]
#[command(
    name = "disk-cleaner",
    version,
    about = "Fast Windows disk analysis for agents. rm ONLY stages; only the human review window deletes."
)]
struct Cli {
    #[arg(
        long,
        global = true,
        default_value = "clean-targets.json",
        help = "Deletion plan in the current working directory (JSON, never a command script)"
    )]
    plan: PathBuf,
    // Compatibility with earlier examples; only --elevate ever elevates.
    #[arg(long, global = true, hide = true)]
    no_elevate: bool,
    #[arg(
        long,
        global = true,
        help = "Relaunch this command through one Windows UAC prompt (needed for raw NTFS/ReFS scans); never implicit"
    )]
    elevate: bool,
    #[arg(long, global = true, hide = true, value_name = "DIR")]
    elevation_report: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Detect filesystem types, privileges and available volumes without modifying them.
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Render a headless, read-only Fluent UI screenshot with clearly marked example data.
    UiPreview {
        #[arg(long)]
        out: PathBuf,
        #[arg(long,default_value="review",value_parser=["review","git","lock","progress"])]
        state: String,
    },
    /// Scan a volume (fast) or subtree (fs); save the complete, lossless drill-down index.
    Scan(ScanArgs),
    /// Inspect a subtree in a saved snapshot, without rescanning or losing small files.
    Detail {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, default_value = ".disk-cleaner/last.dcscan")]
        snapshot: PathBuf,
        #[command(flatten)]
        view: ViewArgs,
    },
    /// Compare every entry in two scan snapshots, without display truncation.
    Compare {
        left: PathBuf,
        right: PathBuf,
        #[arg(long)]
        scope: PathBuf,
    },
    /// Inspect repository state, ignored/untracked data, every local branch/tag and remote coverage.
    Git {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(
            long,
            help = "Contact remotes and fetch remote-tracking branches before checking coverage"
        )]
        fetch: bool,
        #[arg(long)]
        json: bool,
    },
    /// ONLY mark literal paths in clean-targets.json. -rf does NOT delete anything.
    Rm {
        #[arg(required=true,num_args=1..)]
        paths: Vec<PathBuf>,
        #[arg(short = 'r', long)]
        recursive: bool,
        #[arg(
            short = 'f',
            long,
            help = "Ignore missing targets; never skip review, Git checks or locks"
        )]
        force: bool,
        #[arg(long, default_value = "")]
        reason: String,
        #[arg(long,default_value_t=4,value_parser=clap::value_parser!(u16).range(1..=64))]
        threads: u16,
    },
    /// Cancel marks; cannot restore already-deleted files.
    UndoRm {
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        paths: Vec<PathBuf>,
        #[arg(long)]
        all: bool,
    },
    /// Open the human-only Slint review. --text/--json only read the plan.
    ShowRm {
        #[arg(long)]
        text: bool,
        #[arg(long)]
        json: bool,
        #[arg(long, help = "Verify live Git remotes during review preparation")]
        fetch: bool,
        #[arg(
            long,
            help = "Index the review tree from this scan --save snapshot instead of scanning again"
        )]
        snapshot: Option<PathBuf>,
    },
}
#[derive(Args)]
struct ScanArgs {
    #[arg(default_value = ".")]
    path: PathBuf,
    #[arg(long, value_enum, default_value = "auto")]
    backend: Backend,
    #[arg(long,default_value_t=8,value_parser=clap::value_parser!(u16).range(1..=64))]
    threads: u16,
    #[arg(long,default_value_t=8,value_parser=clap::value_parser!(u16).range(1..=64))]
    buffer_mib: u16,
    #[arg(long,default_value_t=1024,value_parser=clap::value_parser!(u32).range(32..=16384))]
    max_memory_mib: u32,
    #[arg(long, default_value = ".disk-cleaner/last.dcscan")]
    save: PathBuf,
    #[arg(long, help = "Do not persist the index (for benchmarks/one-off reads)")]
    no_save: bool,
    #[command(flatten)]
    view: ViewArgs,
}
#[derive(Args)]
struct ViewArgs {
    #[arg(long,default_value_t=3,value_parser=clap::value_parser!(u16).range(0..=64))]
    depth: u16,
    #[arg(long,default_value_t=8,value_parser=clap::value_parser!(u16).range(1..=1000))]
    top: u16,
    #[arg(long, default_value = "64MiB")]
    min_size: String,
    #[arg(long,default_value_t=80,value_parser=clap::value_parser!(u16).range(16..=2000))]
    max_lines: u16,
    #[arg(long, value_enum, default_value = "allocated")]
    metric: Metric,
    #[arg(
        long,
        help = "Skip Git annotations in this report only; cannot disable deletion safety"
    )]
    no_git: bool,
    #[arg(long)]
    ascii: bool,
    #[arg(
        long,
        help = "Machine-readable bounded view; use snapshot for all entries"
    )]
    json: bool,
}
impl ViewArgs {
    fn options(&self) -> Result<ViewOptions> {
        Ok(ViewOptions {
            depth: self.depth as usize,
            top: self.top as usize,
            min_bytes: report::parse_size(&self.min_size)?,
            max_lines: self.max_lines as usize,
            metric: self.metric,
            git: !self.no_git,
            ascii: self.ascii,
        })
    }
}
fn output_json(value: &impl serde::Serialize) -> Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value)?;
    writeln!(out)?;
    Ok(())
}
fn run(cli: Cli) -> Result<i32> {
    #[cfg(windows)]
    if cli.elevate && cli.elevation_report.is_none() && !platform::elevation::is_elevated() {
        return platform::elevation::relaunch_elevated();
    }
    #[cfg(not(windows))]
    anyhow::ensure!(!cli.elevate, "--elevate is a Windows-only option");
    let command_started = Instant::now();
    if platform::elevation::is_elevated() {
        platform::elevation::enable_backup_privilege()?;
    }
    match cli.command {
        Command::Doctor { json } => {
            let volumes = platform::volumes();
            if json {
                output_json(
                    &serde_json::json!({"version":env!("CARGO_PKG_VERSION"),"administrator":platform::elevation::is_elevated(),"elevation":"--elevate asks Windows for one UAC prompt; nothing else elevates","cwd":std::env::current_dir()?,"volumes":volumes,"deletion":"GUI confirmation only; rm is stage-only"}),
                )?;
            } else {
                println!(
                    "disk-cleaner {} | administrator={} | cwd={}",
                    env!("CARGO_PKG_VERSION"),
                    platform::elevation::is_elevated(),
                    std::env::current_dir()?.display()
                );
                for v in volumes {
                    println!(
                        "{}  {:6}  total={} free={} cluster={}  raw={}",
                        v.root.display(),
                        v.filesystem,
                        report::human(v.total_bytes),
                        report::human(v.free_bytes),
                        v.cluster_bytes,
                        v.device
                    );
                }
                println!(
                    "elevation: raw NTFS/ReFS scans need administrator rights; pass --elevate for one UAC prompt. fs enumeration stays unprivileged."
                );
                println!("rm is STAGE ONLY. No headless/--yes/force-delete command exists.");
            }
        }
        Command::UiPreview { out, state } => {
            #[cfg(feature = "gui")]
            {
                disk_cleaner::gui::preview(&out, &state)?;
                println!(
                    "Read-only UI preview: {}",
                    platform::absolute(&out)?.display()
                );
            }
            #[cfg(not(feature = "gui"))]
            {
                let _ = (out, state);
                bail!("GUI feature is disabled");
            }
        }
        Command::Scan(args) => {
            let options = ScanOptions {
                backend: args.backend,
                threads: args.threads as usize,
                buffer_mib: args.buffer_mib as usize,
                max_memory_mib: args.max_memory_mib as usize,
            };
            let scope = platform::canonical(&args.path)?;
            let snapshot = scan::scan(&scope, &options)?;
            if !args.no_save {
                snapshot.save(&args.save)?;
                eprintln!(
                    "Complete drill-down index: {}",
                    platform::absolute(&args.save)?.display()
                );
            }
            let options = args.view.options()?;
            let mut view = report::view(&snapshot, &scope, &options)?;
            view.report_ready_ms = Some(command_started.elapsed().as_millis() as u64);
            if args.view.json {
                output_json(&view)?;
            } else {
                print!("{}", report::text(&view, &options));
            }
            if !snapshot.stats.complete {
                return Ok(2);
            }
        }
        Command::Detail {
            path,
            snapshot,
            view,
        } => {
            let s = Snapshot::load(&snapshot).context("load complete scan index")?;
            let options = view.options()?;
            let mut v = report::view(&s, &path, &options)?;
            v.report_ready_ms = Some(command_started.elapsed().as_millis() as u64);
            if view.json {
                output_json(&v)?;
            } else {
                print!("{}", report::text(&v, &options));
                println!(
                    "Snapshot captured at Unix {}. Run scan again when freshness matters.",
                    s.stats.started_unix
                );
            }
        }
        Command::Compare { left, right, scope } => {
            let a = Snapshot::load(&left)?;
            let b = Snapshot::load(&right)?;
            let result = disk_cleaner::compare::compare(&a, &b, &scope)?;
            output_json(&result)?;
            if !result.equal {
                return Ok(3);
            }
        }
        Command::Git { path, fetch, json } => {
            let audit = git_audit::inspect(&platform::canonical(&path)?, fetch)?;
            if json {
                output_json(&audit)?;
            } else if let Some(a) = audit {
                println!("{}\n{}", a.root.display(), a.concise());
                println!(
                    "tracked_history_covered={}  all_content_synced={}",
                    a.tracked_history_covered, a.all_content_synced
                );
                for r in a.risks {
                    println!("RISK: {}", report::safe_text(&r));
                }
                for r in a.local_only_refs {
                    println!("LOCAL REF: {}", report::safe_text(&r));
                }
            } else {
                println!("not a Git repository");
            }
        }
        Command::Rm {
            paths,
            recursive,
            force,
            reason,
            threads,
        } => {
            let targets = plan::stage(
                &cli.plan,
                &paths,
                recursive,
                force,
                &reason,
                threads as usize,
            )?;
            for t in &targets {
                println!(
                    "STAGED (NOT DELETED): {} | {} | reason={}",
                    report::safe_text(&platform::display_path(&t.path)),
                    report::human(t.summary.allocated_bytes),
                    report::safe_text(&t.reason)
                );
                if let Some(g) = &t.git {
                    println!("  {}", g.concise());
                }
            }
            println!(
                "{} target(s) marked in {}. No files were deleted. Use show-rm for human review.",
                targets.len(),
                platform::absolute(&cli.plan)?.display()
            );
        }
        Command::UndoRm { paths, all } => {
            let n = plan::undo(&cli.plan, &paths, all)?;
            println!("Cancelled {n} mark(s). No content was deleted or restored.");
        }
        Command::ShowRm {
            text,
            json,
            fetch,
            snapshot,
        } => {
            if text || json {
                let store = plan::Store::open(&cli.plan)?;
                if json {
                    output_json(&store.plan)?;
                } else {
                    println!(
                        "PENDING ONLY | {} | revision={}",
                        store.path.display(),
                        store.plan.revision
                    );
                    for t in &store.plan.targets {
                        println!(
                            "{}  {}  files={}  reason={}",
                            report::human(t.summary.allocated_bytes),
                            report::safe_text(&platform::display_path(&t.path)),
                            t.summary.files,
                            report::safe_text(&t.reason)
                        );
                        if let Some(g) = &t.git {
                            println!("  {}", g.concise());
                        }
                    }
                    println!(
                        "{} targets. This text view cannot delete anything.",
                        store.plan.targets.len()
                    );
                }
            } else {
                #[cfg(feature = "gui")]
                {
                    println!(
                        "Opening human review. The agent must NOT click deletion/close-process confirmations."
                    );
                    disk_cleaner::gui::run(&cli.plan, snapshot.as_deref(), fetch)?;
                }
                #[cfg(not(feature = "gui"))]
                bail!(
                    "This build has no GUI; rebuild with default features. Headless deletion is intentionally unavailable."
                );
            }
        }
    }
    Ok(0)
}
fn main() {
    // Accept the user's requested -reason spelling as a compatibility alias only.
    let args = std::env::args_os().map(|a| {
        if a == "-reason" {
            OsString::from("--reason")
        } else {
            a
        }
    });
    let cli = Cli::parse_from(args);
    // Elevated child: report through files, since it may own no console at all.
    if let Some(report) = cli.elevation_report.clone()
        && let Err(e) = platform::elevation::redirect_output(&report)
    {
        eprintln!("ERROR: {e:#}");
        std::process::exit(1);
    }
    let code = match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ERROR: {e:#}");
            1
        }
    };
    std::process::exit(code);
}
