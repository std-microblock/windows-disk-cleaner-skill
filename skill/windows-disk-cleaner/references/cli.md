# CLI 用法

以下 disk-cleaner.exe 均指 skill 目录的 bin/disk-cleaner.exe；实际调用时使用其绝对路径。命令在当前任务 cwd 中运行，默认计划为 clean-targets.json。

## 查看与扫描

    disk-cleaner.exe doctor --json
    disk-cleaner.exe scan D:/ --backend ntfs --threads 8 --elevate --save .disk-cleaner/D.dcscan
    disk-cleaner.exe scan E:/ --backend refs --threads 8 --elevate --save .disk-cleaner/E.dcscan
    disk-cleaner.exe scan C:/Users/Example/Downloads --backend fs --threads 8
    disk-cleaner.exe detail D:/Projects --snapshot .disk-cleaner/D.dcscan --depth 2
    disk-cleaner.exe detail D:/Projects/app/target --snapshot .disk-cleaner/D.dcscan --min-size 0 --top 20

- 默认 auto；NTFS/ReFS 严格后端需要管理员权限。加 --elevate 时 CLI 通过 Windows UAC 重新启动自身（一次弹窗），把子进程的 stdout/stderr 实时回传到当前流，并沿用子进程的退出码；输出走命名管道，连不上时退回临时文件，调用方会被明确告知。提权后的进程看不到映射的网络驱动器，因此工作目录必须能被提权进程访问（相对路径的 --plan/--save 依赖当前目录，失败会直接报错）。不加 --elevate 时严格后端直接失败并提示，绝不静默改成 fs。
- NTFS 直接分块读取 MFT，ReFS 原始扫描当前限定 3.14。其他 ReFS 版本不宣称兼容，使用明确的 --backend fs。
- --max-memory-mib 1024 限制索引预算；--buffer-mib 8 限制 MFT 批量读取；--threads 1..64。
- --depth、--top、--min-size、--max-lines 只限制显示，不裁剪完整索引。
- --metric allocated 默认按占用排序；logical 为逻辑长度。硬链接占用在索引内去重，名称仍保留。
- --no-git 只跳过报告注释，绝不能关闭删除安全检查。
- --no-save 用于一次性只读扫描；--json 提供有界结构化报告而不是海量文件全量输出。
- detail 是缓存快照，可能过期；审阅窗口用 --snapshot 复用已有索引时同样可能过期。
- show-rm 索引顺序：显式 --snapshot → 当前任务 `.disk-cleaner/last.dcscan`（完整且覆盖全部标记时自动复用）→ 卷原始索引（NTFS/ReFS，按卷缓存，同一窗口内多个目标只读一次）→ 只有显式 --index fs 时才走目录枚举。
- show-rm 默认自动提权：需要读卷原始元数据时会自己弹一次 UAC（agent 不需要额外加 --elevate，也不要点 UAC 按钮）。复用快照或用 --index fs 则不请求提权。
- 审阅树不含哈希；实际删除前对每个勾选对象重新打开防替换句柄，核对类型/大小/修改时间，变化过的对象跳过并报告。
- 时间列同时显示 LATEST UTC (max) 与 OLDEST UTC (min)，文件夹统计后代文件、文件两者相同。v2 缓存可从保存的逐文件时间自动补算 max，不需要重新扫描；v1 缓存缺失时间，需重新扫描。
- compare LEFT.dcscan RIGHT.dcscan --scope PATH 对照完整子树，而非屏幕截断的行。

## Git

    disk-cleaner.exe git D:/Projects/app --json
    disk-cleaner.exe git D:/Projects/app --fetch --json

all_content_synced=true 才是本次审计没有发现工作区本地数据、且所检查的历史/引用有远端覆盖；它不是“删除绝对安全”的保证，也不备份自定义 .git 配置、hooks、reflog 或外部资源。remote_verified=false 必须保留为未知。

## 标记与用户审阅

以下 rm 命令只是示例；应先核查目标并取得用户对具体路径的明确同意，不得直接照搬示例理由。

    disk-cleaner.exe rm -rf D:/Projects/app/target --reason "可重建的编译产物，保留源代码"
    disk-cleaner.exe rm C:/Users/Example/Downloads/archive.zip --reason "用户确认已解压且不再需要"
    disk-cleaner.exe rm -rf D:/Cache/junk --reason "用户确认只清理此应用的可重建缓存" --warn "删除后需重新下载；用户确认不依赖离线缓存"
    disk-cleaner.exe rm -rf D:/Data/models --reason "核查服务引用和备份后，用户确认该模型存储不再需要" --critical "模型及可能的本地数据将永久删除；已与用户确认具体范围"
    disk-cleaner.exe undo-rm D:/Projects/app/target
    disk-cleaner.exe undo-rm --all
    disk-cleaner.exe show-rm --text
    disk-cleaner.exe show-rm --json
    disk-cleaner.exe show-rm
    disk-cleaner.exe show-rm --snapshot .disk-cleaner/D.dcscan
    disk-cleaner.exe show-rm --index fs

- `--warn TEXT` / `--critical TEXT` 可重复，附加到本次 rm 标记的目标；只做提示和高亮，不阻止删除，也不算用户确认。
- 未指明对象或只指定宽泛类别时，先问清具体范围（见 SKILL.md）；不确定能否删除的对象，先问用户再标记。没有明确答复就不要标记，也不要把猜测写进 reason 当结论；`--critical` 也不能代替同意。
- -reason 兼容旧例子，推荐 --reason。
- -f 仅忽略不存在的路径，不跳过任何确认；-r 仅允许标记文件夹。
- 不支持通配符、ADS 路径、设备路径、卷根、受保护的 OS 路径，或穿越 junction/symlink 的父目录。
- 默认计划可用全局 --plan PATH 改变。计划有并发锁、schema 和 revision，使用原子替换保存。
- 没有 --yes、execute、force-delete、隐藏的无头删除入口。
- show-rm 在文件树里高亮 rm 的 warn/critical 提示：行内“注意 / 严重”标记 + 底色，选中行下方显示摘要，可展开查看全文；不弹窗，也不阻止删除。
- show-rm --text 用 `!!` / `!` 前缀与 `CRITICAL:` / `WARN:` 行标出提示；show-rm --json 在 `targets[].alerts` 中保留原文（`level` 为 warn 或 critical）。
- 分组目录的灰色图标与实际标记目录的金色图标不同；分组复选框仍批量选择其下已标记目标。右键分组可经范围确认后升级为整个目录的标记，然后必须重新审阅、勾选。
- 所有目标成功处理且标记计划清空后，自动删除计划目录内未被替换的 `.dcscan`；取消、失败、保留标记或外部快照都不会自动清理。
- show-rm --fetch 可以在审阅准备阶段核实 remote。agent 只负责打开窗口，所有破坏性决定交给用户。
- 占用处理使用 Restart Manager；关键进程/服务和本程序不会被关闭，无法识别占用者时要求用户手动处理。

## 退出码

- 0：命令成功（rm 的成功只代表标记成功）。
- 1：错误 / 权限不足 / 严格后端不可用。
- 2：扫描有缺失或错误，报告不完整。
- 3：compare 检测到差异。

show-rm 的详细执行结果还写入计划旁的 audit.jsonl。取消和部分失败不是“已全部清理”，必须读取结果。
