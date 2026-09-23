# CLI 用法

以下 disk-cleaner.exe 均指 skill 目录的 bin/disk-cleaner.exe；实际调用时使用其绝对路径。命令在当前任务 cwd 中运行，默认计划为 clean-targets.json。

## 查看与扫描

    disk-cleaner.exe doctor --json
    disk-cleaner.exe scan D:/ --backend ntfs --threads 8 --save .disk-cleaner/D.dcscan
    disk-cleaner.exe scan E:/ --backend refs --threads 8 --save .disk-cleaner/E.dcscan
    disk-cleaner.exe scan C:/Users/Example/Downloads --backend fs --threads 8
    disk-cleaner.exe detail D:/Projects --snapshot .disk-cleaner/D.dcscan --depth 2
    disk-cleaner.exe detail D:/Projects/app/target --snapshot .disk-cleaner/D.dcscan --min-size 0 --top 20

- 默认 auto；NTFS/ReFS 严格后端需要管理员权限，CLI 只提示，不自动提权。显式 ntfs/refs 失败不会静默改成 fs。
- NTFS 直接分块读取 MFT，ReFS 原始扫描当前限定 3.14。其他 ReFS 版本不宣称兼容，使用明确的 --backend fs。
- --max-memory-mib 1024 限制索引预算；--buffer-mib 8 限制 MFT 批量读取；--threads 1..64。
- --depth、--top、--min-size、--max-lines 只限制显示，不裁剪完整索引。
- --metric allocated 默认按占用排序；logical 为逻辑长度。硬链接占用在索引内去重，名称仍保留。
- --no-git 只跳过报告注释，绝不能关闭删除安全检查。
- --no-save 用于一次性只读扫描；--json 提供有界结构化报告而不是海量文件全量输出。
- detail 是缓存快照，可能过期；实际删除前 GUI 会重新枚举和验证文件身份。
- 时间列同时显示 LATEST UTC (max) 与 OLDEST UTC (min)，文件夹统计后代文件、文件两者相同。v2 缓存可从保存的逐文件时间自动补算 max，不需要重新扫描；v1 缓存缺失时间，需重新扫描。
- compare LEFT.dcscan RIGHT.dcscan --scope PATH 对照完整子树，而非屏幕截断的行。

## Git

    disk-cleaner.exe git D:/Projects/app --json
    disk-cleaner.exe git D:/Projects/app --fetch --json

all_content_synced=true 才是本次审计没有发现工作区本地数据、且所检查的历史/引用有远端覆盖；它不是“删除绝对安全”的保证，也不备份自定义 .git 配置、hooks、reflog 或外部资源。remote_verified=false 必须保留为未知。

## 标记与用户审阅

    disk-cleaner.exe rm -rf D:/Projects/app/target --reason "可重建的编译产物，保留源代码"
    disk-cleaner.exe rm C:/Users/Example/Downloads/archive.zip --reason "用户确认已解压且不再需要"
    disk-cleaner.exe undo-rm D:/Projects/app/target
    disk-cleaner.exe undo-rm --all
    disk-cleaner.exe show-rm --text
    disk-cleaner.exe show-rm --json
    disk-cleaner.exe show-rm

- -reason 兼容旧例子，推荐 --reason。
- -f 仅忽略不存在的路径，不跳过任何确认；-r 仅允许标记文件夹。
- 不支持通配符、ADS 路径、设备路径、卷根、受保护的 OS 路径，或穿越 junction/symlink 的父目录。
- 默认计划可用全局 --plan PATH 改变。计划有并发锁、schema 和 revision，使用原子替换保存。
- 没有 --yes、execute、force-delete、隐藏的无头删除入口。
- show-rm --fetch 可以在审阅准备阶段核实 remote。agent 只负责打开窗口，所有破坏性决定交给用户。
- 占用处理使用 Restart Manager；关键进程/服务和本程序不会被关闭，无法识别占用者时要求用户手动处理。

## 退出码

- 0：命令成功（rm 的成功只代表标记成功）。
- 1：错误 / 权限不足 / 严格后端不可用。
- 2：扫描有缺失或错误，报告不完整。
- 3：compare 检测到差异。

show-rm 的详细执行结果还写入计划旁的 audit.jsonl。取消和部分失败不是“已全部清理”，必须读取结果。
