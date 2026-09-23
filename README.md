# Windows Disk Cleaner

Rust CLI + 轻量 Slint Fluent 清理审阅窗口 + agent skill。
**rm 只标记；实际删除必须由用户在窗口中确认。**

## 构建与运行

需要 Windows、Rust stable（1.92+）与 MSVC C++ 构建工具。

    cargo build --release
    .\target\release\disk-cleaner.exe doctor
    .\target\release\disk-cleaner.exe scan D:/ --backend ntfs
    .\target\release\disk-cleaner.exe scan E:/ --backend refs
    .\target\release\disk-cleaner.exe scan D:/Projects --backend fs
    .\target\release\disk-cleaner.exe detail D:/Projects --snapshot .disk-cleaner/last.dcscan

权限：加 --elevate 时 CLI 通过 Windows UAC 重新启动自身（每次一次弹窗，由用户同意），
等待子进程并把它的输出原样回传；不加则保持当前权限，严格后端直接失败而不静默回退 fs。
不运行 gsudo、不配置常驻提权或凭据缓存。

默认 8 线程、8 MiB MFT 批次、1024 MiB 索引预算。完整 UTF-16 索引保存为带校验的
.dcscan；top/depth/min-size/max-lines 只裁剪显示，不损失下钻精度。

## 安全清理

    .\target\release\disk-cleaner.exe rm -rf D:/Projects/app/target --reason "可重建的编译产物"
    .\target\release\disk-cleaner.exe show-rm --text
    .\target\release\disk-cleaner.exe undo-rm D:/Projects/app/target
    .\target\release\disk-cleaner.exe show-rm

- 同盘目标合并为盘符根下的真实文件树，共享祖先合并；可展开、折叠、分页、全选/半选。
- 每层显示待删大小、已选/总文件数；盘符和中间分组节点本身不会删除。
- 未选子项和半选父目录保留。没有无头删除、--yes 或 force-delete。
- 审阅树来自快速索引（提权时的原始 NTFS/ReFS 卷索引，或一次目录遍历），不含任何哈希。
- 每个勾选对象在删除前重新打开防替换句柄（不共享写/删除），核对类型/大小/修改时间；变化过的对象跳过并报告。
- 标记文件 clean-targets.json 只保存路径、理由、标记时间、对象身份与大小汇总；重解析点不递归跟随。
- git2 检查工作树、所有本地分支/标签、stash、忽略项和未跟踪项；缓存 remote 不是远端证明。
- Git 本地/未知风险由用户二次确认；占用使用 Restart Manager，用户单独决定是否关闭应用。
- 关键服务/进程不会关闭；强制关闭需额外勾选。实时进度可停止，已删除内容不能恢复。
- 永久删除不入回收站，audit.jsonl 记录执行结果。agent 不允许操作破坏性确认按钮。

## 报告时间

LATEST UTC (max) 是主要列，OLDEST UTC (min) 同时保留。
文件两列都是自身最后写入时间；文件夹/折叠行统计后代文件的最大值/最小值。
不混入目录本身的 mtime；空目录 —，不完整值 ?。判断目录最近更新看 max，不能用 min
证明整个目录长期未更新。v2 缓存可以从逐文件时间补算 max；新缓存为 v3。

“扫描/汇总”只计扫描和树汇总；“报告就绪”另含索引 I/O 和 Git 注释，不含最终格式化
及终端输出。detail 的扫描耗时来自历史快照，报告就绪是本次查询耗时。

## 后端与限制

- NTFS：只读分块 MFT、多线程解析，处理 USA、运行段、扩展记录、硬链接、稀疏/压缩、ADS。
- ReFS：读取 superblock/checkpoint/容器表/对象表/目录 B+tree 并逐页校验。不用失效的
  FSCTL_ENUM_USN_DATA；复杂 ADS/短记录用精确路径补充元数据，不用 fs 枚举发现名称。
- 当前 ReFS 实测范围为 3.14 / 4 KiB cluster / CRC64。其他布局明确拒绝，不能夸称兼容。
- fs：有界多线程普通枚举，不跟随重解析点；读取错误会使 complete=false。
- 原始扫描读整卷元数据，小子目录的 fs 可能更快。速度受缓存/记录数/杀毒/存储影响。
- 在线卷不是冻结的 VSS 快照；分配空间不等于释放量（硬链接/克隆块/元数据）。

## 打包、发布与安装 skill

    node scripts/package-skill.mjs     # dist/windows-disk-cleaner/：skill 源码 + Release 程序 + 许可
    node scripts/archive-skill.mjs     # dist/windows-disk-cleaner-skill.zip + dist/SHA256SUMS.txt
    node scripts/install-skill.mjs     # 安装到本机 skill 目录（默认 ~/.agents/skills，--dest 可改）

审阅可直接复用索引，不必重复扫描：

    .\target\release\disk-cleaner.exe show-rm --snapshot .disk-cleaner/D.dcscan

install-skill 只覆盖目标 skill 目录本身，不动其他 skill 或全局配置；目标已存在时需显式 --force。

只读 UI 预览，没有删除回调：

    .\target\release\disk-cleaner.exe ui-preview --out dist/review.png

push 形如 v0.1.0 的 tag 后，.github/workflows/release.yml 在 windows-latest 上构建、打包，
并把 skill 包与校验和作为 GitHub Release 附件发布；ci.yml 另跑 cargo fmt --check、
cargo clippy -D warnings 与 prettier --check。详细第三方信息见 THIRD_PARTY_NOTICES.md。
