# 0.2 大镜像测试 / Large-image test guide

## 中文

0.2.0 仍为待验证版本。合成测试通过不代表对真实 GB/TB 受损镜像有已知恢复率、速度或内存上限。此前 0.1 源码快照不是最终发布。不要在唯一原件上做首测。

1. 使用干净的 Windows 测试环境，保持安全软件开启。保存完整源副本及既有校验记录；不要仅为启动诊断额外进行 TB 级全盘哈希。使用稳定本地存储，防止同步软件、备份任务或虚拟机同时改写源文件。
2. 保留 VHDX/AVHDX、父盘及快照的原目录关系和所有文件。遇到差分链或活动日志，停止该模式测试；不要合并、修复、挂载来宾卷、启动虚拟机或执行来宾文件。本工具不处理差分链/日志回放。
3. 为报告、元数据工作区和最终导出准备另一块健康磁盘，确认空间、权限、电源与连接稳定。扫描工作区可能包含暂存载荷；它不是零占用的预览。禁止输出到源盘或源镜像内部。
4. 先运行 README 中的 `diagnose_recovery_source.py SOURCE --report NEW.json`。报告父目录须存在，新报告不能覆盖旧文件。诊断只读关键元数据，不全盘哈希或扫描载荷。`validated_metadata_only` 不代表文件内容完整；`critical_metadata_unavailable` 等状态说明无法可靠建立映射，不应强行当作正常 VHDX 提取。
首次诊断和扫描保持部分 BAT 高级开关关闭。若明确选择 `--allow-partial-bat`，另建任务；它仅保留可独立验证的映射，不绕过关键元数据、日志或差分链限制。记录 `partial_bat` / `logical_mapping_complete`，不要将部分映射当作完整恢复。

5. 再用 `recover_vhdx_files.py ... --metadata-only --max-records 10000` 做小规模一次性盘点。仅在支持的几何/容器条件下继续。这里的 metadata-only 不是断点恢复会话；独立 `revivex_scan_session.py` 会话核心已通过合成回归测试，续扫需相同源/选项和新输出目录；桌面“打开已有任务”/“继续索引扫描”也有集成测试，但仍需真实镜像验证。
6. 先做小范围提取：如单文件 1 GiB、总输出 4 GiB、最多 10000 条记录；逐步增加，不要默认无限制。记录磁盘读写量、实际进程内存、开始/结束时间及每次限制，避免把达到限制解读为“所有文件已找完”。
7. 在 UI 的“VHDX · 逻辑 NTFS 文件”与原始字节“NTFS · 驻留文件流”之间明确区分。逻辑路径有校验依据；原始驻留/雕刻路径可能只是推断或未知。异常、不可读、未支持及部分结果都应保留在报告中。
8. 在结果页选择少量文件导出到新目录，核对报告、长度和可用校验和。保持恢复文件隔离，切勿执行脚本/程序/宏。正确复制或结构有效不能证明内容与加密前原件一致。
9. 保存版本、构建 commit、系统版本、物理/逻辑大小、诊断状态、资源上限、计数和去敏错误文本。不要把整个镜像、私钥、原始路径报告或受害者文件上传到公开 issue。

退出码或“finished”仅表示某个过程结束。整体原始完整性保持 unknown；不能用“成功数÷看到的候选数”声称全盘恢复率。源状态变化、活动日志、差分链、关键映射缺失、未支持 NTFS 几何或输出空间不足均应停止相应测试，并保留报告与原件。

## English

0.2.0 remains a validation build. Synthetic tests do not establish real-world GB/TB recovery rates, throughput or peak memory. The earlier 0.1 source snapshot is not a final release. Never make the first test on the only original.

1. Use a clean Windows environment with security software enabled. Preserve complete source copies and existing hash records; do not add a whole-TB hashing pass just to start diagnostics. Use stable local storage and prevent sync, backup or VM processes from modifying the source.
2. Preserve all VHDX/AVHDX parents and snapshots with their original relationships. Stop this mode on differencing chains or active logs. Do not merge, repair, mount guest volumes, boot the VM or execute guest files. This tool does not replay logs or merge chains.
3. Put reports, metadata workspaces and exports on healthy separate storage with adequate space and stable power/connections. Scan workspaces may contain staged payloads; they are not zero-storage previews. Never write outputs to affected storage or into the source image.
4. Start with `diagnose_recovery_source.py SOURCE --report NEW.json` as shown in README. The parent folder must exist and the report must be new. This reads key metadata without a full-image hash or payload scan. `validated_metadata_only` does not prove content completeness; states such as `critical_metadata_unavailable` mean reliable mapping is unavailable.
Keep partial-BAT mode off for the first diagnostic/scan. If explicitly selecting `--allow-partial-bat`, use a separate task. It preserves only independently validated mappings and does not bypass critical metadata, active-log or differencing-chain checks. Record `partial_bat` / `logical_mapping_complete`; partial mapping is not complete recovery.

5. Use `recover_vhdx_files.py ... --metadata-only --max-records 10000` for a small one-shot inventory. Proceed only with supported geometry/container states. This option is not a resumable session; the separate `revivex_scan_session.py` session core has synthetic regression coverage and requires the same source/options plus a new output directory for resume; desktop Open workspace / Continue scan also have integration tests, but still require real-image validation.
6. Begin with bounded extraction: for example 1 GiB per file, 4 GiB total and 10000 records. Increase gradually. Record I/O, actual process memory, elapsed time and limits. Reaching a cap does not mean every original file was found.
7. Distinguish “VHDX · Logical NTFS files” from the raw “NTFS · Resident file streams” mode. Logical paths have validated metadata evidence; raw/carved paths may be inferred or unknown. Keep unsupported, unreadable and partial results visible.
8. Select a few files and export to a new directory. Compare reports, lengths and available checksums. Keep files isolated; do not execute recovered programs, scripts or macros. Correct copying or valid structure does not prove pre-encryption authenticity.
9. Retain version/build commit, OS, physical/logical sizes, diagnostic states, resource limits, counts and redacted error text. Never publish full images, keys, unredacted path reports or victim files in issues.

An exit code or “finished” only describes a process outcome. Aggregate original-content completeness remains unknown. “Successful candidates / visible candidates” is not a whole-disk recovery rate. Stop the relevant test on source changes, active logs, differencing chains, missing critical mappings, unsupported NTFS geometry or insufficient output space; preserve the report and original.
