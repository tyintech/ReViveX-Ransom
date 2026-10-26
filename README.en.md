# ReViveX Ransom

[中文](README.md) · [Author website](https://www.xtyue.com/) · [Releases](https://github.com/tyintech/ReViveX-Ransom/releases)

Open-source damaged-file analysis and verifiable data salvage. Author: **陈涛 alan chen**. Contact: **1315333@qq.com**.

**0.2.0 is awaiting validation, not a completed production release. The earlier 0.1 source snapshot is not the final release.** The desktop UI offers Chinese/English and light/dark appearance. Windows assets require frozen-app and install/uninstall checks; run from source if assets are unavailable. Real-world GB/TB throughput, peak memory and recovery rates remain unverified.

Start with the [large-image test guide](build/TESTING-0.2.md) and metadata-only diagnostics before reading payloads.

## Automatic recovery (recommended)

“Automatic recovery (recommended)” is the first and default recovery method. Choose the source and where recovered files are saved; optionally pick a **fast temporary folder** (for example an SSD on drive C) for intermediate data, then click “Start automatic recovery”.

The source is diagnosed read-only and a route is chosen automatically:

| Diagnosis | Route |
| --- | --- |
| VHDX header, region table and BAT (block map) validate | Logical NTFS metadata index (as “VHDX · Logical NTFS files”) |
| Mapping destroyed or encrypted, but a sample probe finds plaintext NTFS metadata | **Rebuild the block map** and recover files under their original names and folders |
| Neither | Raw signature carving (ZIP / NTFS resident / PNG / SQLite; original names unknown) |

The rebuild route has 11 stages; the window shows “Stage i/11 · name”, byte or item progress and counts:

1. **Read-only diagnosis**: header signatures, Gentlemen footer, inferred encryption ranges; no full-image hash.
2. **Sample probe**: bounded samples from plaintext areas decide whether FILE/INDX records survived (about a minute).
3. **Evidence scan**: one sequential pass keeps only FILE records, INDX blocks, file-start signatures, all-zero MiBs, NTFS boot sectors and VHDX metadata tables. A checkpoint every 30 s; after an interruption the evidence is truncated back to the checkpoint, so nothing is duplicated. Inferred encrypted ranges are scanned last, never skipped.
4. **Evidence index**: evidence parsed into SQLite from the evidence folder only; the source is not read again.
5. **Rebuild block map**: cluster size, block size and each volume's partition offset are inferred from evidence (exact INDX anchors plus file-header hits); nothing has to be typed in, and the reasoning is written to the report. Smaller is preferred over larger: a larger block size is used only with several independent supporting blocks and no contradicting evidence.
6. **Volume membership**: a bimodal file-header match ratio per MFT fragment separates the volume's own records from records inside disk-image files (.vhdx/.img/.bak…) stored on it; those never leak into results.
7. **Match missing blocks**: only byte-exact evidence is used (ZIP member CRCs, PNG chunk CRCs, PDF object offsets, several file headers). A candidate is accepted only when **all evidence matches and it is the only one**; ties are rejected. The rules are first tested on already-known blocks; one wrong pick there disables matching for the run. Candidate slots are read once in physical order (no random reads).
8. **Extract named files**: only files whose every block has trusted evidence are written. A parent folder is used only when its sequence number matches and it is a directory; otherwise the file goes under `_上级目录名丢失_<record>` (“parent folder name lost”). Small resident files come straight from evidence and are written first. Files are created exclusively and never overwritten.
9. **Grade results**: usable / needs review / suspect damaged. JPEG entropy data is scanned (not only header and end marker); PNG, PDF, ZIP/Office, OLE, TIFF, SQLite, PE, MP4, GIF and text are checked too.
10. **Organize results**: files are moved to `最终结果\可用|待确认|疑似损坏|缩略图缓存\<volume>\<original path>` (usable | needs review | suspect damaged | thumbnail caches). Moves only, nothing is deleted; every move is logged in `最终结果\_整理记录.tsv` and `revivex_organize.py --undo` reverses them all.
11. **Summary**: `清单.jsonl` (original path, output, size, SHA-256 and grade per file), `未恢复清单.jsonl` (files not written and why), `auto_manifest.json` and `结果说明.txt`.

- **Deleted files**: the rebuild route also recovers files NTFS marks as deleted whose data clusters are not owned by any existing file. They go to `最终结果\已删除文件\<可用|待确认|疑似损坏|缩略图缓存>\<volume>\<original path>` (“deleted files”), apart from live files and never overwriting them. Deleted files whose clusters now belong to another file are listed in `未恢复清单.jsonl` (reason `deleted_clusters_reused_by_existing_file`). Free clusters may still have been overwritten and freed again, so deleted files are graded too; “usable” means structurally intact only. `--skip-deleted` turns this off.
- **Lost files**: when files are “lost” because the image header or block map was destroyed or encrypted, they are recovered by name as long as NTFS metadata is still plaintext (rebuild route). Plain disk images (.img/.dd, not VHDX) with NTFS metadata take the rebuild route too, including deleted files. An intact VHDX is indexed logically by default, without deleted files; add `--route rebuild` on the command line to recover its deleted files.
- **Cancel and continue**: “Cancel safely” works at any time. Open the task in “Results & verification” and click “Continue run” (or run the command line again on the same output folder): finished stages are not repeated and the long evidence scan is not re-read. Source and scan options must be the same.
- **Temporary folder**: evidence, indexes and the block map go there; recovered files always go to the output disk. Its size depends on the number of MFT/INDX records; the run stops with its checkpoint kept when free space falls below the reserve. Without one, `_work` inside the task folder is used.
- **Resource limits**: the per-file/total-output limits in the window apply to raw carving only; the rebuild route is bounded by free space on the output disk (4 GiB reserve by default).
- **Memory**: the rebuild route keeps every captured MFT record and directory entry in memory, growing with the record count; use a machine with ample RAM for sources with millions of files.
- **Results page**: listings are streamed line by line, so millions of records are never loaded at once. Filter by usable / needs review / suspect damaged / thumbnail cache / not recovered; selected files are re-hashed on export.

This is still not decryption: data and MFT records inside encrypted ranges cannot be recovered by name, and grades describe structure only, not authenticity or safety.

## Desktop workflow

1. **macOS (Apple silicon)**: download `macos-arm64.zip` from Releases, unzip it and open `ReViveX-Ransom.app`. It is not signed or notarized by Apple; if macOS says the developer cannot be verified, open System Settings > Privacy & Security and click “Open Anyway” (a note is included in the zip). **Windows**: download `windows-x64-setup.exe` for per-user installation, or extract the complete `portable.zip` and run its `ReViveX-Ransom.exe`. The portable launcher requires the accompanying `_internal` directory. The installer is unsigned and does not need administrator rights.
2. In “Recover files”, choose a source copy, method (default “Automatic recovery (recommended)”, see above) and workspace on healthy separate storage. “VHDX · Logical NTFS files” indexes metadata without pre-extracting all payloads; selected files are read from the unchanged source during export. Other recovery modes such as ZIP, carving and raw resident salvage stage payloads first. Every mode can write reports/indexes, so allow free space.
3. In “Results & verification”, browse Folders, File types or All files and apply search/status filters. Selection is shared across views. “Select all available” covers the whole task; “Select filtered” selects matching exportable records. Neither is limited to the visible page. Failed/unsupported records remain visible but are not exportable.
4. Use “Export selected” and choose a new destination. Only selected exportable files are extracted/copied; inspect the separate Export report. Scan, record and export outcomes are distinct. Workspaces are retained, not automatically deleted.
5. “Open workspace” reopens a persistent task. For interrupted, resumable logical-metadata sessions, “Continue scan” validates source/options then continues from checkpoints into a new task, preserving the old session. This is not general resume for every recovery mode.
6. Inspect Run summary, Record details and Export report. “Verify output” checks supported reports/files only. Passing checks does not establish original-content authenticity, completeness or safety; the original total file count remains unknown.

ZIP paths stored in the archive can be preserved. Logical NTFS mode validates directory records/references and preserves verifiable paths, including empty directories. Raw resident-scan parent relationships remain explicitly labeled inference, with missing/conflicting evidence left uncertain. Carving cannot recover original names or directories. A browse tree is not proof of complete original-tree recovery.

## Current features

- ZIP: salvage intact Stored/Deflate members from local headers, checking length and CRC32, with support for selected data descriptors and ZIP64 metadata. Damaged entries are reported; this does not guarantee repair of the entire archive.
- PNG / SQLite: locate candidates and validate structure, checksums or database integrity, with per-file, total-output and decompression limits.
- “VHDX · Logical NTFS files”: read-only fixed/dynamic VHDX mapping with header/region CRC32C, BAT and bounds checks; supported resident/nonresident streams and fragmented base-record MFT/data runlists; validated folder paths and empty directories. Backup boot-sector/MFT-mirror fallbacks have synthetic tests. These checks do not prove payloads are intact or unencrypted.
- “NTFS · Resident file streams”: raw FILE-record salvage for resident data only; no complete logical mapping or nonresident extraction.
- “VHDX · Structure probe”: shallow signature/header evidence, distinct from the strict VHDX reader.
- Lightweight diagnostic CLI: `diagnose_recovery_source.py` reads key metadata without full-image hashing or payload scanning, reports mapping availability and unknown completeness. Possible ransomware regions remain hypotheses. This report excludes source paths, disk IDs and key material; other recovery reports may contain sensitive names/paths.
- Known-plaintext comparison: compare explicitly supplied original/encrypted file pairs and inspect Gentlemen-style footers and inferred encryption ranges. Ordinary ZIP/NTFS salvage does not require originals; this comparison feature does.
- Experimental inner-ZIP salvage: bounded prefix/suffix recovery attempts in a damaged Deflate stream for an explicitly named outer member. Results require manual review.
- Verification: JSON records and revalidation of supported output formats. A structurally valid file is not necessarily complete, trustworthy or free of malware.

Current improvements include an active-span ZIP index and optional memory mapping, same-name/case-collision protection with separate `--preserve-duplicates` output, PNG palette-index checks, streaming JSONL candidate/NTFS record indexes, and preservation of original Unicode NTFS names in records.

### 0.2 capability boundaries

| Area | Current status |
| --- | --- |
| Fixed/dynamic VHDX, CRC/BAT and bounds checks | Implemented with synthetic tests; not exhaustive conformance or payload-authenticity proof |
| NTFS geometry | 512-byte NTFS sectors and 1024-byte FILE records only; VHDX-reader 4096-byte geometry support does not imply 4K-sector NTFS recovery |
| Supported nonresident streams, fragmented base-record runlists, boot/MFT-mirror fallback | Implemented with synthetic tests; extension-record chains excluded |
| Sparse/uninitialized data | Explicit metadata-defined zero ranges; allocation bounds, empty files and backup fallbacks have synthetic regression tests; unreadable ranges are not guessed as zeros |
| Disk-backed metadata sessions, CLI resume and selected lazy export | Core and desktop/workspace tests cover interruption/crash/WAL/identity checks; not general resume for every mode |
| Destroyed VHDX mapping with plaintext guest NTFS (automatic-recovery rebuild route) | Implemented with a synthetic end-to-end test (header/region table/BAT/metadata destroyed, out-of-order blocks, two volumes, an embedded disk image, record-number reuse); the field recovery used prototype scripts, and this version has not yet been re-run on a real TB-scale source |
| Active VHDX logs, differencing VHDX/AVHDX parent chains | Rejected; no log replay or chain merging |
| Deleted files (NTFS records marked deleted) | Automatic-recovery rebuild route: recovered into “已删除文件” when no existing file owns their clusters; synthetic tests cover free clusters, reused clusters and resident files. Other methods such as “VHDX · Logical NTFS files” do not recover deleted files. Content may still have been overwritten |
| NTFS ATTRIBUTE_LIST/extensions, compression, EFS, reparse points | The rebuild route merges $DATA runs from extension records and skips files whose extension record is missing; compression, EFS and reparse points are not implemented; skipped results are not successes |
| PDF, JPEG, general database recovery | Name-less carving covers PNG/SQLite only; the rebuild route recovers any type by name and grades JPEG/PNG/PDF/ZIP/OLE/TIFF/SQLite/PE/MP4/GIF/text structure |
| Original total file count, complete recovery rate, bootable VM, complete original tree | Not guaranteed; aggregate completeness remains unknown and carved original names/paths are unknown |

Implementation references: [Microsoft MS-VHDX](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/83e061f8-f6e2-4de1-91bd-5d518a43d477), [Dissect NTFS attribute API](https://docs.dissect.tools/en/latest/api/dissect/ntfs/attr/index.html), [MFT API](https://docs.dissect.tools/en/latest/api/dissect/ntfs/mft/index.html). These describe formats/parser APIs; they do not certify this implementation or its recovery results.

## Advanced partial-BAT mode (off by default)

Strict mapping remains the default. For VHDX only, select “Try partial BAT mappings (advanced)” in “VHDX · Logical NTFS files”, or add `--allow-partial-bat` to `recover_vhdx_files.py` / `revivex_scan_session.py`. Independent regression tests cover this mode. It retains only independently validated BAT mappings; invalid, conflicting and unknown ranges remain unreadable, without guessed positions or zero filling.

Critical header/region/metadata validation is unchanged; active logs and differencing chains remain rejected. Raw sources reject this flag. Reports expose `partial_bat` and `logical_mapping_complete`; sessions may end `finished_with_errors`, while content completeness remains unknown. Resume requires the same flag. Keep it off for the first test; review strict-mode failures before trying a separate advanced-mode task.

## Metadata-session CLI (0.2)

Unlike the older one-shot `--metadata-only` inventory, `revivex_scan_session.py` stores progress/candidate metadata in SQLite on healthy destination storage without first extracting all payloads:

```powershell
.venv\Scripts\python src\revivex_scan_session.py "C:\Evidence\disk.vhdx" "E:\Recovered\session-new" --source-format vhdx --max-records 10000
.venv\Scripts\python src\revivex_scan_session.py "C:\Evidence\disk.vhdx" "E:\Recovered\session-resumed-new" --source-format vhdx --max-records 10000 --resume-session "E:\Recovered\session-new\session.sqlite"
```

Resume continues an unfinished session without bypassing its original `--max-records` cap; use a new session to raise that cap. Resume requires the same source, exactly the same options and a new output directory. Source stat/container/NTFS/MFT metadata are checked before SQLite backup copies the prior session, preserving the old workspace. **This is not a full-source content hash** and cannot prove every payload byte is unchanged. Do not manually copy just a live `.sqlite` file while omitting its WAL; retain the complete workspace and use the supported resume entry point.

Core tests cover interruption/resume, crash rollback, WAL-safe copying, source/options drift rejection and lazy selected export. One synthetic 1 TiB logical VHDX with a 512 GiB candidate required less than 128 KiB logical reads and less than 16 MiB peak Python allocations. This demonstrates bounded metadata work for that fixture, not real-image speed, whole-process memory or recovery rate. Desktop reopening, checkpoint continuation and lazy-export integration also have regression coverage; clean-Windows and real-image validation are still required.

## Limits and precautions

This is not a universal ransomware decryptor. Known plaintext does not reveal an X25519 private key. There is no guaranteed recovery rate, content completeness or bootable-VM result. Recovery does not require executing malware, uploading evidence, scanning every drive automatically or requesting administrator privileges.

1. Preserve originals and stop writing to affected storage. Work on copies or read-only images.
2. Select a new output folder on healthy separate storage with enough free space.
3. Isolate untrusted files. Do not execute recovered programs, scripts or macros.
4. Test a small sample and inspect JSON reports. Limits, skips, corruption and failures are not successes.
5. Windows builds are unsigned. Do not disable antivirus or bypass system security warnings to run them.

## Run from source (Python 3.10+)

Windows PowerShell, from the repository root:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python src\revivex_desktop.py
.venv\Scripts\python src\salvage_zip.py "C:\Evidence\damaged.zip" "E:\Recovered\zip-new" --memory-map
.venv\Scripts\python src\carve_verified_formats.py "C:\Evidence\image.bin" "E:\Recovered\formats-new"
.venv\Scripts\python src\probe_vhdx.py "C:\Evidence\disk.vhdx" --report "E:\Recovered\probe-new.json"
.venv\Scripts\python src\recover_vhdx_resident.py "C:\Evidence\disk.vhdx" "E:\Recovered\resident-new"
.venv\Scripts\python src\verify_vhdx_recovery.py "E:\Recovered\resident-new"
```

0.2 lightweight diagnostics and bounded logical recovery (create the report parent folder first; extraction outputs must be new):

```powershell
.venv\Scripts\python src\diagnose_recovery_source.py "C:\Evidence\disk.vhdx" --report "E:\Reports\diagnostic-new.json"
.venv\Scripts\python src\recover_vhdx_files.py "C:\Evidence\disk.vhdx" "E:\Recovered\metadata-new" --source-format vhdx --metadata-only --max-records 10000
.venv\Scripts\python src\recover_vhdx_files.py "C:\Evidence\disk.vhdx" "E:\Recovered\logical-new" --source-format vhdx --max-records 10000 --max-file-bytes 1073741824 --max-total-bytes 4294967296
```

The desktop entry also supports pre-Qt `revivex_desktop.py --diagnose SOURCE --report NEW.json`; frozen builds accept `ReViveX-Ransom.exe --diagnose SOURCE --report NEW.json`. Use the report file as the output. Diagnostic exit code 2 means mapping is unavailable or unvalidated, not successful recovery; inspect the JSON. `--metadata-only` here is a one-shot inventory, not a verified resumable session. The export example caps each file at 1 GiB and total payloads at 4 GiB. Reaching limits does not mean there are no more files. Do not begin with an unbounded whole-TB extraction.

The drive letters are examples, not program defaults. On Linux/macOS, create a venv with `python3 -m venv .venv`, use `.venv/bin/python`, and substitute actual paths. NTFS parsing does not require mounting or modifying the source image.

Automatic recovery from the command line (same flow as the window). The output folder must be new, or a previous automatic-recovery folder, which is then continued from its checkpoints:

```powershell
.venv\Scripts\python src\revivex_auto.py "E:\Evidence\disk.vhdx.locked" "F:\Recovered\auto-new" --work-dir "C:\ReViveX-work" --progress "F:\Recovered\auto-progress.json"
```

Only when you want to undo the sorting (move files back to where extraction wrote them):

```powershell
.venv\Scripts\python src\revivex_organize.py "F:\Recovered\auto-new" --undo
```

Options: `--damaged-range START-END` (known damaged range, repeatable, merged with footer-inferred ranges), `--block-size-mib` (override the inferred VHDX block size), `--reserve-mib` (free space kept on output/temporary disks). Without `--undo`, `revivex_organize.py` sorts again.

Known-plaintext analysis and experimental inner recovery:

```powershell
.venv\Scripts\python src\analyze_gentlemen_pairs.py "C:\Evidence\target.enc" "E:\Recovered\analysis-new.json" --pair "C:\Evidence\original.bin" "C:\Evidence\original.bin.enc"
.venv\Scripts\python src\recover_inner.py "C:\Evidence\outer.zip" "E:\Recovered\inner-new" --outer-member "folder/inner.zip"
```

Repeat `--pair` for additional pairs. `--outer-member` is the exact archive-relative member name. Run each script with `--help` for current options and limits. Use Gentlemen-specific `--gentlemen` range exclusion only after confirming the format; the ranges remain inferred.

## Test, build and download

```powershell
$env:PYTHONPATH = 'src'
.venv\Scripts\python -m pip install -r requirements-test.txt
$env:QT_QPA_PLATFORM = 'offscreen'
.venv\Scripts\python -m pytest tests build -q
```

Windows EXEs must be built on Windows; see [build instructions](build/README.md). `setup.exe` supports per-user installation/uninstallation; `portable.zip` contains the full application directory, bilingual documentation and notices. `corresponding-source.zip` contains matching application and dependency sources, including Qt. Compare `Get-FileHash -Algorithm SHA256 filename` with `SHA256SUMS.txt`. Pending CI or a draft release is not a verified public release. Qt/PySide6 is used under LGPLv3 with replaceable libraries; see the included replacement instructions. CI builds the EXE on Windows and an unsigned `macos-arm64.zip` on macOS (Apple silicon, `build/macos_release.py`); both go into one draft release that is published only after review. An unfinished build or a draft does not mean a released download exists. On macOS verify with `shasum -a 256 filename`.

## License

**AGPL-3.0-or-later**; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Use, modification and redistribution are permitted subject to the license, including applicable source-availability and notice-preservation requirements. Binary distributions must retain access to matching source, build scripts and dependency notices. Modified versions supporting remote network interaction have additional AGPL obligations. Provided as-is, without warranty.

Issue reports should include version, OS, error text and a minimal shareable reproduction. **Do not publish victims' original files, keys, passwords, unredacted path reports or other private information.**
