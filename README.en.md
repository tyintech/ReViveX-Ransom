# ReViveX Ransom

[中文](README.md) · [Download](https://github.com/tyintech/ReViveX-Ransom/releases) · [How it works](docs/PRINCIPLES.en.md) · [Technical reference](docs/TECHNICAL.en.md) · [Author website](https://www.xtyue.com/)

**Data recovery for Hyper-V virtual machine disks (VHDX) encrypted by ransomware.**

When a virtual machine's `.vhdx` file has been encrypted by ransomware and can no longer be opened or mounted, ReViveX Ransom recovers its files under their **original names and folders**. Proven effective in a real case encrypted by the **.6zdxfy variant**.

Author: **陈涛 alan chen** · Contact: **1315333@qq.com** · License: AGPL-3.0-or-later

## Main features

- **One-click automatic recovery**: choose the encrypted file and where to save, click “Start automatic recovery”; the program decides the right method itself.
- **Original names and folders**: recovered files keep their folder structure and file names, not a pile of numbered files.
- **Recovers deleted files**: files that were deleted inside the virtual disk, but whose data has not been overwritten, are recovered separately.
- **Automatic sorting**: results are sorted into usable / needs review / suspect damaged / thumbnail caches / deleted files; start with “usable”.
- **Very large disks**: virtual disks of 10+ TB are supported, with live progress and speed.
- **Pause and continue anytime**: cancel safely at any moment, then “Continue run” picks up where it stopped instead of starting over.
- **Fast temporary disk**: optionally point intermediate data at an SSD to speed things up; recovered files still go where you chose.
- **Never touches the original**: the source is only read, never modified or overwritten; sorting only moves files and can be undone.
- **Browse and export**: in “Results & verification”, browse by folder or type, search, tick and export only what you need.
- Chinese / English interface, light / dark appearance.

Also useful for plain disk images (`.img`, `.dd`…), damaged ZIP archives and PNG / SQLite salvage — see the [technical reference](docs/TECHNICAL.en.md).

## Download

From the [Releases page](https://github.com/tyintech/ReViveX-Ransom/releases):

| System | File | Notes |
| --- | --- | --- |
| Windows 10/11 (64-bit) | `windows-x64-setup.exe` | Installer; double-click, no administrator rights needed |
| Windows 10/11 (64-bit) | `windows-x64-portable.zip` | Portable; unzip and run `ReViveX-Ransom.exe` (keep the whole folder) |
| macOS (Apple silicon) | `macos-arm64.zip` | Unzip and open `ReViveX-Ransom.app` |

The apps are not code-signed: on Windows, if you see “Windows protected your PC”, click “More info › Run anyway”; on macOS, if the developer cannot be verified, open System Settings › Privacy & Security and click “Open Anyway”.

## How to use

1. **Prepare**: stop using the encrypted disk right away; ideally copy the encrypted `.vhdx` and work on the copy. Have a **separate** disk with enough space for the results.
2. **Choose the file**: open the app and, under “Recover files”, choose the encrypted VHDX (its name may now end in something like `.vhdx.6zdxfy` — choose it as is).
3. **Choose where to save**: a folder on the other disk. Optionally also choose a fast temporary folder (for example an SSD).
4. **Start**: keep the method “Automatic recovery (recommended)” and click “Start automatic recovery”. The window shows the current stage and progress; large disks take a long time, so keep the computer on.
5. **See the results**: when finished, “Results & verification” opens, where you can browse, search and export; or open the `最终结果` folder inside your save location.

To stop midway, click “Cancel safely”; later, in “Results & verification”, use “Open workspace” to select the task and click “Continue run”.

## Where the results are

A new task folder is created in your save location:

| Folder / file | Contents |
| --- | --- |
| `最终结果\可用` | Usable: files that passed the check (in their original folders) |
| `最终结果\待确认` | Needs review: files that could not be checked automatically |
| `最终结果\疑似损坏` | Suspect damaged: the check found problems; content may be partly wrong |
| `最终结果\缩略图缓存` | Thumbnail caches (Windows Thumbs.db) |
| `最终结果\已删除文件` | Deleted files that were recovered, sorted the same way |
| `清单.jsonl` | Every recovered file: original path, location, size, checksum |
| `未恢复清单.jsonl` | Files that could not be recovered, and why |

Files whose parent folder name cannot be confirmed are placed under `_上级目录名丢失_<number>` (“parent folder name lost”).

## Precautions

- This is **not a decryptor**: data overwritten by the encryption cannot be recovered, and 100% recovery is not guaranteed.
- Save results to a **separate healthy disk**, never back onto the encrypted one, and leave enough free space.
- Isolate recovered programs, scripts and macros; **do not run them directly**.
- When in doubt, start with the “usable” folder; files in “suspect damaged” may be incomplete.

## More information

- [How it works](docs/PRINCIPLES.en.md): why files can still be recovered from an encrypted VHDX.
- [Technical reference](docs/TECHNICAL.en.md): other recovery methods, capability boundaries, command line, running from source.
- [Build instructions](build/README.md): building the Windows / macOS versions yourself.

When reporting problems, include the version, system and error message; **never publish** victim files, keys, passwords or reports containing paths.

## License

Released under **AGPL-3.0-or-later**; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Provided as is, without warranty.
