# How ReViveX Ransom recovers files

[中文](原理说明.md) · [Back to README](../README.en.md) · [Technical reference](TECHNICAL.en.md)

This explains why “Automatic recovery” can bring back files, under their original names, from a Hyper-V virtual disk (VHDX) encrypted by ransomware. For usage, see the README.

## 1. Why the files are still there

- To be fast, this kind of ransomware encrypts only a few slices of a large file (for example the start, middle and end, about 1% each). Most of the data stays plaintext.
- The VHDX header, region table and **block allocation table (BAT)** sit at the very start of the file, inside the encrypted slice. The BAT says where each block of the virtual disk is stored in the VHDX file; without it, ordinary tools cannot open or mount the disk.
- The guest NTFS file system's own records — MFT FILE records (name, size, data location) and directory index (INDX) blocks (the names in each folder) — are mostly in plaintext areas.
- Rebuild the lost block map, and the NTFS records lead to every file by its original name and folder.

## 2. Steps and the idea behind each

**① Read-only diagnosis and sampling.** Check header signatures and the ransomware footer, infer the likely encrypted ranges, and sample plaintext areas to confirm NTFS records survived. The source is never modified.

**② Evidence scan.** One sequential pass keeps only small “evidence”: NTFS file records, directory index blocks, the opening bytes of common file formats (JPEG, PDF, ZIP headers…), all-zero areas and so on. Evidence is a tiny fraction of the source, and every later step works from it instead of re-reading the source disk.

**③ Rebuild the block map.**
- A directory index block names its directory, and that directory's NTFS record says where the index block lives inside the volume. Pairing the two gives an **exact anchor**: volume position ↔ position in the file.
- VHDX data blocks are 1 MiB aligned, and each partition's anchors share a fixed offset pattern. So the number of volumes, each partition's offset, the cluster size and the block size are all inferred, with nothing typed in.
- Blocks without an anchor get candidate positions from neighbouring anchors, checked against “a file should start here” evidence (if a record says a PDF starts at this spot, the spot must read `%PDF`). The prediction method is first tested on known blocks and used only within the distances where it was exactly right.
- The block size is never over-estimated: too small only uses less evidence, too large would map whole blocks to the wrong place.

**④ Volumes versus stored images.** Data disks often hold other disk images or backups (.vhdx, .bak…) whose own NTFS records end up in the evidence. Each MFT fragment's file-header match ratio separates them: a volume's own records match close to 100%, records inside an image close to 0%. Those are excluded, so names and folders are never mixed up.

**⑤ Matching missing blocks.** Blocks still without a position are located only with byte-exact evidence: ZIP member CRCs, PNG chunk checksums, PDF object numbers, several file headers at once. A candidate is accepted only if all evidence matches and it is the only one that does; ties are dropped. The rules are first checked on known blocks, and one wrong pick there switches matching off. Candidates are read once in disk order, avoiding random reads on slow disks.

**⑥ Writing files by name.** A file is written only when every block it uses has trusted evidence. Its path is followed up parent by parent; a parent must have the same record sequence number and really be a folder, otherwise the file goes into a “parent folder name lost” folder instead of borrowing a wrong name. Files are created exclusively and never overwrite anything.

**⑦ Deleted files.** NTFS deletion only marks a record “not in use”; the data usually remains. Such records are found, and if no existing file now occupies their data, they are recovered separately into “已删除文件” (deleted files). Ones whose data is now occupied are listed as not recoverable.

**⑧ Grading and sorting.** Every written file gets a structure check (JPEG compressed data scanned end to end, PNG/ZIP checksums, PDF object positions, database integrity checks…) and is sorted into usable / needs review / suspect damaged, with Windows thumbnail caches kept apart. Sorting only moves files, never deletes, and every move is logged and can be undone.

## 3. Reliability and safety

- **Read-only:** the source is opened read-only (on Windows, other programs are also blocked from writing to it), and every read is bounded, so 10+ TB files are fine.
- **Interruptible:** every step keeps checkpoints; after cancel, power loss or the app being closed, it continues where it stopped without writing files twice.
- **No over-claiming:** “written” is not “recovered”. Grades show structural integrity only, not that content equals the original; data and records inside the encrypted slices cannot be recovered.
