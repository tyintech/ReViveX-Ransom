import argparse
import json
import math
import struct
from collections import Counter
from pathlib import Path


def entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    return round(-sum(count / len(data) * math.log2(count / len(data)) for count in counts.values()), 4)


def inspect(source, full_scan=False):
    source = Path(source)
    result = {"schema": "revivex.physical-signature-probe", "schema_version": 1, "source": str(source), "size": source.stat().st_size, "samples": [], "signatures": {}, "warning": "Signature candidates only; neither valid VHDX geometry nor block mapping is established.", "source_access": "read_only"}
    if not result["size"]:
        return result
    with source.open("rb") as stream:
        size = result["size"]
        for offset in [0, 65536, 131072, 196608, 262144, 1048576] + [index * (size // 20) for index in range(1, 20)]:
            if offset >= size:
                continue
            stream.seek(offset)
            data = stream.read(min(4096, size - offset))
            result["samples"].append({"offset": offset, "prefix": data[:16].hex(), "entropy": entropy(data)})
        signatures = {"vhdx": b"vhdxfile", "header": b"head", "region": b"regi", "metadata": b"metadata", "ntfs": b"NTFS    ", "gpt": b"EFI PART"}
        limit = size if full_scan else min(size, 64 * 1024 * 1024)
        result["scan_limit_bytes"] = limit
        result["hit_limit_per_signature"] = 200
        result["truncated_signatures"] = []
        result["signatures"] = {name: [] for name in signatures}
        # File mappings of multi-TB sources can fail on Windows (error 1450).
        # Search one bounded buffer at a time, retaining signature overlap.
        stream.seek(0)
        position, tail = 0, b""
        overlap = max(map(len, signatures.values())) - 1
        while position < limit:
            chunk = stream.read(min(8 * 1024 * 1024, limit - position))
            if not chunk:
                raise OSError("Short source read during signature probe")
            data, base = tail + chunk, position - len(tail)
            for name, signature in signatures.items():
                hits = result["signatures"][name]
                cursor = 0
                while len(hits) < 200:
                    found = data.find(signature, cursor)
                    if found < 0:
                        break
                    cursor = found + len(signature)
                    physical = base + found
                    # Matches wholly in the overlap were handled previously.
                    if physical + len(signature) <= position:
                        continue
                    if name not in ("vhdx", "ntfs", "gpt") and physical % 65536:
                        continue
                    hit = {"offset": physical}
                    if name == "ntfs" and physical >= 3:
                        resume = stream.tell()
                        stream.seek(physical - 3)
                        boot = stream.read(min(512, size - (physical - 3)))
                        stream.seek(resume)
                        if len(boot) == 512:
                            hit.update(boot_offset=physical - 3, bytes_per_sector=struct.unpack_from("<H", boot, 11)[0], sectors_per_cluster=boot[13], total_sectors=struct.unpack_from("<Q", boot, 40)[0], mft_cluster=struct.unpack_from("<Q", boot, 48)[0], boot_signature=boot[510:512].hex())
                    hits.append(hit)
            position += len(chunk)
            tail = data[-overlap:]
        result["truncated_signatures"] = [name for name, hits in result["signatures"].items() if len(hits) == 200]
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("--full-scan", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = inspect(args.source, args.full_scan)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with args.report.open("x", encoding="utf-8") as output:
            json.dump(result, output, ensure_ascii=True, indent=2)
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()