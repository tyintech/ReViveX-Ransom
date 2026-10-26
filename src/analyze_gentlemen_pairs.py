import argparse
import base64
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


FOOTER = re.compile(
    rb"--eph--([A-Za-z0-9+/]{43}=)\n--marker--GENTLEMEN\nGENTLEMEN"
    rb"(?:(--fast--|--super--|--ultra--)\n)?$"
)


def footer(path):
    with path.open("rb") as stream:
        stream.seek(max(0, path.stat().st_size - 512))
        tail = stream.read()
    match = FOOTER.search(tail)
    if match is None:
        raise ValueError(f"Unrecognized Gentlemen footer: {path}")
    public = base64.b64decode(match[1], validate=True)
    if len(public) != 32:
        raise ValueError(f"Invalid ephemeral public key length: {path}")
    mode = match[2].decode("ascii") if match[2] else "no-speed-tag"
    return {
        "source": str(path),
        "encrypted_size": path.stat().st_size,
        "body_size": path.stat().st_size - len(match[0]),
        "footer_size": len(match[0]),
        "mode": mode,
        "ephemeral_public_key_hex": public.hex(),
    }


def geometry(size, mode):
    if size < 0:
        raise ValueError("Negative body size")
    ratios = {"--fast--": (3, 100), "--super--": (1, 100), "--ultra--": (3, 1000)}
    if mode not in ratios:
        raise ValueError("Only explicit intermittent mode tags have supported geometry")
    numerator, denominator = ratios[mode]
    chunk = size * numerator // denominator
    middle = (size - 3 * chunk) // 2 + chunk
    return [(0, chunk), (middle, middle + chunk), (2 * middle, 2 * middle + chunk)]


def compare(plain, encrypted):
    info = footer(encrypted)
    if plain.stat().st_size != info["body_size"]:
        raise ValueError(f"Plaintext size does not match ciphertext body: {plain}")
    intervals = geometry(info["body_size"], info["mode"]) if info["mode"] != "no-speed-tag" else [(0, info["body_size"])]
    inside_changed = outside_changed = 0
    per_region = [0] * len(intervals)
    plain_hash = hashlib.sha256()
    encrypted_hash = hashlib.sha256()
    keystream = bytearray()
    with plain.open("rb") as original, encrypted.open("rb") as damaged:
        offset = 0
        while data := original.read(1024 * 1024):
            cipher = damaged.read(len(data))
            if len(cipher) != len(data):
                raise ValueError("Encrypted input changed or was truncated during comparison")
            plain_hash.update(data)
            encrypted_hash.update(cipher)
            if offset == 0:
                keystream.extend(a ^ b for a, b in zip(data[:256], cipher[:256]))
            covered = 0
            total_changed = sum(a != b for a, b in zip(data, cipher))
            for index, (start, end) in enumerate(intervals):
                left, right = max(start, offset) - offset, min(end, offset + len(data)) - offset
                if left < right:
                    changed = sum(a != b for a, b in zip(data[left:right], cipher[left:right]))
                    per_region[index] += changed
                    covered += changed
            inside_changed += covered
            outside_changed += total_changed - covered
            offset += len(data)
        encrypted_hash.update(damaged.read())
    info.update(
        plaintext=str(plain),
        plaintext_sha256=plain_hash.hexdigest(),
        encrypted_sha256=encrypted_hash.hexdigest(),
        intervals=[{"start": start, "end_exclusive": end, "changed_bytes": count}
                   for (start, end), count in zip(intervals, per_region)],
        changed_inside_regions=inside_changed,
        changed_outside_regions=outside_changed,
        keystream_prefix_hex=bytes(keystream).hex(),
        keystream_prefix_sha256=hashlib.sha256(keystream).hexdigest(),
    )
    return info


def main():
    parser = argparse.ArgumentParser(description="Read-only plaintext/ciphertext comparison; not a decryptor")
    parser.add_argument("target", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("--pair", nargs=2, action="append", required=True,
                        metavar=("PLAINTEXT", "ENCRYPTED"), help="Explicit known-plaintext pair; repeat as needed")
    args = parser.parse_args()
    if args.report.exists():
        parser.error("Report must not already exist")
    pairs = [compare(Path(plain), Path(encrypted)) for plain, encrypted in args.pair]
    if not pairs:
        raise ValueError("No known-plaintext pairs found")
    target = footer(args.target)
    target["inferred_regions_not_plaintext_verified"] = geometry(target["body_size"], target["mode"])
    target["inferred_encrypted_bytes"] = sum(end - start for start, end in target["inferred_regions_not_plaintext_verified"])
    groups = Counter(item["ephemeral_public_key_hex"] for item in pairs + [target])
    repeated_prefixes = [
        [a["source"], b["source"]]
        for index, a in enumerate(pairs) for b in pairs[index + 1:]
        if a["keystream_prefix_hex"][:64] == b["keystream_prefix_hex"][:64]
    ]
    report = {
        "status": "analysis_only_not_decryption",
        "pairs": pairs,
        "target": target,
        "pair_count": len(pairs),
        "unique_ephemeral_public_keys_including_target": len(groups),
        "repeated_keystream_first_32_bytes": repeated_prefixes,
        "all_pairs_have_zero_changes_outside_regions": all(item["changed_outside_regions"] == 0 for item in pairs),
        "limitations": [
            "Known plaintext recovers keystream for that file, not the X25519 private key.",
            "Different public keys and nonmatching prefixes do not by themselves prove good randomness.",
            "Target regions are inferred from its mode and size; they are not verified against target plaintext.",
            "The target is not decrypted, repaired or made bootable by this analysis.",
        ],
        "public_sources": [
            "https://github.com/Bedrock-Safeguard/gentlemen-decryptor",
            "https://github.com/yankywilson/gentlemen-ransomware-analysis",
        ],
        "decryptor_prerequisites": [
            "A matching per-file ephemeral private key from incident-time live process memory, or operator private key.",
            "The correct campaign operator public key if using an ephemeral private key; published default is not assumed applicable.",
            "Partial-mode decryption must touch only verified encrypted chunks, not the whole VHDX.",
        ],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf-8") as output:
        json.dump(report, output, ensure_ascii=True, indent=2)
    print(json.dumps({key: value for key, value in report.items() if key != "pairs"}, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
