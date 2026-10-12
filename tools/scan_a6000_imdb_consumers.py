#!/usr/bin/env python3
"""Read-only ELF32 symbol/dependency scanner for A6000 IMDB consumers."""
from __future__ import annotations
import argparse
from pathlib import Path
import struct

NAMES = ("IMDB_find_entry", "IMDB_get_entries", "IMDB_find_target_bit", "imdb_raw")
LIMIT = 256 * 1024 * 1024


def cstr(data, start, size, offset):
    if offset >= size:
        return ""
    end = data.find(b"\0", start + offset, start + size)
    return data[start + offset:end].decode("ascii", "replace") if end >= 0 else ""


def classify(data):
    found = {"imports": [], "exports": [], "needed": [], "literals": []}
    if len(data) < 52 or data[:6] != b"\x7fELF\x01\x01":
        return found
    shoff = struct.unpack_from("<I", data, 32)[0]
    entsize, count = struct.unpack_from("<HH", data, 46)
    if entsize < 40 or count > 4096 or shoff > len(data) or count*entsize > len(data)-shoff:
        return found
    headers = [struct.unpack_from("<10I", data, shoff + i*entsize) for i in range(count)]
    for h in headers:
        _name, typ, _flags, _vma, off, size, link, _info, _align, step = h
        if typ not in (6, 11) or link >= count or off > len(data) or size > len(data)-off:
            continue
        names = headers[link]
        soff, slen = names[4], names[5]
        if soff > len(data) or slen > len(data)-soff:
            continue
        if typ == 11 and step >= 16 and size//step <= 1000000:
            for j in range(0, size-15, step):
                sidx, _value, _size, _info, _other, ndx = struct.unpack_from("<IIIBBH", data, off+j)
                symbol = cstr(data, soff, slen, sidx)
                if symbol in NAMES:
                    found["imports" if ndx == 0 else "exports"].append(symbol)
        elif typ == 6 and step >= 8:
            for j in range(0, size-7, step):
                tag, ptr = struct.unpack_from("<II", data, off+j)
                if tag == 1 and cstr(data, soff, slen, ptr) == "libIMDB.so":
                    found["needed"].append("libIMDB.so")
    for name in NAMES:
        if name.encode() in data and name not in found["imports"] and name not in found["exports"]:
            found["literals"].append(name)
    return {key: sorted(set(values)) for key, values in found.items()}


def scan(root):
    if not root.is_dir():
        raise ValueError("root must be an unpacked firmware directory")
    scanned, skipped, rows = 0, 0, []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            size = path.stat().st_size
            if size > LIMIT:
                skipped += 1
                continue
            if size < 52:
                continue
            with path.open("rb") as f:
                if f.read(6) != b"\x7fELF\x01\x01":
                    continue
                f.seek(0)
                blob = f.read()
            scanned += 1
            result = classify(blob)
            if any(result.values()):
                rows.append((str(path.relative_to(root)), result))
        except OSError:
            continue
    return scanned, skipped, rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("root", type=Path)
    a = p.parse_args()
    try:
        scanned, skipped, rows = scan(a.root)
    except (ValueError, OSError) as e:
        p.exit(2, f"[ERROR] {e}\n")
    print(f"ELF32 scanned: {scanned} | >256 MiB skipped: {skipped}")
    for name, result in rows:
        parts = [k.upper() + "=" + ",".join(result[k]) for k in ("imports", "exports", "needed", "literals") if result[k]]
        print(f"  {name}: {' | '.join(parts)}")
    print(f"Matching libraries: {len(rows)}")
    print("IMPORT proves a linked undefined symbol, not a runtime call; NEEDED and LITERAL prove less.")


if __name__ == "__main__":
    main()
