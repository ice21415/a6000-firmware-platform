from __future__ import annotations

import json
import logging
import os
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .db import Database, sha256_file, utc_now
from . import __version__

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class FileKind:
    format: str
    arch: str | None = None
    endian: str | None = None
    elf_class: int | None = None
    elf_machine: str | None = None
    entry: str | None = None
    metadata: dict[str, Any] | None = None


def _magic(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(64)
    except OSError:
        return b""


def classify(path: Path, magic: bytes | None = None) -> FileKind:
    magic = magic if magic is not None else _magic(path)
    name = path.name.lower()
    lower = str(path).lower().replace("\\", "/")
    if magic[:4] == b"\x7fELF":
        try:
            elf_class = 32 if magic[4] == 1 else 64 if magic[4] == 2 else None
            endian = "little" if magic[5] == 1 else "big" if magic[5] == 2 else None
            arch, machine, entry = parse_elf_header(path, magic)
            return FileKind("elf_executable_or_shared_library", arch, endian, elf_class, machine, entry)
        except (OSError, ValueError, struct.error) as exc:
            # The magic still proves an ELF container even when a truncated
            # header prevents architecture extraction.
            return FileKind("elf_executable_or_shared_library", metadata={"parse_error": str(exc)})
    if magic[:4] == b"dex\n":
        return FileKind("dex")
    if magic[:4] in (b"dey\n", b"ODEX") or name.endswith(".odex"):
        return FileKind("odex")
    if magic[:4] == b"PK\x03\x04" or name.endswith((".apk", ".jar", ".zip")):
        fmt = "apk" if name.endswith(".apk") else "jar" if name.endswith(".jar") else "zip_container"
        try:
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()[:100]
            return FileKind(fmt, metadata={"entries_sample": names})
        except (OSError, zipfile.BadZipFile):
            return FileKind("zip_or_container_unparseable")
    if name.endswith((".sh", ".rc", ".prop", ".conf", ".cfg", ".ini", ".xml", ".json", ".txt")):
        return FileKind("script_or_configuration")
    if "wbi" in name or "/wbi" in lower or name.endswith((".snapshot", ".wbin")):
        return FileKind("wbi_snapshot_candidate")
    if ("nflasha" in name or "part_image" in name or "nand" in name) and "unpacked" not in lower:
        return FileKind("nand_partition")
    if any(token in name for token in ("loader", "bootloader", "loader3")):
        return FileKind("bootloader_image")
    if "kernel" in name or name.startswith("zimage") or name.startswith("uimage"):
        return FileKind("linux_kernel")
    if "initrd" in name or "ramdisk" in name or name.endswith((".cpio", ".cramfs")):
        return FileKind("initrd_or_rootfs")
    if name.endswith((".so", ".elf", ".ko", ".bin", ".img", ".dat", ".fdat", ".tar", ".mtd", ".ipa")):
        return FileKind("binary_resource_or_container")
    if name.endswith((".png", ".jpg", ".jpeg", ".bmp", ".gif", ".ttf", ".otf", ".wav", ".mp3")):
        return FileKind("binary_resource")
    return FileKind("unknown")


def parse_elf_header(path: Path, magic: bytes | None = None) -> tuple[str, str, str]:
    magic = magic if magic is not None else _magic(path)
    if magic[:4] != b"\x7fELF":
        raise ValueError("not ELF")
    bits = magic[4]
    endian = "<" if magic[5] == 1 else ">" if magic[5] == 2 else None
    if endian is None or bits not in (1, 2):
        raise ValueError("unsupported ELF class or endian")
    with path.open("rb") as handle:
        handle.seek(16)
        if bits == 1:
            ident = struct.unpack(endian + "HHIIIIIHHHHHH", handle.read(36))
            machine, entry = ident[1], ident[3]
        else:
            ident = struct.unpack(endian + "HHIQQQIHHHHHH", handle.read(48))
            machine, entry = ident[1], ident[3]
    machines = {40: "ARM", 183: "AArch64", 3: "x86", 62: "x86_64", 8: "MIPS"}
    machine_name = machines.get(machine, f"EM_{machine}")
    return machine_name, machine_name, hex(entry)


def elf_details(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Return sections, segments, and a compact ELF header using pyelftools."""
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return [], [], {}
    sections: list[dict[str, Any]] = []
    segments: list[dict[str, Any]] = []
    with path.open("rb") as handle:
        elf = ELFFile(handle)
        header = {
            "class": elf.elfclass, "data": elf.little_endian and "little" or "big",
            "machine": str(elf["e_machine"]), "entry": hex(int(elf["e_entry"])),
            "flags": int(elf["e_flags"]),
        }
        for section in elf.iter_sections():
            sections.append({"name": section.name, "vma": hex(int(section["sh_addr"])),
                             "file_offset": hex(int(section["sh_offset"])), "size": int(section["sh_size"]),
                             "flags": hex(int(section["sh_flags"])), "type": str(section["sh_type"])})
        for segment in elf.iter_segments():
            segments.append({"type": str(segment["p_type"]), "vma": hex(int(segment["p_vaddr"])),
                             "paddr": hex(int(segment["p_paddr"])), "file_offset": hex(int(segment["p_offset"])),
                             "file_size": int(segment["p_filesz"]), "mem_size": int(segment["p_memsz"]),
                             "flags": hex(int(segment["p_flags"]))})
    return sections, segments, header


def iter_files(root: Path) -> Iterator[Path]:
    for directory, dirnames, filenames in os.walk(root):
        # The platform database and reports are outputs of this scan; indexing
        # them as firmware would create a self-referential manifest and race the
        # SQLite WAL files. Original research directories remain included.
        dirnames[:] = [d for d in dirnames if d not in {".git", "__pycache__", ".pytest_cache", "a6000-firmware-platform"}]
        for filename in filenames:
            path = Path(directory) / filename
            try:
                if path.is_file() and not path.is_symlink():
                    yield path
            except OSError:
                continue


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _partition_for(rel: str) -> tuple[str, str] | None:
    """Return only a physical image/backup chunk, never an extracted directory."""
    lower = rel.lower().replace("\\", "/")
    if "unpacked" in lower:
        return None
    name = Path(rel).name.lower()
    if any(name.endswith(ext) for ext in (".img", ".mtd", ".nand")) and ("nflasha" in lower or "part_image" in lower):
        return rel, "physical_nand"
    if any(token in name for token in ("chunk", "part-")) and any(token in lower for token in ("backup", "snapshot")):
        return rel, "backup_chunk"
    return None


def build_manifest(db: Database, root: Path, limit: int | None = None) -> dict[str, int]:
    root = root.resolve()
    counts: dict[str, int] = {"files": 0, "hashed": 0, "reused": 0, "errors": 0}
    for path in iter_files(root):
        if limit is not None and counts["files"] >= limit:
            break
        counts["files"] += 1
        rel = _relative(path, root)
        try:
            stat = path.stat()
            existing = db.connection.execute("SELECT id,sha256,size,metadata_json,analysis_status,inventory_status,image_id,partition_id FROM binary WHERE path=?", (rel,)).fetchone()
            metadata: dict[str, Any] = {}
            if existing:
                try:
                    metadata = json.loads(existing["metadata_json"] or "{}")
                except json.JSONDecodeError:
                    metadata = {}
            unchanged = bool(existing and existing["size"] == stat.st_size and metadata.get("mtime_ns") == stat.st_mtime_ns)
            digest = str(existing["sha256"]) if unchanged else sha256_file(path)
            counts["reused" if unchanged else "hashed"] += 1
            kind = classify(path)
            partition_info = _partition_for(rel)
            partition_id = None
            image_id = None
            if kind.format in {"binary_resource_or_container", "nand_partition", "bootloader_image", "linux_kernel", "initrd_or_rootfs"}:
                image_id = db.upsert("firmware_image", {"path": rel, "sha256": digest, "size": stat.st_size,
                    "format": kind.format, "version": "3.21" if "3.21" in rel else None,
                    "source_kind": "manifest", "status": "VERIFIED_STATIC", "metadata_json": "{}"}, ("path",))
            if partition_info:
                partition_path, partition_kind = partition_info
                partition_id = db.upsert("partition", {"image_id": image_id, "name": Path(partition_path).name,
                    "path": partition_path, "sha256": digest, "format": kind.format, "offset": None,
                    "size": stat.st_size, "partition_kind": partition_kind, "identity_key": f"{partition_kind}:{digest}",
                    "source_type": "manifest_file", "status": "VERIFIED_STATIC", "metadata_json": "{}"}, ("identity_key",))
            metadata.update({"mtime_ns": stat.st_mtime_ns, "root": str(root), "scanned_at": utc_now()})
            binary_identity_id = db.upsert("binary_identity", {"identity_key": f"sha256:{digest.lower()}:{stat.st_size}:{kind.format}",
                "sha256": digest, "size": stat.st_size, "format": kind.format, "arch": kind.arch,
                "endian": kind.endian, "first_seen_at": utc_now(), "metadata_json": "{}"}, ("identity_key",))
            preserved_analysis_status = (existing["analysis_status"] if existing and existing["analysis_status"] else "INVENTORIED")
            if image_id is None and existing:
                image_id = existing["image_id"]
            if partition_id is None and existing:
                partition_id = existing["partition_id"]
            binary_id = db.upsert("binary", {"path": rel, "sha256": digest, "size": stat.st_size,
                "format": kind.format, "arch": kind.arch, "endian": kind.endian,
                "elf_class": kind.elf_class, "elf_machine": kind.elf_machine, "entry_vma": kind.entry,
                "image_base": None, "runtime_va": None, "physical_offset": None, "wbi_offset": None,
                "image_id": image_id, "partition_id": partition_id, "source_path": rel,
                "source_sha256": digest, "unpack_method": None,
                "analysis_status": preserved_analysis_status, "inventory_status": "INVENTORIED",
                "binary_identity_id": binary_identity_id, "metadata_json": json.dumps(metadata, ensure_ascii=False)}, ("path",))
            db.upsert("analysis_run", {"binary_id": binary_id, "analyzer": "manifest_inventory",
                "analyzer_version": __version__, "input_sha256": digest, "started_at": utc_now(),
                "completed_at": utc_now(), "status": "COMPLETE", "checkpoint": "format-classified",
                "error_text": None, "metadata_json": json.dumps({"format": kind.format}, sort_keys=True)},
                ("binary_id", "analyzer", "analyzer_version", "input_sha256"))
            if kind.format == "elf_executable_or_shared_library":
                try:
                    sections, segments, header = elf_details(path)
                    for section in sections:
                        db.upsert("section", {"binary_id": binary_id, **section, "metadata_json": "{}"}, ("binary_id", "name", "file_offset"))
                    for segment in segments:
                        db.upsert("segment", {"binary_id": binary_id, **segment, "metadata_json": "{}"}, ("binary_id", "file_offset", "vma"))
                    db.connection.execute("UPDATE binary SET elf_class=?,endian=?,elf_machine=?,entry_vma=? WHERE id=?",
                        (header.get("class"), header.get("data"), header.get("machine"), header.get("entry"), binary_id))
                except Exception as exc:  # an individual corrupt ELF must not stop the batch
                    LOG.warning("ELF parse failed for %s: %s", rel, exc)
                    # Inventory errors describe this scan; they must not erase a
                    # completed analyzer checkpoint such as Ghidra CFG import.
                    current = db.connection.execute("SELECT analysis_status FROM binary WHERE id=?", (binary_id,)).fetchone()
                    current_status = str(current[0] or "") if current else ""
                    preserved = current_status if current_status.startswith("ANALYZED") else "INVENTORIED_WITH_ERROR"
                    db.connection.execute("UPDATE binary SET analysis_status=?,metadata_json=? WHERE id=?",
                        (preserved, json.dumps({**metadata, "elf_error": str(exc)}), binary_id))
        except (OSError, ValueError) as exc:
            counts["errors"] += 1
            LOG.warning("inventory failed for %s: %s", path, exc)
    db.commit()
    return counts


def export_manifest(db: Database, output: Path) -> int:
    rows = [dict(row) for row in db.query("SELECT * FROM binary ORDER BY path")]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"schema": 1, "generated_at": utc_now(), "binaries": rows}, ensure_ascii=False, indent=2), encoding="utf-8")
    return len(rows)
