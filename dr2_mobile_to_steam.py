#!/usr/bin/env python3
"""
DR2 Mobile (.tc) -> Steam (.vfs) Save Converter

What v3 fixes/adds:
- Steam .vfs files end with a 4-byte EF BE AD DE footer. v1 accidentally
  parsed that footer as another entry header and errored with 0xDEADBEEF.
- Steam parsing now preserves that footer and roundtrips cleanly.
- Mobile .tc scanning now ranks every zlib save-body stream against a Steam
  template and can build candidate Steam savedata.vfs files.
- v3 can build a multi-slot Steam VFS from several mobile streams, rather
  than injecting only one stream into data0000.bin.
- v3 can patch the visible Steam slot chapter/title area so the save list is
  no longer stuck showing the fresh PC template chapter.

This is an experimental community reverse-engineering converter. It never overwrites inputs.
Back up savedata.vfs, savedata.bak, savedata.tmp, and savedata.tc.
"""
from __future__ import annotations

import argparse
import collections
import csv
import datetime as _datetime
import shutil
import dataclasses
import hashlib
import json
import math
import os
import re
import struct
import sys
import textwrap
import zlib
from pathlib import Path
from typing import Any, Optional

PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
ZLIB_HEADERS = {b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"}
STEAM_FOOTER = b"\xef\xbe\xad\xde"  # little-endian 0xDEADBEEF
STEAM_FOOTER_U32 = 0xDEADBEEF
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
IEND = b"IEND\xaeB`\x82"


def read_file(path: Path) -> bytes:
    if not path.exists():
        raise FileNotFoundError(path)
    if not path.is_file():
        raise IsADirectoryError(path)
    return path.read_bytes()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def hexdump(data: bytes, width: int = 16, max_len: int = 256, base: int = 0) -> str:
    data = data[:max_len]
    lines: list[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if b in PRINTABLE and b not in {9, 10, 13} else "." for b in chunk)
        lines.append(f"{base + offset:08x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


def extract_ascii_strings_with_offsets(data: bytes, min_len: int = 4, limit: int = 100) -> list[dict[str, Any]]:
    strings: list[dict[str, Any]] = []
    current = bytearray()
    start: Optional[int] = None
    for i, b in enumerate(data):
        if b in PRINTABLE and b not in {0x09, 0x0A, 0x0D}:
            if start is None:
                start = i
            current.append(b)
        else:
            if start is not None and len(current) >= min_len:
                strings.append({"offset": start, "text": current.decode("ascii", errors="replace")})
                if len(strings) >= limit:
                    return strings
            current.clear()
            start = None
    if start is not None and len(current) >= min_len and len(strings) < limit:
        strings.append({"offset": start, "text": current.decode("ascii", errors="replace")})
    return strings


def extract_utf16le_strings_with_offsets(data: bytes, min_chars: int = 4, limit: int = 100) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_chars)
    for match in pattern.finditer(data):
        out.append({"offset": match.start(), "text": match.group(0).decode("utf-16le", errors="replace")})
        if len(out) >= limit:
            break
    return out


def safe_filename(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s)[:120] or "unnamed"


def read_tc_title(data: bytes) -> str:
    # TC appears to be followed by protobuf-ish fields. Field 0x12 is a short
    # ASCII title/chapter string immediately before the first zlib stream.
    if not data.startswith(b"TC"):
        return ""
    zpos = min((p for p in [data.find(h, 0, 512) for h in ZLIB_HEADERS] if p != -1), default=-1)
    limit = zpos if zpos != -1 else min(len(data), 128)
    # Prefer a 0x12 length-delimited ASCII value.
    i = 0
    while i + 2 < limit:
        if data[i] == 0x12:
            n = data[i + 1]
            if 1 <= n <= 80 and i + 2 + n <= limit:
                raw = data[i + 2:i + 2 + n]
                if all(32 <= b < 127 for b in raw):
                    return raw.decode("ascii", errors="replace")
        i += 1
    # Fallback: first printable string in the header.
    ss = extract_ascii_strings_with_offsets(data[:limit], min_len=4, limit=5)
    return ss[0]["text"] if ss else ""


@dataclasses.dataclass
class SteamEntry:
    index: int
    name: str
    header_offset: int
    payload_offset: int
    size: int
    sha256: str
    ascii_strings: list[dict[str, Any]]
    utf16le_strings: list[dict[str, Any]]


@dataclasses.dataclass
class SteamArchive:
    entries: list[SteamEntry]
    footer_offset: Optional[int]
    footer_hex: str
    trailing_hex: str


def parse_steam_vfs_archive(data: bytes) -> SteamArchive:
    entries: list[SteamEntry] = []
    off = 0
    idx = 0
    footer_offset: Optional[int] = None
    footer = b""
    trailing = b""

    while off < len(data):
        remaining = len(data) - off
        if remaining >= 4 and data[off:off + 4] == STEAM_FOOTER:
            footer_offset = off
            footer = data[off:off + 4]
            trailing = data[off + 4:]
            break
        if remaining < 4:
            raise ValueError(f"Trailing {remaining} byte(s) at offset 0x{off:x}; not enough for name length")

        name_len = struct.unpack_from("<I", data, off)[0]
        if name_len == STEAM_FOOTER_U32:
            footer_offset = off
            footer = data[off:off + 4]
            trailing = data[off + 4:]
            break
        if not (1 <= name_len <= 255):
            raise ValueError(f"Bad name length {name_len} at offset 0x{off:x}; parsed {idx} entries")

        name_start = off + 4
        name_end = name_start + name_len
        size_start = name_end
        size_end = size_start + 4
        if size_end > len(data):
            raise ValueError(f"Entry {idx} header overruns file at offset 0x{off:x}")

        name_raw = data[name_start:name_end]
        try:
            name = name_raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Entry {idx} name is not ASCII at offset 0x{name_start:x}: {name_raw!r}") from exc

        payload_size = struct.unpack_from("<I", data, size_start)[0]
        payload_offset = size_end
        payload_end = payload_offset + payload_size
        if payload_end > len(data):
            raise ValueError(
                f"Entry {idx} payload {name!r} overruns file: offset=0x{payload_offset:x}, size={payload_size}"
            )
        payload = data[payload_offset:payload_end]
        entries.append(SteamEntry(
            index=idx,
            name=name,
            header_offset=off,
            payload_offset=payload_offset,
            size=payload_size,
            sha256=sha256(payload),
            ascii_strings=extract_ascii_strings_with_offsets(payload, limit=30),
            utf16le_strings=extract_utf16le_strings_with_offsets(payload, limit=30),
        ))
        off = payload_end
        idx += 1

    return SteamArchive(entries=entries, footer_offset=footer_offset, footer_hex=footer.hex(), trailing_hex=trailing.hex())


def parse_steam_vfs_bytes(data: bytes) -> list[SteamEntry]:
    return parse_steam_vfs_archive(data).entries


def build_steam_vfs(entries: list[tuple[str, bytes]], footer: bytes = STEAM_FOOTER) -> bytes:
    out = bytearray()
    for name, payload in entries:
        name_b = name.encode("ascii")
        if not (1 <= len(name_b) <= 255):
            raise ValueError(f"Bad Steam entry name length for {name!r}")
        out += struct.pack("<I", len(name_b))
        out += name_b
        out += struct.pack("<I", len(payload))
        out += payload
    out += footer
    return bytes(out)


@dataclasses.dataclass
class StreamHit:
    index: int
    offset: int
    mode: str
    compressed_end_offset: int
    compressed_size: int
    decompressed_size: int
    compressed_sha256: str
    decompressed_sha256: str
    decompressed_entropy: float
    ascii_strings: list[dict[str, Any]]
    utf16le_strings: list[dict[str, Any]]


def try_decompress_stream(data: bytes, offset: int, mode: str = "zlib", max_out: int = 128 * 1024 * 1024) -> Optional[tuple[bytes, int]]:
    wbits = 15 if mode == "zlib" else 31
    try:
        obj = zlib.decompressobj(wbits)
        out = obj.decompress(data[offset:], max_out)
        if not obj.eof:
            return None
        end = len(data) - len(obj.unused_data)
        if len(out) < 32 or end <= offset:
            return None
        return bytes(out), end
    except Exception:
        return None


def find_header_offsets(data: bytes, needle: bytes) -> list[int]:
    out: list[int] = []
    start = 0
    while True:
        p = data.find(needle, start)
        if p == -1:
            return out
        out.append(p)
        start = p + 1


def scan_tc_streams(data: bytes, max_out: int = 128 * 1024 * 1024, include_gzip: bool = False) -> list[StreamHit]:
    candidate_offsets: set[tuple[int, str]] = set()
    for h in ZLIB_HEADERS:
        for off in find_header_offsets(data, h):
            candidate_offsets.add((off, "zlib"))
    if include_gzip:
        for off in find_header_offsets(data, b"\x1f\x8b"):
            candidate_offsets.add((off, "gzip"))

    hits: list[StreamHit] = []
    seen: set[tuple[int, int, str]] = set()
    for off, mode in sorted(candidate_offsets):
        result = try_decompress_stream(data, off, mode, max_out=max_out)
        if result is None:
            continue
        raw, end = result
        key = (off, end, mode)
        if key in seen:
            continue
        seen.add(key)
        comp = data[off:end]
        hits.append(StreamHit(
            index=len(hits),
            offset=off,
            mode=mode,
            compressed_end_offset=end,
            compressed_size=len(comp),
            decompressed_size=len(raw),
            compressed_sha256=sha256(comp),
            decompressed_sha256=sha256(raw),
            decompressed_entropy=entropy(raw),
            ascii_strings=extract_ascii_strings_with_offsets(raw, limit=20),
            utf16le_strings=extract_utf16le_strings_with_offsets(raw, limit=20),
        ))
    return hits


def extract_stream_blob(data: bytes, stream_index: int, include_gzip: bool = False) -> tuple[StreamHit, bytes]:
    streams = scan_tc_streams(data, include_gzip=include_gzip)
    if stream_index >= len(streams):
        raise IndexError(f"stream index {stream_index} not found; only {len(streams)} stream(s) found")
    h = streams[stream_index]
    result = try_decompress_stream(data, h.offset, h.mode)
    if result is None:
        raise RuntimeError(f"stream {stream_index} no longer decompresses")
    raw, _ = result
    return h, raw


def extract_png_ranges(data: bytes, limit: int = 1000) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    start = 0
    while len(out) < limit:
        idx = data.find(PNG_MAGIC, start)
        if idx == -1:
            break
        end_marker = data.find(IEND, idx)
        if end_marker == -1:
            out.append({"offset": idx, "end_offset": None, "size": None, "complete": False})
            start = idx + 8
            continue
        end = end_marker + len(IEND)
        blob = data[idx:end]
        out.append({"offset": idx, "end_offset": end, "size": len(blob), "complete": True, "sha256": sha256(blob)})
        start = end
    return out


def compare_blobs(a: bytes, b: bytes) -> dict[str, Any]:
    min_len = min(len(a), len(b))
    common_prefix = 0
    while common_prefix < min_len and a[common_prefix] == b[common_prefix]:
        common_prefix += 1
    common_suffix = 0
    while common_suffix < min_len - common_prefix and a[len(a) - 1 - common_suffix] == b[len(b) - 1 - common_suffix]:
        common_suffix += 1
    same = sum(x == y for x, y in zip(a[:min_len], b[:min_len]))
    return {
        "a_size": len(a),
        "b_size": len(b),
        "same_size": len(a) == len(b),
        "same_sha256": sha256(a) == sha256(b),
        "common_prefix": common_prefix,
        "common_suffix": common_suffix,
        "same_offset_equal_bytes": same,
        "same_offset_equal_percent_of_shorter": round(100 * same / min_len, 6) if min_len else 0,
    }


def sampled_equal_percent(a: bytes, b: bytes, stride: int = 32) -> float:
    min_len = min(len(a), len(b))
    if min_len == 0:
        return 0.0
    same = 0
    total = 0
    # Sampling makes prefix ranking fast; the exact score is computed once for
    # the winning prefix.
    for i in range(0, min_len, stride):
        total += 1
        if a[i] == b[i]:
            same += 1
    return 100 * same / total if total else 0.0


def score_stream_against_payload(stream: bytes, payload: bytes, prefix_min: int = 700, prefix_max: int = 780, step: int = 4) -> dict[str, Any]:
    best_prefix: Optional[int] = None
    best_sample = -1.0
    for n in range(prefix_min, min(prefix_max, len(payload) - 1) + 1, step):
        sample = sampled_equal_percent(stream, payload[n:])
        if sample > best_sample:
            best_sample = sample
            best_prefix = n
    if best_prefix is None:
        return {"steam_prefix_removed": None, **compare_blobs(stream, payload)}
    exact = compare_blobs(stream, payload[best_prefix:])
    return {"steam_prefix_removed": best_prefix, "sampled_percent_for_prefix_choice": round(best_sample, 6), **exact}


def steam_list(path: Path, json_out: Optional[Path] = None) -> int:
    data = read_file(path)
    archive = parse_steam_vfs_archive(data)
    manifest = {
        "path": str(path),
        "size": len(data),
        "sha256": sha256(data),
        "entry_count": len(archive.entries),
        "footer_offset": archive.footer_offset,
        "footer_hex": archive.footer_hex,
        "trailing_hex": archive.trailing_hex,
        "entries": [dataclasses.asdict(e) for e in archive.entries],
    }
    print(f"Steam VFS: {path}")
    print(f"Size: {len(data)} bytes  SHA-256: {sha256(data)}")
    print(f"Entries: {len(archive.entries)}")
    print(f"Footer: {archive.footer_hex or '(none)'} at {hex(archive.footer_offset) if archive.footer_offset is not None else '(none)'}")
    for e in archive.entries:
        title = next((s["text"] for s in e.ascii_strings if "Danganronpa" in s["text"]), "")
        chapter = next((s["text"] for s in e.ascii_strings if s["text"].startswith(("PROLOGUE", "CHAPTER", "EPILOGUE"))), "")
        coins = next((s["text"] for s in e.ascii_strings if s["text"].startswith("Monocoins")), "")
        print(f"[{e.index:02}] {e.name:<14} payload=0x{e.payload_offset:08x} size={e.size:7} {chapter} {coins} {title}")
    if json_out:
        json_out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Wrote {json_out}")
    return 0


def steam_extract(path: Path, out_dir: Path) -> int:
    data = read_file(path)
    archive = parse_steam_vfs_archive(data)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "source": str(path),
        "size": len(data),
        "sha256": sha256(data),
        "footer_offset": archive.footer_offset,
        "footer_hex": archive.footer_hex,
        "entries": [],
    }
    for e in archive.entries:
        payload = data[e.payload_offset:e.payload_offset + e.size]
        filename = f"{e.index:02d}_{safe_filename(e.name)}"
        payload_path = out_dir / filename
        payload_path.write_bytes(payload)
        (out_dir / f"{filename}.head.txt").write_text(hexdump(payload, max_len=2048), encoding="utf-8")
        info = dataclasses.asdict(e)
        info["extracted_file"] = payload_path.name
        manifest["entries"].append(info)
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Extracted {len(archive.entries)} Steam entries to {out_dir}")
    print(f"Wrote {out_dir / 'manifest.json'}")
    return 0


def steam_roundtrip(path: Path, out_path: Path) -> int:
    data = read_file(path)
    archive = parse_steam_vfs_archive(data)
    rebuilt = build_steam_vfs(
        [(e.name, data[e.payload_offset:e.payload_offset + e.size]) for e in archive.entries],
        footer=bytes.fromhex(archive.footer_hex) if archive.footer_hex else b"",
    )
    out_path.write_bytes(rebuilt)
    print(f"Original SHA-256:  {sha256(data)}")
    print(f"Roundtrip SHA-256: {sha256(rebuilt)}")
    print(f"Wrote {out_path}")
    print("MATCH" if data == rebuilt else "WARNING: rebuilt file differs")
    return 0 if data == rebuilt else 2


def tc_list(path: Path, json_out: Optional[Path], include_gzip: bool = False) -> int:
    data = read_file(path)
    streams = scan_tc_streams(data, include_gzip=include_gzip)
    manifest = {
        "path": str(path),
        "size": len(data),
        "sha256": sha256(data),
        "md5": md5(data),
        "entropy": entropy(data),
        "tc_title_guess": read_tc_title(data),
        "stream_count": len(streams),
        "streams": [dataclasses.asdict(s) for s in streams],
    }
    print(f"TC file: {path}")
    print(f"Size: {len(data)} bytes SHA-256: {sha256(data)} entropy={entropy(data):.4f}")
    print(f"Title/chapter guess: {manifest['tc_title_guess']!r}")
    print(f"Streams: {len(streams)}")
    for s in streams:
        first_text = s.utf16le_strings[0]["text"] if s.utf16le_strings else ""
        print(f"[{s.index:02}] {s.mode} off=0x{s.offset:x} comp={s.compressed_size:7} decomp={s.decompressed_size:7} entropy={s.decompressed_entropy:.4f} {first_text[:70]}")
    if json_out:
        json_out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Wrote {json_out}")
    return 0


def tc_extract(path: Path, out_dir: Path, include_gzip: bool = False) -> int:
    data = read_file(path)
    streams = scan_tc_streams(data, include_gzip=include_gzip)
    pngs = extract_png_ranges(data)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "source": str(path),
        "size": len(data),
        "sha256": sha256(data),
        "md5": md5(data),
        "entropy": entropy(data),
        "tc_title_guess": read_tc_title(data),
        "head_hex": hexdump(data, max_len=512),
        "tail_hex": hexdump(data[-512:], max_len=512, base=max(0, len(data) - 512)),
        "streams": [],
        "pngs": pngs,
    }
    for s in streams:
        raw, _ = try_decompress_stream(data, s.offset, s.mode)  # type: ignore[misc]
        stem = f"stream_{s.index:02d}_{s.mode}_off_{s.offset:08x}_size_{s.decompressed_size}"
        raw_path = out_dir / f"{stem}.bin"
        raw_path.write_bytes(raw)
        (out_dir / f"{stem}.head.txt").write_text(hexdump(raw, max_len=2048), encoding="utf-8")
        info = dataclasses.asdict(s)
        info["extracted_file"] = raw_path.name
        manifest["streams"].append(info)
    for i, p in enumerate(pngs):
        if p.get("complete") and p.get("size"):
            (out_dir / f"png_{i:02d}_off_{p['offset']:08x}.png").write_bytes(data[p["offset"]:p["end_offset"]])
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Extracted {len(streams)} stream(s) and {sum(1 for p in pngs if p.get('complete'))} PNG(s) to {out_dir}")
    print(f"Wrote {out_dir / 'manifest.json'}")
    return 0


def score_streams(mobile_tc: Path, steam_vfs: Path, entry_index: int, json_out: Optional[Path], include_gzip: bool = False) -> int:
    mobile = read_file(mobile_tc)
    steam = read_file(steam_vfs)
    streams = scan_tc_streams(mobile, include_gzip=include_gzip)
    archive = parse_steam_vfs_archive(steam)
    if entry_index >= len(archive.entries):
        raise IndexError(f"Steam entry {entry_index} not found; only {len(archive.entries)} entries found")
    e = archive.entries[entry_index]
    payload = steam[e.payload_offset:e.payload_offset + e.size]
    ranked = []
    for s in streams:
        raw, _ = try_decompress_stream(mobile, s.offset, s.mode)  # type: ignore[misc]
        best = score_stream_against_payload(raw, payload)
        ranked.append({"stream": dataclasses.asdict(s), "best_alignment": best})
    ranked.sort(key=lambda r: r["best_alignment"]["same_offset_equal_percent_of_shorter"], reverse=True)
    result = {
        "mobile_tc": str(mobile_tc),
        "steam_vfs": str(steam_vfs),
        "tc_title_guess": read_tc_title(mobile),
        "steam_entry": dataclasses.asdict(e),
        "ranked_streams": ranked,
    }
    print(f"Best stream ranking against Steam entry {entry_index} ({e.name}):")
    for r in ranked:
        s = r["stream"]
        b = r["best_alignment"]
        print(f"stream {s['index']:02} off=0x{s['offset']:x} decomp={s['decompressed_size']} best_prefix={b['steam_prefix_removed']} equal={b['same_offset_equal_percent_of_shorter']}%")
    if json_out:
        json_out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Wrote {json_out}")
    return 0


def make_candidate(mobile: bytes, steam: bytes, stream_index: int, entry_index: int, prefix_from_template: int, out_path: Path, include_gzip: bool = False) -> dict[str, Any]:
    h, stream_blob = extract_stream_blob(mobile, stream_index, include_gzip=include_gzip)
    archive = parse_steam_vfs_archive(steam)
    if entry_index >= len(archive.entries):
        raise IndexError(f"Steam entry {entry_index} not found; only {len(archive.entries)} entries found")
    new_entries: list[tuple[str, bytes]] = []
    for e in archive.entries:
        payload = steam[e.payload_offset:e.payload_offset + e.size]
        if e.index == entry_index:
            if prefix_from_template < 0 or prefix_from_template > len(payload):
                raise ValueError("prefix_from_template is outside the target Steam payload")
            payload = payload[:prefix_from_template] + stream_blob
        new_entries.append((e.name, payload))
    candidate = build_steam_vfs(new_entries, footer=bytes.fromhex(archive.footer_hex) if archive.footer_hex else STEAM_FOOTER)
    out_path.write_bytes(candidate)
    parsed = parse_steam_vfs_archive(candidate)
    notes = {
        "warning": "EXPERIMENTAL. Back up Steam saves and disable Steam Cloud before testing.",
        "out": str(out_path),
        "candidate_size": len(candidate),
        "candidate_sha256": sha256(candidate),
        "stream_used": dataclasses.asdict(h),
        "steam_entry_replaced": dataclasses.asdict(archive.entries[entry_index]),
        "prefix_from_template": prefix_from_template,
        "candidate_parse_ok": len(parsed.entries) == len(archive.entries),
        "candidate_footer_hex": parsed.footer_hex,
    }
    out_path.with_suffix(out_path.suffix + ".notes.json").write_text(json.dumps(notes, indent=2, ensure_ascii=False), encoding="utf-8")
    return notes


def convert_one(mobile_tc: Path, steam_template: Path, out_path: Path, stream_index: int, entry_index: int, prefix_from_template: int, include_gzip: bool = False) -> int:
    notes = make_candidate(read_file(mobile_tc), read_file(steam_template), stream_index, entry_index, prefix_from_template, out_path, include_gzip=include_gzip)
    print(f"Wrote candidate: {out_path}")
    print(f"Wrote notes: {out_path.with_suffix(out_path.suffix + '.notes.json')}")
    print(f"Candidate parse ok: {notes['candidate_parse_ok']} footer={notes['candidate_footer_hex']}")
    print("Test with backups and Steam Cloud disabled.")
    return 0


def build_candidates(mobile_tc: Path, steam_template: Path, out_dir: Path, entry_index: int, prefix_from_template: int, top: int, include_gzip: bool = False) -> int:
    mobile = read_file(mobile_tc)
    steam = read_file(steam_template)
    streams = scan_tc_streams(mobile, include_gzip=include_gzip)
    archive = parse_steam_vfs_archive(steam)
    if entry_index >= len(archive.entries):
        raise IndexError(f"Steam entry {entry_index} not found; only {len(archive.entries)} entries found")
    payload = steam[archive.entries[entry_index].payload_offset:archive.entries[entry_index].payload_offset + archive.entries[entry_index].size]
    ranked = []
    for s in streams:
        raw, _ = try_decompress_stream(mobile, s.offset, s.mode)  # type: ignore[misc]
        best = score_stream_against_payload(raw, payload)
        ranked.append((best["same_offset_equal_percent_of_shorter"], s.index, best))
    ranked.sort(reverse=True)
    selected = ranked if top <= 0 else ranked[:top]
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "mobile_tc": str(mobile_tc),
        "steam_template": str(steam_template),
        "entry_index": entry_index,
        "prefix_from_template": prefix_from_template,
        "tc_title_guess": read_tc_title(mobile),
        "generated": [],
        "ranking": [{"stream_index": idx, "score_percent": score, "best_alignment": best} for score, idx, best in ranked],
    }
    for score, idx, best in selected:
        out_path = out_dir / f"savedata_candidate_stream{idx:02d}.vfs"
        notes = make_candidate(mobile, steam, idx, entry_index, prefix_from_template, out_path, include_gzip=include_gzip)
        notes["ranking_score_percent"] = score
        notes["best_alignment"] = best
        manifest["generated"].append(notes)
        print(f"Wrote {out_path.name}: stream={idx:02d} score={score:.6f}% parse_ok={notes['candidate_parse_ok']}")
    (out_dir / "candidate_manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {out_dir / 'candidate_manifest.json'}")
    print("Rename the candidate you want to test to savedata.vfs only after backing up your Steam saves.")
    return 0


def report(path: Path, out: Optional[Path] = None, json_out: Optional[Path] = None) -> int:
    data = read_file(path)
    rep = {
        "path": str(path),
        "size": len(data),
        "sha256": sha256(data),
        "md5": md5(data),
        "entropy": entropy(data),
        "head_hex": hexdump(data, max_len=256),
        "tail_hex": hexdump(data[-256:], max_len=256, base=max(0, len(data) - 256)),
        "ascii_strings_sample": extract_ascii_strings_with_offsets(data[:2 * 1024 * 1024], limit=100),
        "utf16le_strings_sample": extract_utf16le_strings_with_offsets(data[:2 * 1024 * 1024], limit=100),
    }
    if data.startswith(b"TC"):
        streams = scan_tc_streams(data)
        rep["tc_title_guess"] = read_tc_title(data)
        rep["zlib_streams"] = [dataclasses.asdict(s) for s in streams]
    if data[:4] == b"\x0c\x00\x00\x00":
        archive = parse_steam_vfs_archive(data)
        rep["steam_archive"] = {
            "entry_count": len(archive.entries),
            "footer_offset": archive.footer_offset,
            "footer_hex": archive.footer_hex,
            "entries": [dataclasses.asdict(e) for e in archive.entries],
        }
    txt = textwrap.dedent(f"""
    DR2 Save Report v6
    ==================
    Path: {path}
    Size: {len(data)} bytes
    SHA-256: {sha256(data)}
    MD5: {md5(data)}
    Entropy: {entropy(data):.4f} bits/byte

    Header hexdump:
{hexdump(data, max_len=256)}

    Tail hexdump:
{hexdump(data[-256:], max_len=256, base=max(0, len(data) - 256))}
    """).strip() + "\n"
    if out:
        out.write_text(txt, encoding="utf-8")
        print(f"Wrote {out}")
    else:
        print(txt)
    if json_out:
        json_out.write_text(json.dumps(rep, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Wrote {json_out}")
    return 0



# ---------------- v3 helpers: multi-slot building and visible slot metadata ----------------

STEAM_PAYLOAD_TITLE_OFF = 0x00
STEAM_PAYLOAD_TITLE_LEN = 0x40
# Important: in real Steam saves, the chapter text begins at payload+0x40.
# v3 wrote at payload+0x3c, causing the game to display "TER..." instead
# of "CHAPTER..." and "OGUE" instead of "PROLOGUE".
STEAM_PAYLOAD_CHAPTER_OFF = 0x40
STEAM_PAYLOAD_CHAPTER_LEN = 0x80
STEAM_PAYLOAD_INFO_OFF = 0xc0
STEAM_PAYLOAD_INFO_LEN = 0x100
STEAM_PAYLOAD_DATE_OFF = 0x2c0
STEAM_PAYLOAD_DATE_LEN = 0x40


def parse_int_list(text: str) -> list[int]:
    """Parse "1,2,5-7" into [1,2,5,6,7]."""
    out: list[int] = []
    for part in text.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            start = int(a.strip())
            end = int(b.strip())
            step = 1 if end >= start else -1
            out.extend(range(start, end + step, step))
        else:
            out.append(int(part))
    # Preserve order, remove duplicates.
    seen: set[int] = set()
    deduped: list[int] = []
    for x in out:
        if x not in seen:
            deduped.append(x)
            seen.add(x)
    return deduped


def strings_in_range(data: bytes, start: int, end: int, min_len: int = 4) -> list[str]:
    start = max(0, start)
    end = min(len(data), end)
    return [s['text'] for s in extract_ascii_strings_with_offsets(data[start:end], min_len=min_len, limit=50)]


def guess_stream_chapter_from_context(tc_data: bytes, stream: StreamHit, previous_end: int = 0) -> str:
    """Guess the mobile save slot title/chapter from bytes before a zlib stream.

    The TC header/record uses protobuf-ish length-delimited fields. In samples,
    a plain ASCII chapter title appears shortly before the compressed save body.
    This deliberately avoids pretending we fully understand the container.
    """
    # Prefer a local window after the previous compressed stream.
    start = max(previous_end, stream.offset - 256)
    local = tc_data[start:stream.offset]

    # Look for length-delimited field 0x12: <len> <printable ASCII>.
    best = ''
    for i in range(0, max(0, len(local) - 2)):
        if local[i] == 0x12:
            n = local[i + 1]
            if 3 <= n <= 80 and i + 2 + n <= len(local):
                raw = local[i + 2:i + 2 + n]
                if all(32 <= b < 127 for b in raw):
                    text = raw.decode('ascii', errors='replace').strip()
                    if any(k in text.upper() for k in ('PROLOGUE', 'CHAPTER', 'EPILOGUE')):
                        return text
                    if len(text) > len(best):
                        best = text
    if best:
        return best

    # Fallback: use normal ASCII strings in the window.
    candidates = strings_in_range(tc_data, start, stream.offset, min_len=4)
    for text in reversed(candidates):
        u = text.upper()
        if any(k in u for k in ('PROLOGUE', 'CHAPTER', 'EPILOGUE')):
            return text.strip()
    return ''


def parse_pipe_list(text: str) -> list[str]:
    """Parse pipe-separated user text, preserving empty entries."""
    if not text:
        return []
    return [part.strip() for part in text.split('|')]


def find_png_after_stream(pngs: list[dict[str, Any]], stream: StreamHit, next_stream_offset: Optional[int]) -> Optional[dict[str, Any]]:
    """Find a PNG thumbnail that appears after this stream and before the next stream."""
    for p in pngs:
        off = p.get('offset')
        if off is None:
            continue
        if off >= stream.compressed_end_offset and (next_stream_offset is None or off < next_stream_offset):
            return p
    return None


def tc_map(mobile_tc: Path, json_out: Optional[Path] = None, steam_template: Optional[Path] = None, entry_index: int = 0, streams_arg: str = 'all', include_gzip: bool = False, grep: str = '', only_png: bool = False, only_titled: bool = False) -> int:
    """Print a practical map of mobile TC streams, titles, thumbnails, and optional Steam similarity.

    This is meant for deciding which TC stream numbers correspond to the visible
    mobile save slots before building a multi-slot Steam VFS. v5 adds --grep,
    --only-png, and --only-titled so you can find the handful of visible saves
    inside a noisy TC file.
    """
    mobile = read_file(mobile_tc)
    streams = scan_tc_streams(mobile, include_gzip=include_gzip)
    pngs = extract_png_ranges(mobile)

    if streams_arg.lower() in {'all', '*'}:
        selected = [s.index for s in streams]
    else:
        selected = parse_int_list(streams_arg)

    steam_payload: Optional[bytes] = None
    if steam_template is not None:
        steam = read_file(steam_template)
        archive = parse_steam_vfs_archive(steam)
        if entry_index >= len(archive.entries):
            raise IndexError(f"Steam entry {entry_index} not found; only {len(archive.entries)} entries found")
        e = archive.entries[entry_index]
        steam_payload = steam[e.payload_offset:e.payload_offset + e.size]

    previous_ends: dict[int, int] = {}
    last_end = 0
    for s in streams:
        previous_ends[s.index] = last_end
        last_end = s.compressed_end_offset

    grep_re = re.compile(grep, re.IGNORECASE) if grep else None

    rows: list[dict[str, Any]] = []
    for pos, s in enumerate(streams):
        if s.index not in selected:
            continue
        next_off = streams[pos + 1].offset if pos + 1 < len(streams) else None
        title = guess_stream_chapter_from_context(mobile, s, previous_ends.get(s.index, 0))
        png = find_png_after_stream(pngs, s, next_off)
        first_utf16 = s.utf16le_strings[0]['text'] if s.utf16le_strings else ''
        if only_png and png is None:
            continue
        if only_titled and not title:
            continue
        haystack = f"{title} {first_utf16}"
        if grep_re is not None and not grep_re.search(haystack):
            continue
        score_obj: Optional[dict[str, Any]] = None
        score_pct: Optional[float] = None
        if steam_payload is not None:
            raw, _ = try_decompress_stream(mobile, s.offset, s.mode)  # type: ignore[misc]
            if raw is not None:
                score_obj = score_stream_against_payload(raw, steam_payload)
                score_pct = score_obj['same_offset_equal_percent_of_shorter']
        rows.append({
            'stream_index': s.index,
            'offset_hex': f"0x{s.offset:x}",
            'compressed_end_hex': f"0x{s.compressed_end_offset:x}",
            'compressed_size': s.compressed_size,
            'decompressed_size': s.decompressed_size,
            'title_guess': title,
            'has_following_png_before_next_stream': png is not None,
            'following_png_offset_hex': f"0x{png['offset']:x}" if png else '',
            'first_utf16_text': first_utf16[:120],
            'score_against_template_percent': score_pct,
            'alignment': score_obj,
        })

    result = {
        'mobile_tc': str(mobile_tc),
        'size': len(mobile),
        'sha256': sha256(mobile),
        'stream_count': len(streams),
        'png_count': len(pngs),
        'streams_arg': streams_arg,
        'steam_template': str(steam_template) if steam_template else None,
        'grep': grep,
        'only_png': only_png,
        'only_titled': only_titled,
        'entries': rows,
    }
    print(f"TC map: {mobile_tc}")
    print(f"Streams: {len(streams)}  PNGs: {len(pngs)}")
    if steam_template:
        print(f"Scored against Steam template: {steam_template}")
    print("idx   score%     png  offset    title / first in-body text")
    print("----  ---------  ---  --------  ------------------------------------------------------------")
    for r in rows:
        score = '' if r['score_against_template_percent'] is None else f"{r['score_against_template_percent']:.6f}"
        pngflag = 'yes' if r['has_following_png_before_next_stream'] else 'no'
        title = r['title_guess'] or '(no title guess)'
        body = r['first_utf16_text']
        print(f"{r['stream_index']:>4}  {score:>9}  {pngflag:>3}  {r['offset_hex']:<8}  {title}  |  {body}")
    if json_out:
        json_out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
        print(f"Wrote {json_out}")
    return 0


def steam_display_bytes(text: str, max_len: int) -> bytes:
    """Encode Steam visible slot text, padded with NULs.

    Steam slot titles use Shift-JIS-compatible bytes. ASCII works, and the PC
    saves often use E3 80 80 full-width-space bytes after the chapter title.
    We keep this conservative: ASCII plus a Japanese full-width space separator
    if room allows.
    """
    clean = re.sub(r"[\x00-\x1f]+", " ", text).strip()
    raw = clean.encode('utf-8', errors='ignore')
    if len(raw) + 3 <= max_len:
        raw += b'\xe3\x80\x80'
    raw = raw[:max_len]
    return raw + b'\x00' * (max_len - len(raw))


def patch_steam_payload_prefix(prefix: bytes, chapter: str = '', info: str = '', date: str = '') -> bytes:
    """Patch only the visible Steam save-list metadata prefix.

    This does not touch the mobile save body that appears to hold real progress.
    If chapter/info/date are blank, the template prefix is kept as-is.
    """
    out = bytearray(prefix)
    if chapter and len(out) >= STEAM_PAYLOAD_CHAPTER_OFF + STEAM_PAYLOAD_CHAPTER_LEN:
        out[STEAM_PAYLOAD_CHAPTER_OFF:STEAM_PAYLOAD_CHAPTER_OFF + STEAM_PAYLOAD_CHAPTER_LEN] = steam_display_bytes(chapter, STEAM_PAYLOAD_CHAPTER_LEN)
    if info and len(out) >= STEAM_PAYLOAD_INFO_OFF + min(STEAM_PAYLOAD_INFO_LEN, len(out) - STEAM_PAYLOAD_INFO_OFF):
        max_len = min(STEAM_PAYLOAD_INFO_LEN, len(out) - STEAM_PAYLOAD_INFO_OFF)
        raw = info.encode('utf-8', errors='ignore')[:max_len]
        out[STEAM_PAYLOAD_INFO_OFF:STEAM_PAYLOAD_INFO_OFF + max_len] = raw + b'\x00' * (max_len - len(raw))
    if date and len(out) >= STEAM_PAYLOAD_DATE_OFF + min(STEAM_PAYLOAD_DATE_LEN, len(out) - STEAM_PAYLOAD_DATE_OFF):
        max_len = min(STEAM_PAYLOAD_DATE_LEN, len(out) - STEAM_PAYLOAD_DATE_OFF)
        raw = date.encode('ascii', errors='ignore')[:max_len]
        out[STEAM_PAYLOAD_DATE_OFF:STEAM_PAYLOAD_DATE_OFF + max_len] = raw + b'\x00' * (max_len - len(raw))
    return bytes(out)


def build_multi(mobile_tc: Path, steam_template: Path, out_path: Path, streams_arg: str, entry_index: int, prefix_from_template: int, sort_by_score: bool, include_gzip: bool = False, max_entries: int = 0, patch_titles: bool = True, titles_arg: str = '', dates_arg: str = '') -> int:
    mobile = read_file(mobile_tc)
    steam = read_file(steam_template)
    tc_streams = scan_tc_streams(mobile, include_gzip=include_gzip)
    archive = parse_steam_vfs_archive(steam)
    if entry_index >= len(archive.entries):
        raise IndexError(f"Steam entry {entry_index} not found; only {len(archive.entries)} entries found")
    template_entry = archive.entries[entry_index]
    template_payload = steam[template_entry.payload_offset:template_entry.payload_offset + template_entry.size]
    if prefix_from_template < 0 or prefix_from_template > len(template_payload):
        raise ValueError("prefix_from_template is outside the target Steam payload")
    prefix = template_payload[:prefix_from_template]
    title_overrides = parse_pipe_list(titles_arg)
    date_overrides = parse_pipe_list(dates_arg)

    if streams_arg.lower() in {'all', '*'}:
        selected = [s.index for s in tc_streams]
    else:
        selected = parse_int_list(streams_arg)

    stream_by_index = {s.index: s for s in tc_streams}
    missing = [i for i in selected if i not in stream_by_index]
    if missing:
        raise IndexError(f"Stream index(es) not found: {missing}; available 0..{len(tc_streams)-1}")

    previous_ends: dict[int, int] = {}
    last_end = 0
    for s in tc_streams:
        previous_ends[s.index] = last_end
        last_end = s.compressed_end_offset

    records: list[dict[str, Any]] = []
    for idx in selected:
        s = stream_by_index[idx]
        raw, _ = try_decompress_stream(mobile, s.offset, s.mode)  # type: ignore[misc]
        if raw is None:
            continue
        score = score_stream_against_payload(raw, template_payload)
        chapter = guess_stream_chapter_from_context(mobile, s, previous_ends.get(idx, 0))
        records.append({
            'stream': s,
            'raw': raw,
            'score': score,
            'chapter_guess': chapter,
        })

    if sort_by_score:
        records.sort(key=lambda r: r['score']['same_offset_equal_percent_of_shorter'], reverse=True)
    if max_entries and max_entries > 0:
        records = records[:max_entries]

    entries: list[tuple[str, bytes]] = []
    manifest_records: list[dict[str, Any]] = []
    for out_idx, r in enumerate(records):
        s = r['stream']
        name = f"data{out_idx:04d}.bin"
        chapter = r['chapter_guess'] if patch_titles else ''
        if out_idx < len(title_overrides) and title_overrides[out_idx]:
            chapter = title_overrides[out_idx]
        info = ''
        if patch_titles:
            score_pct = r['score']['same_offset_equal_percent_of_shorter']
            info = f"Converted from mobile stream {s.index}\nScore {score_pct:.6f}%\n"
        date_text = date_overrides[out_idx] if out_idx < len(date_overrides) else ''
        payload = patch_steam_payload_prefix(prefix, chapter=chapter, info=info, date=date_text) + r['raw']
        entries.append((name, payload))
        manifest_records.append({
            'steam_entry_name': name,
            'mobile_stream_index': s.index,
            'mobile_stream_offset': s.offset,
            'decompressed_size': len(r['raw']),
            'chapter_guess': chapter,
            'score_against_template_percent': r['score']['same_offset_equal_percent_of_shorter'],
            'alignment': r['score'],
            'payload_size': len(payload),
        })

    candidate = build_steam_vfs(entries, footer=bytes.fromhex(archive.footer_hex) if archive.footer_hex else STEAM_FOOTER)
    out_path.write_bytes(candidate)
    parsed = parse_steam_vfs_archive(candidate)
    manifest = {
        'warning': 'EXPERIMENTAL. Back up Steam saves and disable Steam Cloud before testing.',
        'mobile_tc': str(mobile_tc),
        'steam_template': str(steam_template),
        'out': str(out_path),
        'out_sha256': sha256(candidate),
        'entry_count': len(entries),
        'parse_ok': len(parsed.entries) == len(entries),
        'footer_hex': parsed.footer_hex,
        'streams_arg': streams_arg,
        'sort_by_score': sort_by_score,
        'prefix_from_template': prefix_from_template,
        'patch_titles': patch_titles,
        'title_overrides': title_overrides,
        'date_overrides': date_overrides,
        'entries': manifest_records,
    }
    out_path.with_suffix(out_path.suffix + '.manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"Wrote multi-slot candidate: {out_path}")
    print(f"Entries: {len(entries)}  parse_ok={manifest['parse_ok']} footer={parsed.footer_hex}")
    print(f"Wrote manifest: {out_path.with_suffix(out_path.suffix + '.manifest.json')}")
    print("Test with backups and Steam Cloud disabled.")
    for rec in manifest_records[:20]:
        print(f"[{rec['steam_entry_name']}] stream={rec['mobile_stream_index']:02d} score={rec['score_against_template_percent']:.6f}% title={rec['chapter_guess']!r}")
    if len(manifest_records) > 20:
        print(f"... {len(manifest_records)-20} more entries in manifest")
    return 0



def load_plan(path: Path) -> list[dict[str, Any]]:
    """Load a build plan from JSON.

    Expected format:
      [
        {"stream": 55, "title": "CHAPTER 0 & 6 Class Trial", "date": "2026-06-17 09:16"},
        {"stream": 54, "title": "Dangan Island Day 6", "date": "2025-07-03 01:38"}
      ]

    Optional per-slot keys: name, prefix, info.
    """
    obj = json.loads(path.read_text(encoding='utf-8'))
    if isinstance(obj, dict):
        obj = obj.get('slots', obj.get('entries', []))
    if not isinstance(obj, list):
        raise ValueError('Plan JSON must be a list, or an object with a slots/entries list')
    plan: list[dict[str, Any]] = []
    for i, item in enumerate(obj):
        if not isinstance(item, dict):
            raise ValueError(f'Plan item {i} is not an object')
        if 'stream' not in item and 'stream_index' not in item:
            raise ValueError(f'Plan item {i} needs a stream or stream_index field')
        stream = int(item.get('stream', item.get('stream_index')))
        plan.append({
            'stream': stream,
            'title': str(item.get('title', item.get('chapter', ''))),
            'date': str(item.get('date', '')),
            'info': str(item.get('info', '')),
            'name': str(item.get('name', f'data{i:04d}.bin')),
            'prefix': item.get('prefix', item.get('prefix_from_template', None)),
        })
    return plan


def build_plan(mobile_tc: Path, steam_template: Path, plan_path: Path, out_path: Path, entry_index: int, prefix_from_template: int, include_gzip: bool = False, dry_run: bool = False) -> int:
    """Build a Steam VFS from an explicit JSON plan.

    This is for recreating the mobile save list once you know which streams map
    to the visible mobile slots. Unlike build-multi, it does not add diagnostic
    info text by default; it only patches title/date/info if provided in the plan.
    """
    mobile = read_file(mobile_tc)
    steam = read_file(steam_template)
    tc_streams = scan_tc_streams(mobile, include_gzip=include_gzip)
    stream_by_index = {s.index: s for s in tc_streams}
    archive = parse_steam_vfs_archive(steam)
    if entry_index >= len(archive.entries):
        raise IndexError(f"Steam entry {entry_index} not found; only {len(archive.entries)} entries found")
    template_entry = archive.entries[entry_index]
    template_payload = steam[template_entry.payload_offset:template_entry.payload_offset + template_entry.size]
    plan = load_plan(plan_path)

    entries: list[tuple[str, bytes]] = []
    manifest_records: list[dict[str, Any]] = []
    for out_idx, slot in enumerate(plan):
        idx = int(slot['stream'])
        if idx not in stream_by_index:
            raise IndexError(f"Stream index {idx} not found; available 0..{len(tc_streams)-1}")
        s = stream_by_index[idx]
        raw, _ = try_decompress_stream(mobile, s.offset, s.mode)  # type: ignore[misc]
        if raw is None:
            raise RuntimeError(f"Stream {idx} failed to decompress")
        prefix_len = prefix_from_template if slot.get('prefix') in (None, '') else int(slot['prefix'])
        if prefix_len < 0 or prefix_len > len(template_payload):
            raise ValueError(f"Bad prefix length {prefix_len} for plan slot {out_idx}")
        title = slot.get('title', '')
        date = slot.get('date', '')
        info = slot.get('info', '')
        prefix = patch_steam_payload_prefix(template_payload[:prefix_len], chapter=title, info=info, date=date)
        payload = prefix + raw
        name = slot.get('name') or f"data{out_idx:04d}.bin"
        entries.append((name, payload))
        score = score_stream_against_payload(raw, template_payload)
        manifest_records.append({
            'steam_entry_name': name,
            'mobile_stream_index': idx,
            'mobile_stream_offset': s.offset,
            'title': title,
            'date': date,
            'info': info,
            'prefix_from_template': prefix_len,
            'payload_size': len(payload),
            'decompressed_size': len(raw),
            'score_against_template_percent': score['same_offset_equal_percent_of_shorter'],
            'first_utf16_text': s.utf16le_strings[0]['text'] if s.utf16le_strings else '',
        })

    candidate = build_steam_vfs(entries, footer=bytes.fromhex(archive.footer_hex) if archive.footer_hex else STEAM_FOOTER)
    parsed = parse_steam_vfs_archive(candidate)
    manifest = {
        'warning': 'EXPERIMENTAL. Back up Steam saves and disable Steam Cloud before testing.',
        'mobile_tc': str(mobile_tc),
        'steam_template': str(steam_template),
        'plan': str(plan_path),
        'out': str(out_path),
        'out_sha256': sha256(candidate),
        'entry_count': len(entries),
        'parse_ok': len(parsed.entries) == len(entries),
        'footer_hex': parsed.footer_hex,
        'default_prefix_from_template': prefix_from_template,
        'entries': manifest_records,
    }
    if not dry_run:
        out_path.write_bytes(candidate)
        out_path.with_suffix(out_path.suffix + '.manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
        print(f"Wrote planned multi-slot candidate: {out_path}")
        print(f"Wrote manifest: {out_path.with_suffix(out_path.suffix + '.manifest.json')}")
    else:
        print('DRY RUN: did not write VFS')
    print(f"Entries: {len(entries)}  parse_ok={manifest['parse_ok']} footer={parsed.footer_hex}")
    for rec in manifest_records:
        print(f"[{rec['steam_entry_name']}] stream={rec['mobile_stream_index']:02d} title={rec['title']!r} date={rec['date']!r} score={rec['score_against_template_percent']:.6f}% text={rec['first_utf16_text'][:50]}")
    return 0

def retitle_vfs(path: Path, out_path: Path, chapter: str, info: str, entry_index: int, prefix_from_template: int, date: str = '') -> int:
    data = read_file(path)
    archive = parse_steam_vfs_archive(data)
    if entry_index >= len(archive.entries):
        raise IndexError(f"Steam entry {entry_index} not found; only {len(archive.entries)} entries found")
    new_entries: list[tuple[str, bytes]] = []
    for e in archive.entries:
        payload = data[e.payload_offset:e.payload_offset + e.size]
        if e.index == entry_index:
            if prefix_from_template > len(payload):
                raise ValueError("prefix_from_template is larger than the selected payload")
            payload = patch_steam_payload_prefix(payload[:prefix_from_template], chapter=chapter, info=info, date=date) + payload[prefix_from_template:]
        new_entries.append((e.name, payload))
    candidate = build_steam_vfs(new_entries, footer=bytes.fromhex(archive.footer_hex) if archive.footer_hex else STEAM_FOOTER)
    out_path.write_bytes(candidate)
    print(f"Wrote retitled VFS: {out_path}")
    print(f"SHA-256: {sha256(candidate)}")
    return 0


def parse_range_list(arg: str) -> list[int]:
    """Parse comma/range list like 700-780:4,716,740."""
    vals: list[int] = []
    for part in (arg or '').split(','):
        part = part.strip()
        if not part:
            continue
        step = 1
        if ':' in part:
            part, step_s = part.split(':', 1)
            step = int(step_s)
            if step <= 0:
                raise ValueError('range step must be positive')
        if '-' in part:
            a, b = part.split('-', 1)
            start = int(a)
            end = int(b)
            if end < start:
                start, end = end, start
            vals.extend(range(start, end + 1, step))
        else:
            vals.append(int(part))
    # preserve order while removing duplicates
    seen = set()
    out = []
    for v in vals:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def prefix_sweep(mobile_tc: Path, steam_template: Path, stream_index: int, out_dir: Path, prefixes_arg: str, entry_index: int = 0, include_gzip: bool = False, title: str = '', date: str = '') -> int:
    """Build single-slot candidates over many prefix lengths.

    This is for the current failure mode: menu/global unlocks can work while
    actual Load returns to the title screen. A sweep lets the user test whether
    Steam needs a different amount of PC slot prefix kept before the mobile body.
    """
    mobile = read_file(mobile_tc)
    steam = read_file(steam_template)
    archive = parse_steam_vfs_archive(steam)
    if entry_index >= len(archive.entries):
        raise IndexError(f"Steam entry {entry_index} not found; only {len(archive.entries)} entries found")
    template_entry = archive.entries[entry_index]
    template_payload = steam[template_entry.payload_offset:template_entry.payload_offset + template_entry.size]
    h, stream_blob = extract_stream_blob(mobile, stream_index, include_gzip=include_gzip)
    prefixes = parse_range_list(prefixes_arg)
    if not prefixes:
        raise ValueError('No prefixes parsed')
    out_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    for prefix in prefixes:
        if prefix < 0 or prefix > len(template_payload):
            continue
        prefix_bytes = template_payload[:prefix]
        if title or date:
            prefix_bytes = patch_steam_payload_prefix(prefix_bytes, chapter=title, date=date)
        payload = prefix_bytes + stream_blob
        # Use one entry only while testing loadability; multi-slot comes later.
        candidate = build_steam_vfs([(template_entry.name, payload)], footer=bytes.fromhex(archive.footer_hex) if archive.footer_hex else STEAM_FOOTER)
        out_path = out_dir / f"savedata_stream{stream_index:02d}_prefix{prefix:03d}.vfs"
        out_path.write_bytes(candidate)
        parsed = parse_steam_vfs_archive(candidate)
        score = compare_blobs(stream_blob, template_payload[prefix:])
        records.append({
            'out': str(out_path),
            'stream_index': stream_index,
            'stream_offset': h.offset,
            'prefix_from_template': prefix,
            'payload_size': len(payload),
            'vfs_size': len(candidate),
            'parse_ok': len(parsed.entries) == 1,
            'score_percent_at_prefix': score['same_offset_equal_percent_of_shorter'],
            'same_size_against_template_suffix': score['same_size'],
            'candidate_sha256': sha256(candidate),
        })
        print(f"Wrote {out_path.name} prefix={prefix} payload={len(payload)} score={score['same_offset_equal_percent_of_shorter']:.6f}%")
    manifest = {
        'warning': 'Test these one at a time as savedata.vfs with Steam Cloud disabled. The goal is to find a candidate whose Load slot actually enters gameplay, not merely unlocks menus.',
        'mobile_tc': str(mobile_tc),
        'steam_template': str(steam_template),
        'stream_index': stream_index,
        'stream': dataclasses.asdict(h),
        'entry_index': entry_index,
        'prefixes_arg': prefixes_arg,
        'title': title,
        'date': date,
        'generated': records,
    }
    (out_dir / 'prefix_sweep_manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"Wrote {out_dir / 'prefix_sweep_manifest.json'}")
    print('Test one candidate at a time. Start with 740, then 716, then nearby values around whichever behaves better.')
    return 0


def clone_template_multi(steam_template: Path, out_path: Path, count: int = 6, entry_index: int = 0, title: str = '') -> int:
    """Make a multi-slot VFS by cloning a known-good Steam payload.

    This is a control test. If this does not load, our archive packaging/name
    assumptions are wrong. If this loads but mobile candidates do not, the
    remaining problem is the mobile body/prefix/checksum, not the VFS archive.
    """
    steam = read_file(steam_template)
    archive = parse_steam_vfs_archive(steam)
    if entry_index >= len(archive.entries):
        raise IndexError(f"Steam entry {entry_index} not found; only {len(archive.entries)} entries found")
    e = archive.entries[entry_index]
    payload0 = steam[e.payload_offset:e.payload_offset + e.size]
    entries: list[tuple[str, bytes]] = []
    for i in range(count):
        payload = payload0
        if title:
            payload = patch_steam_payload_prefix(payload, chapter=f"{title} {i+1}")
        entries.append((f"data{i:04d}.bin", payload))
    candidate = build_steam_vfs(entries, footer=bytes.fromhex(archive.footer_hex) if archive.footer_hex else STEAM_FOOTER)
    out_path.write_bytes(candidate)
    parsed = parse_steam_vfs_archive(candidate)
    manifest = {
        'purpose': 'Control test: clones a known Steam slot into multiple dataXXXX.bin entries.',
        'steam_template': str(steam_template),
        'out': str(out_path),
        'count': count,
        'entry_index_cloned': entry_index,
        'payload_size': len(payload0),
        'parse_ok': len(parsed.entries) == count,
        'out_sha256': sha256(candidate),
    }
    out_path.with_suffix(out_path.suffix + '.manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"Wrote clone control VFS: {out_path}")
    print(f"Entries: {count} parse_ok={manifest['parse_ok']}")
    print(f"Wrote manifest: {out_path.with_suffix(out_path.suffix + '.manifest.json')}")
    return 0



# ---------------- v7 helpers: diagnose Steam Load-vs-Continue failure ----------------

def parse_range_pairs(arg: str) -> list[tuple[int, int]]:
    """Parse ranges like 0x740-0x1740,4096-8192 into [(start,end), ...]."""
    out: list[tuple[int, int]] = []
    for part in (arg or '').split(','):
        part = part.strip()
        if not part:
            continue
        if '-' not in part:
            raise ValueError(f"Range {part!r} must look like start-end")
        a, b = part.split('-', 1)
        start = int(a.strip(), 0)
        end = int(b.strip(), 0)
        if end < start:
            start, end = end, start
        if end == start:
            continue
        out.append((start, end))
    return out


def payload_for_entry(vfs_bytes: bytes, entry_index: int = 0) -> tuple[SteamEntry, bytes, SteamArchive]:
    archive = parse_steam_vfs_archive(vfs_bytes)
    if entry_index >= len(archive.entries):
        raise IndexError(f"Steam entry {entry_index} not found; only {len(archive.entries)} entries found")
    e = archive.entries[entry_index]
    return e, vfs_bytes[e.payload_offset:e.payload_offset + e.size], archive


def differing_ranges(a: bytes, b: bytes, min_run: int = 1) -> list[dict[str, Any]]:
    """Return contiguous ranges where two byte strings differ."""
    n = min(len(a), len(b))
    out: list[dict[str, Any]] = []
    i = 0
    while i < n:
        if a[i] == b[i]:
            i += 1
            continue
        start = i
        while i < n and a[i] != b[i]:
            i += 1
        if i - start >= min_run:
            out.append({
                'start': start,
                'end': i,
                'size': i - start,
                'start_hex': f"0x{start:x}",
                'end_hex': f"0x{i:x}",
                'a_head_hex': a[start:min(i, start + 16)].hex(),
                'b_head_hex': b[start:min(i, start + 16)].hex(),
            })
    if len(a) != len(b):
        out.append({
            'start': n,
            'end': max(len(a), len(b)),
            'size': abs(len(a) - len(b)),
            'start_hex': f"0x{n:x}",
            'end_hex': f"0x{max(len(a), len(b)):x}",
            'length_mismatch': True,
        })
    return out


def diff_vfs(a_vfs: Path, b_vfs: Path, json_out: Optional[Path] = None, entry_index: int = 0, min_run: int = 1) -> int:
    """Compare two VFS payloads at the same entry index."""
    a_data = read_file(a_vfs)
    b_data = read_file(b_vfs)
    a_entry, a_payload, a_archive = payload_for_entry(a_data, entry_index)
    b_entry, b_payload, b_archive = payload_for_entry(b_data, entry_index)
    comp = compare_blobs(a_payload, b_payload)
    ranges = differing_ranges(a_payload, b_payload, min_run=min_run)
    result = {
        'a_vfs': str(a_vfs),
        'b_vfs': str(b_vfs),
        'entry_index': entry_index,
        'a_entry': dataclasses.asdict(a_entry),
        'b_entry': dataclasses.asdict(b_entry),
        'a_entry_count': len(a_archive.entries),
        'b_entry_count': len(b_archive.entries),
        'comparison': comp,
        'differing_range_count': len(ranges),
        'differing_ranges': ranges[:10000],
    }
    print(f"A: {a_vfs} entry {entry_index} size={len(a_payload)} sha256={sha256(a_payload)}")
    print(f"B: {b_vfs} entry {entry_index} size={len(b_payload)} sha256={sha256(b_payload)}")
    print(f"Equal bytes at same offsets: {comp['same_offset_equal_percent_of_shorter']}%")
    print(f"Differing ranges: {len(ranges)}")
    for r in ranges[:30]:
        print(f"  {r['start_hex']}-{r['end_hex']} size={r['size']}")
    if len(ranges) > 30:
        print(f"  ... {len(ranges)-30} more in JSON")
    if json_out:
        json_out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
        print(f"Wrote {json_out}")
    return 0


def build_payload_from_mobile_stream(mobile: bytes, steam_template_payload: bytes, stream_index: int, prefix_from_template: int, include_gzip: bool = False, title: str = '', date: str = '') -> tuple[StreamHit, bytes]:
    h, stream_blob = extract_stream_blob_from_bytes(mobile, stream_index, include_gzip=include_gzip)
    if prefix_from_template < 0 or prefix_from_template > len(steam_template_payload):
        raise ValueError('prefix_from_template is outside the target Steam payload')
    prefix = steam_template_payload[:prefix_from_template]
    if title or date:
        prefix = patch_steam_payload_prefix(prefix, chapter=title, date=date)
    return h, prefix + stream_blob


def extract_stream_blob_from_bytes(data: bytes, stream_index: int, include_gzip: bool = False) -> tuple[StreamHit, bytes]:
    streams = scan_tc_streams(data, include_gzip=include_gzip)
    if stream_index >= len(streams):
        raise IndexError(f"stream index {stream_index} not found; only {len(streams)} stream(s) found")
    h = streams[stream_index]
    result = try_decompress_stream(data, h.offset, h.mode)
    if result is None:
        raise RuntimeError(f"stream {stream_index} no longer decompresses")
    raw, _ = result
    return h, raw


def restore_ranges_build(mobile_tc: Path, steam_template: Path, out_path: Path, stream_index: int, ranges_arg: str, donor_vfs: Optional[Path] = None, entry_index: int = 0, prefix_from_template: int = 740, include_gzip: bool = False, title: str = '', date: str = '') -> int:
    """Build one candidate, but restore specified payload byte ranges from a Steam donor.

    This is meant for the current failure mode: the converted payload can seed Continue,
    but the Steam Load path bounces to main menu. Restoring small PC-native regions
    can identify/load-repair fields without throwing away the whole mobile body.
    """
    mobile = read_file(mobile_tc)
    steam = read_file(steam_template)
    template_entry, template_payload, template_archive = payload_for_entry(steam, entry_index)
    donor = read_file(donor_vfs) if donor_vfs else steam
    donor_entry, donor_payload, _ = payload_for_entry(donor, entry_index)
    h, payload = build_payload_from_mobile_stream(mobile, template_payload, stream_index, prefix_from_template, include_gzip=include_gzip, title=title, date=date)
    payload_b = bytearray(payload)
    ranges = parse_range_pairs(ranges_arg)
    restored: list[dict[str, Any]] = []
    for start, end in ranges:
        s = max(0, start)
        e = min(len(payload_b), end, len(donor_payload))
        if e <= s:
            continue
        payload_b[s:e] = donor_payload[s:e]
        restored.append({'start': s, 'end': e, 'size': e - s, 'start_hex': f"0x{s:x}", 'end_hex': f"0x{e:x}"})
    candidate = build_steam_vfs([(template_entry.name, bytes(payload_b))], footer=bytes.fromhex(template_archive.footer_hex) if template_archive.footer_hex else STEAM_FOOTER)
    out_path.write_bytes(candidate)
    parsed = parse_steam_vfs_archive(candidate)
    manifest = {
        'warning': 'EXPERIMENTAL load-repair candidate. Test as savedata.vfs with Steam Cloud disabled and backups made.',
        'mobile_tc': str(mobile_tc),
        'steam_template': str(steam_template),
        'donor_vfs': str(donor_vfs) if donor_vfs else str(steam_template),
        'out': str(out_path),
        'stream_index': stream_index,
        'stream': dataclasses.asdict(h),
        'prefix_from_template': prefix_from_template,
        'entry_index': entry_index,
        'restored_ranges': restored,
        'payload_size': len(payload_b),
        'vfs_size': len(candidate),
        'parse_ok': len(parsed.entries) == 1,
        'out_sha256': sha256(candidate),
    }
    out_path.with_suffix(out_path.suffix + '.manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"Wrote restore-ranges candidate: {out_path}")
    print(f"Restored {len(restored)} range(s) from {donor_vfs or steam_template}")
    for r in restored:
        print(f"  {r['start_hex']}-{r['end_hex']} size={r['size']}")
    print(f"Wrote manifest: {out_path.with_suffix(out_path.suffix + '.manifest.json')}")
    return 0


def restore_window_sweep(mobile_tc: Path, steam_template: Path, out_dir: Path, stream_index: int, donor_vfs: Optional[Path] = None, entry_index: int = 0, prefix_from_template: int = 740, include_gzip: bool = False, start: int = 740, end: int = 0, window_size: int = 4096, step: int = 4096, title: str = '', date: str = '', limit: int = 0) -> int:
    """Generate candidates where one window is restored from a PC donor payload.

    Use this to hunt for the PC-specific region that makes Steam's Load handler
    bounce to the main menu. Start coarse, then narrow around any window that
    changes behavior.
    """
    if window_size <= 0 or step <= 0:
        raise ValueError('window-size and step must be positive')
    mobile = read_file(mobile_tc)
    steam = read_file(steam_template)
    template_entry, template_payload, template_archive = payload_for_entry(steam, entry_index)
    donor = read_file(donor_vfs) if donor_vfs else steam
    donor_entry, donor_payload, _ = payload_for_entry(donor, entry_index)
    h, base_payload = build_payload_from_mobile_stream(mobile, template_payload, stream_index, prefix_from_template, include_gzip=include_gzip, title=title, date=date)
    max_end = min(len(base_payload), len(donor_payload))
    if end <= 0 or end > max_end:
        end = max_end
    start = max(0, min(start, max_end))
    out_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    count = 0
    for s in range(start, end, step):
        e = min(s + window_size, end)
        if e <= s:
            continue
        payload_b = bytearray(base_payload)
        payload_b[s:e] = donor_payload[s:e]
        candidate = build_steam_vfs([(template_entry.name, bytes(payload_b))], footer=bytes.fromhex(template_archive.footer_hex) if template_archive.footer_hex else STEAM_FOOTER)
        out_path = out_dir / f"savedata_stream{stream_index:02d}_restore_{s:06x}_{e:06x}.vfs"
        out_path.write_bytes(candidate)
        records.append({
            'out': str(out_path),
            'restore_start': s,
            'restore_end': e,
            'restore_size': e - s,
            'restore_start_hex': f"0x{s:x}",
            'restore_end_hex': f"0x{e:x}",
            'payload_size': len(payload_b),
            'vfs_size': len(candidate),
            'candidate_sha256': sha256(candidate),
        })
        print(f"Wrote {out_path.name} restore={s:#x}-{e:#x}")
        count += 1
        if limit and count >= limit:
            break
    manifest = {
        'warning': 'Test candidates one at a time as savedata.vfs. If one changes Load behavior, run a narrower sweep around that restore range.',
        'mobile_tc': str(mobile_tc),
        'steam_template': str(steam_template),
        'donor_vfs': str(donor_vfs) if donor_vfs else str(steam_template),
        'stream_index': stream_index,
        'stream': dataclasses.asdict(h),
        'entry_index': entry_index,
        'prefix_from_template': prefix_from_template,
        'start': start,
        'end': end,
        'window_size': window_size,
        'step': step,
        'generated_count': len(records),
        'generated': records,
    }
    (out_dir / 'restore_window_sweep_manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"Wrote {out_dir / 'restore_window_sweep_manifest.json'}")
    return 0


def transplant_ranges_between_vfs(target_vfs: Path, donor_vfs: Path, out_path: Path, ranges_arg: str, entry_index: int = 0) -> int:
    """Copy byte ranges from a donor VFS payload into a target VFS payload."""
    target = read_file(target_vfs)
    donor = read_file(donor_vfs)
    target_archive = parse_steam_vfs_archive(target)
    if entry_index >= len(target_archive.entries):
        raise IndexError(f"Target entry {entry_index} not found; only {len(target_archive.entries)} entries found")
    donor_entry, donor_payload, _ = payload_for_entry(donor, entry_index)
    new_entries: list[tuple[str, bytes]] = []
    restored: list[dict[str, Any]] = []
    ranges = parse_range_pairs(ranges_arg)
    for e in target_archive.entries:
        payload = bytearray(target[e.payload_offset:e.payload_offset + e.size])
        if e.index == entry_index:
            for start, end in ranges:
                s = max(0, start)
                ee = min(len(payload), end, len(donor_payload))
                if ee <= s:
                    continue
                payload[s:ee] = donor_payload[s:ee]
                restored.append({'start': s, 'end': ee, 'size': ee-s, 'start_hex': f"0x{s:x}", 'end_hex': f"0x{ee:x}"})
        new_entries.append((e.name, bytes(payload)))
    candidate = build_steam_vfs(new_entries, footer=bytes.fromhex(target_archive.footer_hex) if target_archive.footer_hex else STEAM_FOOTER)
    out_path.write_bytes(candidate)
    manifest = {
        'target_vfs': str(target_vfs),
        'donor_vfs': str(donor_vfs),
        'out': str(out_path),
        'entry_index': entry_index,
        'restored_ranges': restored,
        'out_sha256': sha256(candidate),
    }
    out_path.with_suffix(out_path.suffix + '.manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"Wrote transplanted VFS: {out_path}")
    print(f"Wrote manifest: {out_path.with_suffix(out_path.suffix + '.manifest.json')}")
    return 0


# ---------------- v8 helpers: postgame unlock / mobile donor experiments ----------------

def make_single_stream_vfs_from_raw(
    steam_template_bytes: bytes,
    raw_stream: bytes,
    out_path: Path,
    entry_index: int = 0,
    prefix_from_template: int = 740,
    title: str = '',
    date: str = '',
) -> dict[str, Any]:
    archive = parse_steam_vfs_archive(steam_template_bytes)
    if entry_index >= len(archive.entries):
        raise IndexError(f"Steam entry {entry_index} not found; only {len(archive.entries)} entries found")
    new_entries: list[tuple[str, bytes]] = []
    for e in archive.entries:
        payload = steam_template_bytes[e.payload_offset:e.payload_offset + e.size]
        if e.index == entry_index:
            prefix = payload[:prefix_from_template]
            if title or date:
                prefix = patch_steam_payload_prefix(prefix, chapter=title, date=date)
            payload = prefix + raw_stream
        new_entries.append((e.name, payload))
    candidate = build_steam_vfs(new_entries, footer=bytes.fromhex(archive.footer_hex) if archive.footer_hex else STEAM_FOOTER)
    out_path.write_bytes(candidate)
    notes = {
        "out": str(out_path),
        "candidate_sha256": sha256(candidate),
        "entry_index": entry_index,
        "prefix_from_template": prefix_from_template,
        "title": title,
        "date": date,
        "parse_ok": len(parse_steam_vfs_archive(candidate).entries) == len(archive.entries),
    }
    out_path.with_suffix(out_path.suffix + '.notes.json').write_text(json.dumps(notes, indent=2, ensure_ascii=False), encoding='utf-8')
    return notes


def postgame_candidates(
    mobile_tc: Path,
    steam_template: Path,
    out_dir: Path,
    streams_arg: str = '50-54',
    prefixes_arg: str = '740,716',
    entry_index: int = 0,
    include_gzip: bool = False,
) -> int:
    mobile = read_file(mobile_tc)
    steam = read_file(steam_template)
    streams = scan_tc_streams(mobile, include_gzip=include_gzip)
    selected_indices = parse_int_list(streams_arg) if streams_arg != 'all' else [s.index for s in streams]
    prefixes = parse_range_list(prefixes_arg)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        'mobile_tc': str(mobile_tc),
        'steam_template': str(steam_template),
        'streams_arg': streams_arg,
        'prefixes_arg': prefixes_arg,
        'generated': [],
    }
    for idx in selected_indices:
        if idx < 0 or idx >= len(streams):
            print(f"Skipping missing stream {idx}; only {len(streams)} streams exist")
            continue
        hit, raw = extract_stream_blob_from_bytes(mobile, idx, include_gzip=include_gzip)
        title = guess_stream_chapter_from_context(mobile, hit)
        first_text = hit.utf16le_strings[0]['text'] if hit.utf16le_strings else ''
        for prefix in prefixes:
            out_path = out_dir / f"savedata_direct_stream{idx:02d}_prefix{prefix}.vfs"
            notes = make_single_stream_vfs_from_raw(
                steam, raw, out_path, entry_index=entry_index,
                prefix_from_template=prefix, title=title or f"STREAM {idx:02d}",
            )
            notes.update({
                'kind': 'direct_stream',
                'stream_index': idx,
                'stream_offset_hex': hex(hit.offset),
                'stream_title_guess': title,
                'first_utf16_text': first_text,
                'decompressed_size': len(raw),
            })
            out_path.with_suffix(out_path.suffix + '.notes.json').write_text(json.dumps(notes, indent=2, ensure_ascii=False), encoding='utf-8')
            manifest['generated'].append(notes)
            print(f"Wrote {out_path.name}  title={title!r}  first_text={first_text[:55]!r}")
    (out_dir / 'postgame_candidate_manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"Wrote {out_dir / 'postgame_candidate_manifest.json'}")
    return 0


def mobile_donor_ranges(
    mobile_tc: Path,
    steam_template: Path,
    out_path: Path,
    base_stream: int = 47,
    donor_stream: int = 51,
    ranges_arg: str = '',
    entry_index: int = 0,
    prefix_from_template: int = 740,
    include_gzip: bool = False,
    title: str = '',
    date: str = '',
) -> int:
    if not ranges_arg:
        raise ValueError('--ranges is required, e.g. 0x10000-0x11000,0x2f000-0x30000')
    mobile = read_file(mobile_tc)
    steam = read_file(steam_template)
    base_hit, base_raw = extract_stream_blob_from_bytes(mobile, base_stream, include_gzip=include_gzip)
    donor_hit, donor_raw = extract_stream_blob_from_bytes(mobile, donor_stream, include_gzip=include_gzip)
    patched = bytearray(base_raw)
    ranges = parse_range_pairs(ranges_arg)
    for start, end in ranges:
        if start < 0 or end < start:
            raise ValueError(f'Bad range {start}-{end}')
        e = min(end, len(patched), len(donor_raw))
        if start >= e:
            continue
        patched[start:e] = donor_raw[start:e]
    label = title or f"B{base_stream:02d}_D{donor_stream:02d}"
    notes = make_single_stream_vfs_from_raw(
        steam, bytes(patched), out_path, entry_index=entry_index,
        prefix_from_template=prefix_from_template, title=label, date=date,
    )
    notes.update({
        'kind': 'mobile_donor_ranges',
        'base_stream': base_stream,
        'donor_stream': donor_stream,
        'base_title_guess': guess_stream_chapter_from_context(mobile, base_hit),
        'donor_title_guess': guess_stream_chapter_from_context(mobile, donor_hit),
        'ranges': [{'start': s0, 'end': e0, 'start_hex': hex(s0), 'end_hex': hex(e0)} for s0, e0 in ranges],
        'raw_length': len(patched),
    })
    out_path.with_suffix(out_path.suffix + '.notes.json').write_text(json.dumps(notes, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"Wrote {out_path}")
    print(f"Base stream {base_stream}; donor stream {donor_stream}; ranges {ranges_arg}")
    return 0


def mobile_donor_window_sweep(
    mobile_tc: Path,
    steam_template: Path,
    out_dir: Path,
    base_stream: int = 47,
    donor_stream: int = 51,
    entry_index: int = 0,
    prefix_from_template: int = 740,
    include_gzip: bool = False,
    start: int = 0,
    end: int = 0,
    window_size: int = 0x1000,
    step: int = 0x1000,
    title: str = '',
    date: str = '',
    limit: int = 0,
) -> int:
    mobile = read_file(mobile_tc)
    steam = read_file(steam_template)
    base_hit, base_raw = extract_stream_blob_from_bytes(mobile, base_stream, include_gzip=include_gzip)
    donor_hit, donor_raw = extract_stream_blob_from_bytes(mobile, donor_stream, include_gzip=include_gzip)
    n = min(len(base_raw), len(donor_raw))
    if end <= 0 or end > n:
        end = n
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        'mobile_tc': str(mobile_tc),
        'steam_template': str(steam_template),
        'base_stream': base_stream,
        'donor_stream': donor_stream,
        'base_title_guess': guess_stream_chapter_from_context(mobile, base_hit),
        'donor_title_guess': guess_stream_chapter_from_context(mobile, donor_hit),
        'prefix_from_template': prefix_from_template,
        'start': start,
        'end': end,
        'window_size': window_size,
        'step': step,
        'generated': [],
    }
    count = 0
    for off in range(start, end, step):
        if limit and count >= limit:
            break
        win_end = min(off + window_size, n)
        if off >= win_end:
            continue
        patched = bytearray(base_raw)
        patched[off:win_end] = donor_raw[off:win_end]
        label = title or f"B{base_stream:02d}D{donor_stream:02d}_{off:05x}"
        out_path = out_dir / f"savedata_b{base_stream:02d}_d{donor_stream:02d}_raw_{off:05x}_{win_end:05x}.vfs"
        notes = make_single_stream_vfs_from_raw(
            steam, bytes(patched), out_path, entry_index=entry_index,
            prefix_from_template=prefix_from_template, title=label, date=date,
        )
        rec = {
            'out': str(out_path),
            'start': off,
            'end': win_end,
            'start_hex': hex(off),
            'end_hex': hex(win_end),
            'candidate_sha256': notes['candidate_sha256'],
        }
        out_path.with_suffix(out_path.suffix + '.notes.json').write_text(json.dumps({**notes, **rec, 'base_stream': base_stream, 'donor_stream': donor_stream}, indent=2, ensure_ascii=False), encoding='utf-8')
        manifest['generated'].append(rec)
        count += 1
        print(f"Wrote {out_path.name} raw[{hex(off)}:{hex(win_end)}]")
    (out_dir / 'mobile_donor_window_sweep_manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"Wrote {out_dir / 'mobile_donor_window_sweep_manifest.json'}")
    return 0



# ---------------- user-friendly final workflow ----------------

def _now_stamp() -> str:
    return _datetime.datetime.now().strftime('%Y%m%d_%H%M%S')


def _short_title_for_filename(title: str) -> str:
    title = title or 'untitled'
    return safe_filename(title.replace('&', 'and'))[:48]


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8', newline='\n')


def _copy_candidate(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        dst.unlink()
    shutil.copy2(src, dst)
    notes = src.with_suffix(src.suffix + '.notes.json')
    if notes.exists():
        shutil.copy2(notes, dst.with_suffix(dst.suffix + '.notes.json'))


def analyze_mobile_streams_for_auto(mobile: bytes, steam: bytes, entry_index: int, prefix: int, include_gzip: bool = False) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    archive = parse_steam_vfs_archive(steam)
    if entry_index >= len(archive.entries):
        raise IndexError(f"Steam entry {entry_index} not found; only {len(archive.entries)} entries found")
    template_entry = archive.entries[entry_index]
    template_payload = steam[template_entry.payload_offset:template_entry.payload_offset + template_entry.size]
    streams = scan_tc_streams(mobile, include_gzip=include_gzip)
    pngs = extract_png_ranges(mobile)

    previous_ends: dict[int, int] = {}
    last_end = 0
    for s in streams:
        previous_ends[s.index] = last_end
        last_end = s.compressed_end_offset

    rows: list[dict[str, Any]] = []
    expected_raw_len = max(0, len(template_payload) - prefix)
    for pos, s in enumerate(streams):
        raw, _ = try_decompress_stream(mobile, s.offset, s.mode)  # type: ignore[misc]
        if raw is None:
            continue
        # Keep the wider prefix scan for reporting, but candidates are built with the tested default prefix.
        score = score_stream_against_payload(raw, template_payload)
        title = guess_stream_chapter_from_context(mobile, s, previous_ends.get(s.index, 0))
        next_off = streams[pos + 1].offset if pos + 1 < len(streams) else None
        png = find_png_after_stream(pngs, s, next_off)
        first_utf16 = s.utf16le_strings[0]['text'] if s.utf16le_strings else ''
        score_pct = score.get('same_offset_equal_percent_of_shorter', 0.0) or 0.0
        best_prefix = score.get('steam_prefix_removed')
        length_delta = abs(len(raw) - expected_raw_len)
        title_l = title.lower()
        first_l = first_utf16.lower()
        tags: list[str] = []
        if 'dangan island' in title_l:
            tags.append('dangan-island')
        if 'epilogue' in title_l:
            tags.append('epilogue')
        if 'end' in title_l:
            tags.append('end')
        if 'chapter' in title_l:
            tags.append('chapter')
        if 'danganronpa if' in first_l or 'novel' in first_l:
            tags.append('novel-hint')
        if png is not None:
            tags.append('has-thumbnail')
        if length_delta <= 4096:
            tags.append('steam-sized')
        rows.append({
            'stream_index': s.index,
            'offset': s.offset,
            'offset_hex': hex(s.offset),
            'mode': s.mode,
            'compressed_size': s.compressed_size,
            'decompressed_size': len(raw),
            'expected_raw_size_for_prefix': expected_raw_len,
            'length_delta_vs_prefix': length_delta,
            'title_guess': title,
            'first_utf16_text': first_utf16[:160],
            'has_following_png_before_next_stream': png is not None,
            'following_png_offset_hex': f"0x{png['offset']:x}" if png else '',
            'score_against_template_percent': score_pct,
            'best_detected_prefix': best_prefix,
            'tags': tags,
            '_hit': s,
            '_raw': raw,
        })

    meta = {
        'steam_entry_index': entry_index,
        'steam_entry_name': template_entry.name,
        'steam_entry_size': template_entry.size,
        'steam_template_payload_size': len(template_payload),
        'prefix_used_for_candidates': prefix,
        'expected_mobile_raw_size': expected_raw_len,
        'stream_count': len(streams),
        'png_count': len(pngs),
    }
    return rows, meta


def _candidate_sort_key(row: dict[str, Any]) -> tuple[int, int, float, int]:
    # Higher is better. This is for likely candidates, not a guarantee.
    tags = set(row.get('tags', []))
    score = float(row.get('score_against_template_percent') or 0.0)
    bonus = 0
    if 'steam-sized' in tags:
        bonus += 20
    if row.get('title_guess'):
        bonus += 5
    if 'has-thumbnail' in tags:
        bonus += 3
    if 'epilogue' in tags or 'end' in tags or 'dangan-island' in tags:
        bonus += 4
    return (bonus, int(row['stream_index']), score, -int(row.get('length_delta_vs_prefix') or 0))


def auto_convert(mobile_tc: Path, steam_template: Path, out_dir: Optional[Path] = None, entry_index: int = 0, prefix: int = 740, include_gzip: bool = False, all_candidates: bool = True, top: int = 12) -> int:
    """User-friendly conversion flow.

    It generates candidate Steam savedata.vfs files from every plausible mobile
    stream, plus a small try_first folder. Users test one file at a time.
    """
    mobile_tc = mobile_tc.expanduser().resolve()
    steam_template = steam_template.expanduser().resolve()
    if out_dir is None:
        out_dir = Path.cwd() / f'dr2_converted_candidates_{_now_stamp()}'
    else:
        out_dir = out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = out_dir / 'reports'
    all_dir = out_dir / 'all_candidates'
    try_dir = out_dir / 'try_first'
    reports_dir.mkdir(parents=True, exist_ok=True)
    all_dir.mkdir(parents=True, exist_ok=True)
    try_dir.mkdir(parents=True, exist_ok=True)

    mobile = read_file(mobile_tc)
    steam = read_file(steam_template)
    rows, meta = analyze_mobile_streams_for_auto(mobile, steam, entry_index, prefix, include_gzip=include_gzip)
    if not rows:
        raise ValueError('No usable compressed save streams were found in the mobile savedata.tc')

    # Write reports first.
    json_rows = []
    for r in rows:
        rr = {k: v for k, v in r.items() if not k.startswith('_')}
        json_rows.append(rr)
    result_json = {
        'warning': 'Experimental community converter. Back up Steam saves and disable Steam Cloud before testing.',
        'mobile_tc': str(mobile_tc),
        'mobile_sha256': sha256(mobile),
        'steam_template': str(steam_template),
        'steam_template_sha256': sha256(steam),
        'out_dir': str(out_dir),
        **meta,
        'streams': json_rows,
    }
    (reports_dir / 'stream_report.json').write_text(json.dumps(result_json, indent=2, ensure_ascii=False), encoding='utf-8')
    with (reports_dir / 'stream_report.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['stream_index', 'title_guess', 'score_against_template_percent', 'best_detected_prefix', 'decompressed_size', 'length_delta_vs_prefix', 'has_following_png_before_next_stream', 'tags', 'first_utf16_text']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in json_rows:
            row = {k: r.get(k, '') for k in fieldnames}
            row['tags'] = ','.join(r.get('tags', []))
            w.writerow(row)

    # Build candidate files.
    archive = parse_steam_vfs_archive(steam)
    template_payload = steam[archive.entries[entry_index].payload_offset:archive.entries[entry_index].payload_offset + archive.entries[entry_index].size]
    footer = bytes.fromhex(archive.footer_hex) if archive.footer_hex else STEAM_FOOTER
    generated: list[dict[str, Any]] = []
    for r in rows:
        idx = int(r['stream_index'])
        title = r.get('title_guess') or f'Mobile stream {idx:02d}'
        info = f"Converted from mobile stream {idx}\nScore {float(r.get('score_against_template_percent') or 0.0):.6f}%\nPrefix {prefix}\n"
        prefix_bytes = patch_steam_payload_prefix(template_payload[:prefix], chapter=title, info=info)
        payload = prefix_bytes + r['_raw']
        entry_name = archive.entries[entry_index].name
        candidate = build_steam_vfs([(entry_name, payload)], footer=footer)
        filename = f"savedata_stream{idx:02d}_prefix{prefix}_{_short_title_for_filename(title)}.vfs"
        out_path = all_dir / filename
        out_path.write_bytes(candidate)
        rec = {k: v for k, v in r.items() if not k.startswith('_')}
        rec.update({
            'candidate_file': str(out_path.relative_to(out_dir)),
            'candidate_sha256': sha256(candidate),
            'prefix_used': prefix,
            'steam_entry_name': entry_name,
            'payload_size': len(payload),
        })
        out_path.with_suffix(out_path.suffix + '.notes.json').write_text(json.dumps(rec, indent=2, ensure_ascii=False), encoding='utf-8')
        generated.append(rec)

    # Pick convenient try-first candidates. Duplicates are skipped.
    by_idx = {int(r['stream_index']): r for r in generated}
    picked: list[tuple[str, dict[str, Any]]] = []
    def pick(label: str, pred) -> None:
        candidates = [r for r in generated if pred(r)]
        if not candidates:
            return
        # Label decides sort behavior.
        if 'best_score' in label:
            chosen = max(candidates, key=lambda r: float(r.get('score_against_template_percent') or 0.0))
        elif 'latest' in label:
            chosen = max(candidates, key=lambda r: int(r['stream_index']))
        else:
            chosen = max(candidates, key=_candidate_sort_key)
        if int(chosen['stream_index']) not in [int(x[1]['stream_index']) for x in picked]:
            picked.append((label, chosen))

    pick('best_score', lambda r: True)
    pick('best_epilogue_or_end', lambda r: any(t in r.get('tags', []) for t in ['epilogue', 'end', 'novel-hint']))
    pick('latest_dangan_island', lambda r: 'dangan-island' in r.get('tags', []))
    pick('latest_titled_stream', lambda r: bool(r.get('title_guess')))
    pick('latest_steam_sized_stream', lambda r: 'steam-sized' in r.get('tags', []))

    # Add top-N by score as fallback.
    top_by_score = sorted(generated, key=lambda r: float(r.get('score_against_template_percent') or 0.0), reverse=True)[:max(0, top)]
    for r in top_by_score:
        if int(r['stream_index']) not in [int(x[1]['stream_index']) for x in picked]:
            picked.append((f'top_score_{len(picked)+1:02d}', r))

    picked_manifest: list[dict[str, Any]] = []
    for n, (label, r) in enumerate(picked, start=1):
        src = out_dir / r['candidate_file']
        title = r.get('title_guess') or 'untitled'
        dst = try_dir / f"{n:02d}_{label}_stream{int(r['stream_index']):02d}_{_short_title_for_filename(title)}.vfs"
        _copy_candidate(src, dst)
        rr = dict(r)
        rr['try_first_file'] = str(dst.relative_to(out_dir))
        rr['try_first_reason'] = label
        picked_manifest.append(rr)

    (reports_dir / 'generated_manifest.json').write_text(json.dumps({'generated': generated, 'try_first': picked_manifest}, indent=2, ensure_ascii=False), encoding='utf-8')

    results_text = f"""
Danganronpa 2 Mobile -> Steam conversion results
================================================

Input mobile save:
  {mobile_tc}
Input fresh Steam template:
  {steam_template}

Output folder:
  {out_dir}

What was generated:
  try_first/        Small set of candidates to test first.
  all_candidates/   Candidate for every detected mobile stream.
  reports/          CSV/JSON reports showing stream numbers, guessed titles, scores, and notes.

How to test safely:
  1. Back up Steam's savedata.vfs, savedata.bak, and savedata.tmp.
  2. Disable Steam Cloud for Danganronpa 2 while testing.
  3. Pick ONE candidate .vfs from try_first/.
  4. Copy it into the Steam save folder.
  5. Rename it exactly to savedata.vfs.
  6. Launch the game and try Load/Continue.

Recommended testing order:
""".lstrip()
    for rec in picked_manifest:
        results_text += f"  - {rec['try_first_file']}\n"
        results_text += f"      stream {rec['stream_index']} | title: {rec.get('title_guess') or '(unknown)'} | score: {float(rec.get('score_against_template_percent') or 0.0):.6f}% | reason: {rec['try_first_reason']}\n"
    results_text += """
Notes:
  - A high score is not always the final/latest save. In one verified case, the best-score stream loaded the epilogue, while a later Dangan Island stream contained the final postgame unlocks.
  - If the first candidate loads but is missing Island Mode or Novel, try a later EPILOGUE/END/Dangan Island candidate.
  - Once a candidate works, save once inside the Steam version and back up the newly written Steam save.
"""
    _write_text(out_dir / 'READ_ME_FIRST_RESULTS.txt', results_text)

    print('\nDone. Candidate files were created.')
    print(f'Output folder: {out_dir}')
    print(f'Read this next: {out_dir / "READ_ME_FIRST_RESULTS.txt"}')
    print('\nTry-first candidates:')
    for rec in picked_manifest[:20]:
        print(f"  {rec['try_first_file']}  (stream {rec['stream_index']}, {rec.get('title_guess') or 'unknown'})")
    print('\nRemember: back up Steam saves and disable Steam Cloud before testing.')
    return 0


def interactive_wizard() -> int:
    print('Danganronpa 2 Mobile -> Steam Save Converter')
    print('------------------------------------------------')
    print('This will create candidate Steam savedata.vfs files. It will not modify your input files.\n')
    default_tc = Path('savedata.tc')
    default_vfs = Path('fresh_savedata.vfs') if Path('fresh_savedata.vfs').exists() else Path('savedata.vfs')
    tc_in = input(f'Mobile savedata.tc path [{default_tc}]: ').strip().strip('"') or str(default_tc)
    vfs_in = input(f'Fresh Steam savedata.vfs template path [{default_vfs}]: ').strip().strip('"') or str(default_vfs)
    out_in = input('Output folder [auto]: ').strip().strip('"')
    prefix_in = input('Prefix to use [740]: ').strip()
    prefix = int(prefix_in, 0) if prefix_in else 740
    out_dir = Path(out_in) if out_in else None
    print('\nWorking... this may take a minute.\n')
    return auto_convert(Path(tc_in), Path(vfs_in), out_dir=out_dir, prefix=prefix)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Danganronpa 2 Mobile -> Steam save converter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Easiest workflow:

          python dr2_mobile_to_steam.py auto savedata.tc fresh_savedata.vfs

        Or launch the interactive wizard:

          python dr2_mobile_to_steam.py wizard

        The tool creates a folder with try_first/ and all_candidates/.
        Test one .vfs at a time by renaming it to savedata.vfs in the Steam save folder.

        Candidate files are experimental. Back up savedata.vfs, savedata.bak, and savedata.tmp.
        Disable Steam Cloud before replacing anything.
        """),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("auto", help="User-friendly workflow: generate try-first and all conversion candidates")
    p.add_argument("mobile_tc", help="Mobile savedata.tc")
    p.add_argument("steam_template", help="Fresh Steam savedata.vfs template")
    p.add_argument("--out-dir", help="Output folder; default creates a timestamped folder")
    p.add_argument("--entry-index", type=int, default=0)
    p.add_argument("--prefix", type=int, default=740, help="Steam prefix bytes to keep from template; 740 is the known-good default")
    p.add_argument("--top", type=int, default=12, help="How many top-score fallbacks to copy into try_first")
    p.add_argument("--include-gzip", action="store_true")
    p.set_defaults(func=lambda a: auto_convert(Path(a.mobile_tc), Path(a.steam_template), out_dir=Path(a.out_dir) if a.out_dir else None, entry_index=a.entry_index, prefix=a.prefix, include_gzip=a.include_gzip, top=a.top))

    p = sub.add_parser("wizard", help="Interactive Windows-friendly wizard")
    p.set_defaults(func=lambda a: interactive_wizard())

    p = sub.add_parser("report", help="Create a general report for a file")
    p.add_argument("file")
    p.add_argument("--out")
    p.add_argument("--json")
    p.set_defaults(func=lambda a: report(Path(a.file), Path(a.out) if a.out else None, Path(a.json) if a.json else None))

    p = sub.add_parser("steam-list", help="Parse and list a Steam savedata.vfs")
    p.add_argument("vfs")
    p.add_argument("--json")
    p.set_defaults(func=lambda a: steam_list(Path(a.vfs), Path(a.json) if a.json else None))

    p = sub.add_parser("steam-extract", help="Extract Steam VFS entries to files")
    p.add_argument("vfs")
    p.add_argument("--out-dir", required=True)
    p.set_defaults(func=lambda a: steam_extract(Path(a.vfs), Path(a.out_dir)))

    p = sub.add_parser("steam-roundtrip", help="Parse and rebuild a Steam VFS to validate the parser")
    p.add_argument("vfs")
    p.add_argument("--out", required=True)
    p.set_defaults(func=lambda a: steam_roundtrip(Path(a.vfs), Path(a.out)))

    p = sub.add_parser("tc-list", help="List compressed streams in a mobile savedata.tc")
    p.add_argument("tc")
    p.add_argument("--json")
    p.add_argument("--include-gzip", action="store_true")
    p.set_defaults(func=lambda a: tc_list(Path(a.tc), Path(a.json) if a.json else None, include_gzip=a.include_gzip))

    p = sub.add_parser("tc-extract", help="Extract zlib streams and PNGs from a mobile savedata.tc")
    p.add_argument("tc")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--include-gzip", action="store_true")
    p.set_defaults(func=lambda a: tc_extract(Path(a.tc), Path(a.out_dir), include_gzip=a.include_gzip))

    p = sub.add_parser("score-streams", help="Rank mobile streams against a Steam VFS slot")
    p.add_argument("tc")
    p.add_argument("vfs")
    p.add_argument("--entry-index", type=int, default=0)
    p.add_argument("--json")
    p.add_argument("--include-gzip", action="store_true")
    p.set_defaults(func=lambda a: score_streams(Path(a.tc), Path(a.vfs), a.entry_index, Path(a.json) if a.json else None, include_gzip=a.include_gzip))

    p = sub.add_parser("convert-one", help="Build one candidate Steam savedata.vfs from a selected mobile stream")
    p.add_argument("tc")
    p.add_argument("steam_template")
    p.add_argument("--out", required=True)
    p.add_argument("--stream-index", type=int, default=0)
    p.add_argument("--entry-index", type=int, default=0)
    p.add_argument("--prefix-from-template", type=int, default=740)
    p.add_argument("--include-gzip", action="store_true")
    p.set_defaults(func=lambda a: convert_one(Path(a.tc), Path(a.steam_template), Path(a.out), a.stream_index, a.entry_index, a.prefix_from_template, include_gzip=a.include_gzip))

    p = sub.add_parser("build-candidates", help="Build candidates for the top-ranked or all mobile streams")
    p.add_argument("tc")
    p.add_argument("steam_template")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--entry-index", type=int, default=0)
    p.add_argument("--prefix-from-template", type=int, default=740)
    p.add_argument("--top", type=int, default=3, help="Top N streams to build; use 0 to build all")
    p.add_argument("--include-gzip", action="store_true")
    p.set_defaults(func=lambda a: build_candidates(Path(a.tc), Path(a.steam_template), Path(a.out_dir), a.entry_index, a.prefix_from_template, a.top, include_gzip=a.include_gzip))


    p = sub.add_parser("tc-map", help="Map mobile TC streams to guessed titles/thumbnails and optional Steam scores")
    p.add_argument("tc")
    p.add_argument("--json")
    p.add_argument("--steam-template", help="Optional Steam VFS template to score similarity against")
    p.add_argument("--entry-index", type=int, default=0)
    p.add_argument("--streams", default="all", help="Stream list like 40-47, or all")
    p.add_argument("--grep", default="", help="Case-insensitive regex filter over guessed title + first in-body text")
    p.add_argument("--only-png", action="store_true", help="Only show streams that have a following PNG thumbnail before the next stream")
    p.add_argument("--only-titled", action="store_true", help="Only show streams with a guessed title")
    p.add_argument("--include-gzip", action="store_true")
    p.set_defaults(func=lambda a: tc_map(Path(a.tc), Path(a.json) if a.json else None, Path(a.steam_template) if a.steam_template else None, a.entry_index, a.streams, include_gzip=a.include_gzip, grep=a.grep, only_png=a.only_png, only_titled=a.only_titled))

    p = sub.add_parser("build-multi", help="Build a multi-slot Steam VFS from several mobile TC streams")
    p.add_argument("tc")
    p.add_argument("steam_template")
    p.add_argument("--out", required=True)
    p.add_argument("--streams", default="all", help="Stream list like 47,46,45 or 40-47, or all")
    p.add_argument("--entry-index", type=int, default=0)
    p.add_argument("--prefix-from-template", type=int, default=740)
    p.add_argument("--sort-by-score", action="store_true", help="Order Steam slots by score instead of stream order")
    p.add_argument("--max-entries", type=int, default=0, help="Limit number of entries after optional sorting; 0 means no limit")
    p.add_argument("--no-patch-titles", action="store_true", help="Keep template save-list title/header metadata unchanged")
    p.add_argument("--titles", default="", help="Optional pipe-separated visible titles, one per output slot")
    p.add_argument("--dates", default="", help="Optional pipe-separated visible dates, one per output slot; format like 2025-07-03 00:04")
    p.add_argument("--include-gzip", action="store_true")
    p.set_defaults(func=lambda a: build_multi(Path(a.tc), Path(a.steam_template), Path(a.out), a.streams, a.entry_index, a.prefix_from_template, a.sort_by_score, include_gzip=a.include_gzip, max_entries=a.max_entries, patch_titles=not a.no_patch_titles, titles_arg=a.titles, dates_arg=a.dates))

    p = sub.add_parser("build-plan", help="Build a multi-slot Steam VFS from an explicit JSON plan")
    p.add_argument("tc")
    p.add_argument("steam_template")
    p.add_argument("--plan", required=True, help="JSON list of slots: [{stream,title,date}, ...]")
    p.add_argument("--out", required=True)
    p.add_argument("--entry-index", type=int, default=0)
    p.add_argument("--prefix-from-template", type=int, default=740)
    p.add_argument("--include-gzip", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=lambda a: build_plan(Path(a.tc), Path(a.steam_template), Path(a.plan), Path(a.out), a.entry_index, a.prefix_from_template, include_gzip=a.include_gzip, dry_run=a.dry_run))

    p = sub.add_parser("retitle-vfs", help="Patch the visible Steam save-list title/info for one VFS entry")
    p.add_argument("vfs")
    p.add_argument("--out", required=True)
    p.add_argument("--chapter", required=True)
    p.add_argument("--info", default="")
    p.add_argument("--date", default="", help="Optional visible date string to patch")
    p.add_argument("--entry-index", type=int, default=0)
    p.add_argument("--prefix-from-template", type=int, default=740)
    p.set_defaults(func=lambda a: retitle_vfs(Path(a.vfs), Path(a.out), a.chapter, a.info, a.entry_index, a.prefix_from_template, date=a.date))



    p = sub.add_parser("prefix-sweep", help="Build single-slot candidates for many prefix lengths to test actual loadability")
    p.add_argument("tc")
    p.add_argument("steam_template")
    p.add_argument("--stream-index", type=int, required=True)
    p.add_argument("--out-dir", required=True)
    p.add_argument("--prefixes", default="700-780:4,716,740", help="Prefix lengths like 700-780:4,716,740")
    p.add_argument("--entry-index", type=int, default=0)
    p.add_argument("--title", default="")
    p.add_argument("--date", default="")
    p.add_argument("--include-gzip", action="store_true")
    p.set_defaults(func=lambda a: prefix_sweep(Path(a.tc), Path(a.steam_template), a.stream_index, Path(a.out_dir), a.prefixes, entry_index=a.entry_index, include_gzip=a.include_gzip, title=a.title, date=a.date))

    p = sub.add_parser("clone-template-multi", help="Control test: clone a known-good Steam slot into multiple VFS entries")
    p.add_argument("steam_template")
    p.add_argument("--out", required=True)
    p.add_argument("--count", type=int, default=6)
    p.add_argument("--entry-index", type=int, default=0)
    p.add_argument("--title", default="")
    p.set_defaults(func=lambda a: clone_template_multi(Path(a.steam_template), Path(a.out), count=a.count, entry_index=a.entry_index, title=a.title))



    p = sub.add_parser("diff-vfs", help="Compare two Steam VFS payloads and list differing byte ranges")
    p.add_argument("a_vfs")
    p.add_argument("b_vfs")
    p.add_argument("--entry-index", type=int, default=0)
    p.add_argument("--min-run", type=int, default=1, help="Only report diff ranges at least this many bytes long")
    p.add_argument("--json")
    p.set_defaults(func=lambda a: diff_vfs(Path(a.a_vfs), Path(a.b_vfs), Path(a.json) if a.json else None, entry_index=a.entry_index, min_run=a.min_run))

    p = sub.add_parser("restore-ranges", help="Build one mobile candidate but restore payload ranges from a PC donor VFS")
    p.add_argument("tc")
    p.add_argument("steam_template")
    p.add_argument("--out", required=True)
    p.add_argument("--stream-index", type=int, required=True)
    p.add_argument("--ranges", required=True, help="Payload byte ranges like 0x740-0x1740,0x36000-0x3763c")
    p.add_argument("--donor-vfs", help="Donor VFS to copy ranges from; defaults to steam_template")
    p.add_argument("--entry-index", type=int, default=0)
    p.add_argument("--prefix-from-template", type=int, default=740)
    p.add_argument("--title", default="")
    p.add_argument("--date", default="")
    p.add_argument("--include-gzip", action="store_true")
    p.set_defaults(func=lambda a: restore_ranges_build(Path(a.tc), Path(a.steam_template), Path(a.out), a.stream_index, a.ranges, donor_vfs=Path(a.donor_vfs) if a.donor_vfs else None, entry_index=a.entry_index, prefix_from_template=a.prefix_from_template, include_gzip=a.include_gzip, title=a.title, date=a.date))

    p = sub.add_parser("restore-window-sweep", help="Generate candidates restoring one PC-native window at a time")
    p.add_argument("tc")
    p.add_argument("steam_template")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--stream-index", type=int, required=True)
    p.add_argument("--donor-vfs", help="Donor VFS to copy windows from; defaults to steam_template")
    p.add_argument("--entry-index", type=int, default=0)
    p.add_argument("--prefix-from-template", type=int, default=740)
    p.add_argument("--start", type=lambda x: int(x, 0), default=740)
    p.add_argument("--end", type=lambda x: int(x, 0), default=0, help="0 means end of payload")
    p.add_argument("--window-size", type=lambda x: int(x, 0), default=4096)
    p.add_argument("--step", type=lambda x: int(x, 0), default=4096)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--title", default="")
    p.add_argument("--date", default="")
    p.add_argument("--include-gzip", action="store_true")
    p.set_defaults(func=lambda a: restore_window_sweep(Path(a.tc), Path(a.steam_template), Path(a.out_dir), a.stream_index, donor_vfs=Path(a.donor_vfs) if a.donor_vfs else None, entry_index=a.entry_index, prefix_from_template=a.prefix_from_template, include_gzip=a.include_gzip, start=a.start, end=a.end, window_size=a.window_size, step=a.step, title=a.title, date=a.date, limit=a.limit))

    p = sub.add_parser("transplant-ranges", help="Copy payload ranges from one VFS into another existing VFS")
    p.add_argument("target_vfs")
    p.add_argument("donor_vfs")
    p.add_argument("--out", required=True)
    p.add_argument("--ranges", required=True)
    p.add_argument("--entry-index", type=int, default=0)
    p.set_defaults(func=lambda a: transplant_ranges_between_vfs(Path(a.target_vfs), Path(a.donor_vfs), Path(a.out), a.ranges, entry_index=a.entry_index))


    p = sub.add_parser("postgame-candidates", help="Build direct candidates from likely postgame mobile streams")
    p.add_argument("mobile_tc")
    p.add_argument("steam_template")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--streams", default="50-54")
    p.add_argument("--prefixes", default="740,716")
    p.add_argument("--entry-index", type=int, default=0)
    p.add_argument("--include-gzip", action="store_true")
    p.set_defaults(func=lambda a: postgame_candidates(Path(a.mobile_tc), Path(a.steam_template), Path(a.out_dir), streams_arg=a.streams, prefixes_arg=a.prefixes, entry_index=a.entry_index, include_gzip=a.include_gzip))

    p = sub.add_parser("mobile-donor-ranges", help="Copy raw decompressed ranges from a donor mobile stream into a loadable base stream")
    p.add_argument("mobile_tc")
    p.add_argument("steam_template")
    p.add_argument("--base-stream", type=int, default=47)
    p.add_argument("--donor-stream", type=int, default=51)
    p.add_argument("--ranges", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--entry-index", type=int, default=0)
    p.add_argument("--prefix", type=int, default=740)
    p.add_argument("--include-gzip", action="store_true")
    p.add_argument("--title", default="")
    p.add_argument("--date", default="")
    p.set_defaults(func=lambda a: mobile_donor_ranges(Path(a.mobile_tc), Path(a.steam_template), Path(a.out), base_stream=a.base_stream, donor_stream=a.donor_stream, ranges_arg=a.ranges, entry_index=a.entry_index, prefix_from_template=a.prefix, include_gzip=a.include_gzip, title=a.title, date=a.date))

    p = sub.add_parser("mobile-donor-window-sweep", help="Sweep raw mobile donor windows into a loadable base stream")
    p.add_argument("mobile_tc")
    p.add_argument("steam_template")
    p.add_argument("--base-stream", type=int, default=47)
    p.add_argument("--donor-stream", type=int, default=51)
    p.add_argument("--out-dir", required=True)
    p.add_argument("--entry-index", type=int, default=0)
    p.add_argument("--prefix", type=int, default=740)
    p.add_argument("--include-gzip", action="store_true")
    p.add_argument("--start", type=lambda x: int(x, 0), default=0)
    p.add_argument("--end", type=lambda x: int(x, 0), default=0)
    p.add_argument("--window-size", type=lambda x: int(x, 0), default=0x1000)
    p.add_argument("--step", type=lambda x: int(x, 0), default=0x1000)
    p.add_argument("--title", default="")
    p.add_argument("--date", default="")
    p.add_argument("--limit", type=int, default=0)
    p.set_defaults(func=lambda a: mobile_donor_window_sweep(Path(a.mobile_tc), Path(a.steam_template), Path(a.out_dir), base_stream=a.base_stream, donor_stream=a.donor_stream, entry_index=a.entry_index, prefix_from_template=a.prefix, include_gzip=a.include_gzip, start=a.start, end=a.end, window_size=a.window_size, step=a.step, title=a.title, date=a.date, limit=a.limit))

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    if argv is None and len(sys.argv) == 1:
        return interactive_wizard()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
