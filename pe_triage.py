#!/usr/bin/env python3
import math
import struct
import sys
from pathlib import Path


def u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def cstr(buf, off, limit=512):
    end = buf.find(b"\x00", off, min(len(buf), off + limit))
    if end < 0:
        end = min(len(buf), off + limit)

    return buf[off:end].decode("ascii", errors="replace")


def entropy(data):
    if not data:
        return 0.0

    counts = [0] * 256

    for b in data:
        counts[b] += 1

    n = len(data)
    total = 0.0

    for count in counts:
        if not count:
            continue

        p = count / n
        total -= p * math.log2(p)

    return total


class PE:
    def __init__(self, raw):
        self.raw = raw
        self.sections = []

        self.pe = 0
        self.machine = 0
        self.section_count = 0
        self.opt = 0
        self.magic = 0
        self.is64 = False
        self.entry_rva = 0
        self.image_base = 0
        self.size_of_image = 0
        self.headers_size = 0
        self.data_dirs = []

        self._parse()

    def _parse(self):
        if len(self.raw) < 0x40 or self.raw[:2] != b"MZ":
            raise ValueError("not an MZ executable")

        self.pe = u32(self.raw, 0x3C)

        if self.pe + 0x18 >= len(self.raw):
            raise ValueError("PE header outside file")

        if self.raw[self.pe:self.pe + 4] != b"PE\x00\x00":
            raise ValueError("bad PE signature")

        coff = self.pe + 4

        self.machine = u16(self.raw, coff)
        self.section_count = u16(self.raw, coff + 2)

        opt_size = u16(self.raw, coff + 16)
        self.opt = coff + 20

        if self.opt + opt_size > len(self.raw):
            raise ValueError("truncated optional header")

        self.magic = u16(self.raw, self.opt)

        if self.magic == 0x20B:
            self.is64 = True
        elif self.magic == 0x10B:
            self.is64 = False
        else:
            raise ValueError(f"unknown optional header magic 0x{self.magic:04x}")

        self.entry_rva = u32(self.raw, self.opt + 16)

        if self.is64:
            self.image_base = u64(self.raw, self.opt + 24)
            dirs_off = self.opt + 112
        else:
            self.image_base = u32(self.raw, self.opt + 28)
            dirs_off = self.opt + 96

        self.size_of_image = u32(self.raw, self.opt + 56)
        self.headers_size = u32(self.raw, self.opt + 60)

        number_of_dirs = u32(
            self.raw,
            self.opt + (108 if self.is64 else 92),
        )

        for i in range(min(number_of_dirs, 16)):
            off = dirs_off + i * 8

            if off + 8 > self.opt + opt_size:
                break

            self.data_dirs.append((
                u32(self.raw, off),
                u32(self.raw, off + 4),
            ))

        sec = self.opt + opt_size

        for _ in range(self.section_count):
            if sec + 40 > len(self.raw):
                raise ValueError("truncated section table")

            name = self.raw[sec:sec + 8].split(b"\x00", 1)[0]
            name = name.decode("ascii", errors="replace")

            virtual_size = u32(self.raw, sec + 8)
            virtual_address = u32(self.raw, sec + 12)
            raw_size = u32(self.raw, sec + 16)
            raw_offset = u32(self.raw, sec + 20)
            characteristics = u32(self.raw, sec + 36)

            self.sections.append({
                "name": name,
                "vsize": virtual_size,
                "rva": virtual_address,
                "raw_size": raw_size,
                "raw": raw_offset,
                "chars": characteristics,
            })

            sec += 40

    def rva_to_offset(self, rva):
        if rva < self.headers_size:
            return rva

        for s in self.sections:
            span = max(s["vsize"], s["raw_size"])

            if s["rva"] <= rva < s["rva"] + span:
                off = s["raw"] + (rva - s["rva"])

                if off < len(self.raw):
                    return off

        return None

    def section_for_rva(self, rva):
        for s in self.sections:
            span = max(s["vsize"], s["raw_size"])

            if s["rva"] <= rva < s["rva"] + span:
                return s

        return None

    def imports(self):
        if len(self.data_dirs) < 2:
            return []

        import_rva, import_size = self.data_dirs[1]

        if not import_rva or not import_size:
            return []

        pos = self.rva_to_offset(import_rva)

        if pos is None:
            return []

        result = []

        for _ in range(4096):
            if pos + 20 > len(self.raw):
                break

            original_thunk = u32(self.raw, pos)
            timestamp = u32(self.raw, pos + 4)
            forwarder = u32(self.raw, pos + 8)
            name_rva = u32(self.raw, pos + 12)
            first_thunk = u32(self.raw, pos + 16)

            if not any((
                original_thunk,
                timestamp,
                forwarder,
                name_rva,
                first_thunk,
            )):
                break

            name_off = self.rva_to_offset(name_rva)

            if name_off is None:
                dll = "<bad-name-rva>"
            else:
                dll = cstr(self.raw, name_off)

            result.append(dll)
            pos += 20

        return result


def perms(chars):
    out = ""

    if chars & 0x40000000:
        out += "R"
    else:
        out += "-"

    if chars & 0x80000000:
        out += "W"
    else:
        out += "-"

    if chars & 0x20000000:
        out += "X"
    else:
        out += "-"

    return out


def machine_name(x):
    return {
        0x14C: "x86",
        0x8664: "x86-64",
        0xAA64: "ARM64",
        0x1C4: "ARM Thumb-2",
    }.get(x, f"0x{x:04x}")


def analyze(path):
    raw = path.read_bytes()
    pe = PE(raw)

    print(f"\n{path.name}")
    print("-" * len(path.name))

    print(f"size       : {len(raw):,} bytes")
    print(f"machine    : {machine_name(pe.machine)}")
    print(f"image base : 0x{pe.image_base:x}")
    print(f"image size : 0x{pe.size_of_image:x}")
    print(f"entry RVA  : 0x{pe.entry_rva:x}")
    print(f"sections   : {pe.section_count}")

    entry_section = pe.section_for_rva(pe.entry_rva)

    if entry_section:
        print(f"entry sec  : {entry_section['name']}")
    else:
        print("entry sec  : <none>")

    findings = []

    print("\nsections")

    highest_raw_end = 0

    for s in pe.sections:
        raw_start = s["raw"]
        raw_end = min(len(raw), raw_start + s["raw_size"])
        block = raw[raw_start:raw_end]

        ent = entropy(block)
        p = perms(s["chars"])

        print(
            f"  {s['name']:<9} "
            f"RVA 0x{s['rva']:08x}  "
            f"VSZ 0x{s['vsize']:06x}  "
            f"RAW 0x{s['raw_size']:06x}  "
            f"{p}  "
            f"H={ent:.3f}"
        )

        highest_raw_end = max(
            highest_raw_end,
            s["raw"] + s["raw_size"],
        )

        if "W" in p and "X" in p:
            findings.append(
                f"{s['name']} is writable + executable"
            )

        if ent >= 7.3 and s["raw_size"] >= 1024:
            findings.append(
                f"{s['name']} has high entropy ({ent:.3f})"
            )

        if s["raw_size"] == 0 and s["vsize"] > 0x100000:
            findings.append(
                f"{s['name']} has unusually large virtual-only size"
            )

        if not s["name"]:
            findings.append("unnamed section present")

    if entry_section:
        ep_perms = perms(entry_section["chars"])

        if "X" not in ep_perms:
            findings.append(
                f"entry point is inside non-executable section "
                f"{entry_section['name']}"
            )

    if highest_raw_end < len(raw):
        overlay_size = len(raw) - highest_raw_end

        print(f"\noverlay    : {overlay_size:,} bytes")

        if overlay_size > 4096:
            findings.append(
                f"{overlay_size:,}-byte overlay after final section"
            )
    else:
        print("\noverlay    : none")

    imports = pe.imports()

    print(f"\nimports ({len(imports)})")

    for dll in imports:
        print(f"  {dll}")

    imported = {x.lower() for x in imports}

    interesting = {
        "wininet.dll",
        "winhttp.dll",
        "ws2_32.dll",
        "dbghelp.dll",
        "ntdll.dll",
        "bcrypt.dll",
        "crypt32.dll",
        "advapi32.dll",
    }

    hits = sorted(imported & interesting)

    if hits:
        findings.append(
            "interesting imports: " + ", ".join(hits)
        )

    if pe.section_count > 12:
        findings.append(
            f"unusually high section count ({pe.section_count})"
        )

    print("\ntriage")

    if not findings:
        print("  nothing obvious")
    else:
        for x in findings:
            print(f"  ! {x}")

    print()


def main():
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} <pe-file>")
        raise SystemExit(2)

    path = Path(sys.argv[1])

    if not path.is_file():
        print(f"not found: {path}")
        raise SystemExit(2)

    try:
        analyze(path)
    except (OSError, ValueError, struct.error) as e:
        print(f"error: {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
