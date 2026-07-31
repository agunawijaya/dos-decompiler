#!/usr/bin/env python3
"""
fatextract.py -- Pull files out of raw DOS floppy images (FAT12).

Period compilers, libraries and games are archived as raw 360K/720K/1.2M/1.44M
disk images. Getting at their contents is a recurring chore in retro reverse
engineering: you need the C library to build a signature database, the headers
to rebuild source, the original binaries to compare against.

Deliberately dependency-free. FAT12 is simple enough that a correct reader is
shorter than the code needed to drive an external tool, and this way the
package keeps working on a machine with nothing installed but Python.

Handles: FAT12 with a standard BPB, 12-bit cluster chains, 8.3 names, volume
labels and subdirectories. Long file names (VFAT) are not relevant here --
nothing from this era used them.

Usage:
    python fatextract.py disk.img --list
    python fatextract.py disk.img --out DIR
    python fatextract.py *.img --out DIR          # merge several disks
"""

import argparse
import glob
import struct
import sys
from pathlib import Path

ATTR_DIRECTORY = 0x10
ATTR_VOLUME_ID = 0x08
ATTR_LFN = 0x0F


class Fat12:
    def __init__(self, data):
        self.data = data
        if len(data) < 512:
            raise ValueError("too small to be a disk image")

        # BIOS Parameter Block. Some images from this era have an odd jump
        # instruction but a sane BPB, so the BPB is trusted rather than the
        # boot signature.
        self.bytes_per_sector = struct.unpack_from("<H", data, 11)[0]
        self.sectors_per_cluster = data[13]
        self.reserved_sectors = struct.unpack_from("<H", data, 14)[0]
        self.num_fats = data[16]
        self.root_entries = struct.unpack_from("<H", data, 17)[0]
        self.total_sectors = struct.unpack_from("<H", data, 19)[0]
        self.sectors_per_fat = struct.unpack_from("<H", data, 22)[0]

        if self.bytes_per_sector not in (512, 1024) or not self.sectors_per_cluster:
            raise ValueError("not a FAT12 image (implausible BPB)")

        self.fat_start = self.reserved_sectors * self.bytes_per_sector
        self.root_start = self.fat_start + self.num_fats * self.sectors_per_fat \
            * self.bytes_per_sector
        self.root_bytes = self.root_entries * 32
        self.data_start = self.root_start + self.root_bytes
        self.cluster_bytes = self.sectors_per_cluster * self.bytes_per_sector

    def fat_entry(self, cluster):
        """FAT12 packs one and a half bytes per entry."""
        offset = self.fat_start + (cluster * 3) // 2
        if offset + 1 >= len(self.data):
            return 0xFFF
        pair = struct.unpack_from("<H", self.data, offset)[0]
        return pair & 0x0FFF if cluster % 2 == 0 else pair >> 4

    def chain(self, first):
        out, cluster, guard = [], first, 0
        while 2 <= cluster < 0xFF0 and guard < 65536:
            out.append(cluster)
            cluster = self.fat_entry(cluster)
            guard += 1
        return out

    def read_clusters(self, first, size):
        chunks = []
        for c in self.chain(first):
            start = self.data_start + (c - 2) * self.cluster_bytes
            chunks.append(self.data[start:start + self.cluster_bytes])
        return b"".join(chunks)[:size] if size else b"".join(chunks)

    def read_dir(self, offset, count, path=""):
        """Yield (path, first_cluster, size, is_dir)."""
        for i in range(count):
            e = self.data[offset + i * 32: offset + i * 32 + 32]
            if len(e) < 32 or e[0] == 0x00:
                break
            if e[0] == 0xE5:                     # deleted
                continue
            attr = e[11]
            if attr == ATTR_LFN or attr & ATTR_VOLUME_ID:
                continue
            name = e[0:8].decode("latin-1").rstrip()
            ext = e[8:11].decode("latin-1").rstrip()
            if name in (".", ".."):
                continue
            full = f"{name}.{ext}" if ext else name
            full = f"{path}/{full}" if path else full
            cluster = struct.unpack_from("<H", e, 26)[0]
            size = struct.unpack_from("<I", e, 28)[0]
            is_dir = bool(attr & ATTR_DIRECTORY)
            yield full, cluster, size, is_dir
            if is_dir and cluster >= 2:
                sub = self.read_clusters(cluster, 0)
                # Subdirectory entries live in cluster data, not the root area.
                for item in self._read_dir_bytes(sub, full):
                    yield item

    def _read_dir_bytes(self, blob, path):
        for i in range(len(blob) // 32):
            e = blob[i * 32:(i + 1) * 32]
            if e[0] == 0x00:
                break
            if e[0] == 0xE5:
                continue
            attr = e[11]
            if attr == ATTR_LFN or attr & ATTR_VOLUME_ID:
                continue
            name = e[0:8].decode("latin-1").rstrip()
            ext = e[8:11].decode("latin-1").rstrip()
            if name in (".", ".."):
                continue
            full = f"{name}.{ext}" if ext else name
            full = f"{path}/{full}"
            cluster = struct.unpack_from("<H", e, 26)[0]
            size = struct.unpack_from("<I", e, 28)[0]
            yield full, cluster, size, bool(attr & ATTR_DIRECTORY)

    def entries(self):
        return list(self.read_dir(self.root_start, self.root_entries))


def process(image, outdir, listing):
    data = Path(image).read_bytes()
    try:
        fs = Fat12(data)
    except ValueError as e:
        print(f"{Path(image).name}: {e}", file=sys.stderr)
        return 0

    written = 0
    for name, cluster, size, is_dir in fs.entries():
        if is_dir:
            continue
        if listing:
            print(f"  {name:<32} {size:>8}")
            continue
        blob = fs.read_clusters(cluster, size)
        dest = Path(outdir) / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(blob)
        written += 1
    return written


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("images", nargs="+")
    ap.add_argument("--out", help="directory to extract into")
    ap.add_argument("--list", action="store_true", help="list contents only")
    args = ap.parse_args()

    paths = []
    for pattern in args.images:
        paths.extend(sorted(glob.glob(pattern)) or [pattern])

    total = 0
    for image in paths:
        print(f"{Path(image).name}:")
        if args.list:
            process(image, None, True)
        else:
            if not args.out:
                ap.error("--out is required unless --list is given")
            n = process(image, args.out, False)
            print(f"  {n} file(s)")
            total += n
    if not args.list:
        print(f"\n{total} file(s) extracted to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
