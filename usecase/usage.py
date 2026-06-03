"""pymemwalker subcommand demo — file-based memory dump analysis.

Usage:
    python -m usecase.usage <dump.raw>                          # ps (default)
    python -m usecase.usage <dump.raw> ps                       # list all processes
    python -m usecase.usage <dump.raw> find <name>              # CR3 / Base for one process
    python -m usecase.usage <dump.raw> hexdump <name> <va> [size]
    python -m usecase.usage <dump.raw> offsets                  # show discovered offsets

``<dump.raw>`` is any raw physical-memory image (
WinPmem ``.raw``, Magnet RAM Capture ``.raw``, VMware ``.vmem``,
hibernation file converted to raw, etc.).
"""
from __future__ import annotations

import mmap
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from pymemwalker import Vmm  # noqa: E402


class RawDumpAcquisition:
    """Raw physical-memory dump file as a flat PA-space backend.

    Implements the ``PhysicalMemoryAcquisition`` protocol with mmap so
    that scan loops fault in only the pages they touch — no full-file
    read up front.
    """

    def __init__(self, path: str):
        self._f = open(path, "rb")
        self._mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)

    def read_pa(self, pa: int, size: int) -> bytes:
        if pa < 0 or pa >= len(self._mm):
            return b""
        return bytes(self._mm[pa:min(pa + size, len(self._mm))])

    def write_pa(self, pa: int, data: bytes) -> bool:
        return False                # static snapshot is read-only by nature

    @property
    def max_pa(self) -> int:
        return len(self._mm)

    def close(self) -> None:
        self._mm.close()
        self._f.close()

    def __enter__(self) -> "RawDumpAcquisition":
        return self

    def __exit__(self, *_) -> None:
        self.close()


# ---------------------------------------------------------------------- #
# Subcommands
# ---------------------------------------------------------------------- #

def cmd_ps(vmm: Vmm) -> int:
    procs = vmm.list_processes()
    print(f"{len(procs)} processes:")
    for p in procs:
        print(f"  PID={p.pid:5}  {p.name:<24s}  "
              f"CR3=0x{p.cr3:013X}  Base=0x{p.base:013X}")
    return 0


def cmd_find(vmm: Vmm, name: str) -> int:
    cr3 = vmm.cr3_by_name(name)
    base = vmm.base_by_name(name)
    if cr3 is None:
        print(f"{name}: not found")
        return 1
    print(f"{name}:")
    print(f"  CR3  = 0x{cr3:X}")
    if base:
        print(f"  Base = 0x{base:X}")
    else:
        print("  Base = (not discovered)")
    return 0


def cmd_hexdump(vmm: Vmm, name: str, va_str: str, size_str: str = "64") -> int:
    cr3 = vmm.cr3_by_name(name)
    if cr3 is None:
        print(f"{name}: not found")
        return 1
    va = int(va_str, 0)
    size = int(size_str, 0)
    data = vmm.read_va(cr3, va, size)
    print(f"{name} VA=0x{va:X} ({len(data)} bytes):")
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {va + i:016X}  {hex_part:<48}  {ascii_part}")
    return 0


def cmd_offsets(vmm: Vmm) -> int:
    print(f"kernel CR3 = 0x{vmm.kernel_cr3:X}")
    print("EPROCESS field offsets (auto-discovered, no PDB):")
    for k, v in vmm.offsets.items():
        print(f"  {k:<22s} = {f'0x{v:X}' if isinstance(v, int) else v}")
    return 0


COMMANDS = {
    "ps":       cmd_ps,
    "find":     cmd_find,
    "hexdump":  cmd_hexdump,
    "offsets":  cmd_offsets,
}


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1

    dump_path = Path(sys.argv[1])
    if not dump_path.exists():
        print(f"dump file not found: {dump_path}")
        return 1

    cmd_name = sys.argv[2] if len(sys.argv) >= 3 else "ps"
    cmd = COMMANDS.get(cmd_name)
    if cmd is None:
        print(f"unknown command: {cmd_name}")
        print(__doc__)
        return 1
    cmd_args = sys.argv[3:]

    with RawDumpAcquisition(str(dump_path)) as acq:
        print(f"[*] {dump_path} ({acq.max_pa / (1024 ** 3):.1f} GiB)\n")

        print("[*] Initializing Vmm ...")
        t0 = time.perf_counter()
        vmm = Vmm(acq)
        print(f"    done in {time.perf_counter() - t0:.2f}s\n")

        try:
            return cmd(vmm, *cmd_args)
        except TypeError as e:
            print(f"wrong arguments for '{cmd_name}': {e}")
            print(__doc__)
            return 1


if __name__ == "__main__":
    sys.exit(main())
