"""04 — hexdump virtual memory of a target process.

    python usecase/04_hexdump.py <process_name> <va_hex> [size]

Example:
    python usecase/04_hexdump.py explorer.exe 0x7ff000000000 128

Resolves the process CR3 by name, then translates and reads ``size``
bytes (default 64) at virtual address ``va``.
"""
from __future__ import annotations

import sys
from pathlib import Path

_USECASE_DIR = Path(__file__).resolve().parent
for _p in (str(_USECASE_DIR.parent), str(_USECASE_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from pymemwalker import Walker                     # noqa: E402
from sample_acquisition import SampleAcquisition   # noqa: E402


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    name = sys.argv[1]
    va = int(sys.argv[2], 0)
    size = int(sys.argv[3], 0) if len(sys.argv) > 3 else 64

    acq = SampleAcquisition()
    walker = Walker(acq)

    cr3 = walker.cr3_by_name(name)
    if cr3 is None:
        print(f"{name}: not found")
        return 1

    data = walker.read_va(cr3, va, size)
    print(f"{name} VA=0x{va:X} ({len(data)} bytes):")
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {va + i:016X}  {hex_part:<48}  {ascii_part}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
