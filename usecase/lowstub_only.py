"""Diagnostic: run only ``find_kernel_cr3`` (Low Stub parsing).

Useful for verifying that a new acquisition backend can correctly serve
low physical memory before exercising the full ``Walker`` pipeline.

Usage:
    python -m usecase.lowstub_only <dump.raw>
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from pymemwalker._kernel import find_kernel_cr3  # noqa: E402
from usecase.usage import RawDumpAcquisition  # noqa: E402


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python -m usecase.lowstub_only <dump.raw>")
        return 1

    dump_path = Path(sys.argv[1])
    if not dump_path.exists():
        print(f"dump file not found: {dump_path}")
        return 1

    with RawDumpAcquisition(str(dump_path)) as acq:
        print(f"[*] {dump_path} ({acq.max_pa / (1024 ** 3):.1f} GiB)")
        cr3, entry_va = find_kernel_cr3(acq)
        print(f"    kernel CR3 = 0x{cr3:X}")
        print(f"    entry VA   = 0x{entry_va:X}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
