"""02 — enumerate the full Windows process list.

    python usecase/02_process_list.py

Walks the EPROCESS active-process chain and prints PID / name / CR3 /
image base for every process.
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
    acq = SampleAcquisition()

    print(f"[*] Initializing Walker against {type(acq).__name__} ...")
    walker = Walker(acq)
    print(f"    kernel CR3 = 0x{walker.kernel_cr3:X}\n")

    procs = walker.list_processes()
    print(f"[*] {len(procs)} processes:")
    for p in procs:
        print(f"    PID={p.pid:5}  {p.name:<24s}  "
              f"CR3=0x{p.cr3:013X}  Base=0x{p.base:013X}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
