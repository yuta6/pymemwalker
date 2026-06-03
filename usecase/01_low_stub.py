"""01 — lowest-level smoke test: bring up Walker on your SampleAcquisition.

Implement ``SampleAcquisition`` in ``sample_acquisition.py`` first, then:

    python usecase/01_low_stub.py

Prints the auto-discovered kernel CR3 and EPROCESS field offsets — proof
that Walker bootstrapped purely from the bytes your acquisition returns
(no PDB, no symbol server).
"""
from __future__ import annotations

import sys
from pathlib import Path

# Numbered scripts can't be run with ``python -m`` (a module name can't
# start with a digit), so run them as files. Put both the repo root (for
# ``pymemwalker``) and this folder (for ``sample_acquisition``) on sys.path.
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
    print(f"    kernel CR3 = 0x{walker.kernel_cr3:X}")
    print("    EPROCESS field offsets (auto-discovered, no PDB):")
    for k, v in walker.offsets.items():
        print(f"      {k:<22s} = "
              f"{f'0x{v:X}' if isinstance(v, int) else v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
