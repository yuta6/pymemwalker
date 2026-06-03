"""03 — resolve one process's CR3 and image base by name.

    python usecase/03_find_process.py [process_name]

Defaults to ``explorer.exe`` when no name is given.
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

DEFAULT_NAME = "explorer.exe"


def main() -> int:
    name = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_NAME

    acq = SampleAcquisition()
    walker = Walker(acq)

    cr3 = walker.cr3_by_name(name)
    base = walker.base_by_name(name)
    if cr3 is None:
        print(f"{name}: not found")
        return 1

    print(f"{name}:")
    print(f"  CR3  = 0x{cr3:X}")
    print(f"  Base = 0x{base:X}" if base else "  Base = (not discovered)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
