"""Template: implement physical memory access — pymemwalker does the rest.

Fill in ``YourAcquisition`` below to point at your own physical memory
source (raw dump file, DMA device, hypervisor debug API, VM .vmem file,
hibernation image, etc.), then run:

    python -m usecase.sample_acquisition

You will see the full Windows process list — kernel CR3 discovery,
ntoskrnl PE export resolution, EPROCESS chain walking, image-base
resolution — all done by pymemwalker using only the bytes your three
methods return. No symbol server, no PDB, no native build.

Example fill-in for a raw memory dump file (.raw / .vmem):

    import mmap

    class YourAcquisition:
        def __init__(self, path: str = "memory.raw"):
            self._mm = mmap.mmap(
                open(path, "rb").fileno(), 0,
                access=mmap.ACCESS_READ,
            )

        def read_pa(self, pa: int, size: int) -> bytes:
            if pa < 0 or pa >= len(self._mm):
                return b""
            return bytes(self._mm[pa:min(pa + size, len(self._mm))])

        def write_pa(self, pa: int, data: bytes) -> bool:
            return False

        @property
        def max_pa(self) -> int:
            return len(self._mm)
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from pymemwalker import Walker  # noqa: E402


class YourAcquisition:
    """Skeleton — fill in to satisfy ``PhysicalMemoryAcquisition``."""

    def __init__(self) -> None:
        raise NotImplementedError(
            "Edit usecase/sample_acquisition.py: open your physical memory "
            "source (file, device, etc.) here and replace this stub. See the "
            "docstring at the top of this file for a raw-dump example."
        )

    def read_pa(self, pa: int, size: int) -> bytes:
        """Return up to ``size`` bytes at physical address ``pa``.

        Out-of-range / invalid reads must return shorter or empty bytes —
        never raise. Scan loops call this millions of times across the
        whole physical address space.
        """
        raise NotImplementedError

    def write_pa(self, pa: int, data: bytes) -> bool:
        """Write ``data`` at physical address ``pa``. Return ``True`` on
        success.

        Snapshot-based backends (dump files, hibernation images) should
        return ``False`` unconditionally — writes to a dead snapshot have
        no semantic meaning. Never raise.
        """
        return False

    @property
    def max_pa(self) -> int:
        """Upper bound (exclusive) of valid physical addresses."""
        raise NotImplementedError


def main() -> int:
    acq = YourAcquisition()

    print(f"[*] Initializing Walker against {type(acq).__name__} ...")
    walker = Walker(acq)
    print(f"    kernel CR3 = 0x{walker.kernel_cr3:X}")
    print()

    procs = walker.list_processes()
    print(f"[*] {len(procs)} processes:")
    for p in procs:
        print(f"    PID={p.pid:5}  {p.name:<24s}  "
              f"CR3=0x{p.cr3:013X}  Base=0x{p.base:013X}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
