"""Template: implement physical memory access — pymemwalker does the rest.

Fill in ``SampleAcquisition`` below to point at your own physical memory
source (raw dump file, DMA device, hypervisor debug API, VM .vmem file,
hibernation image, etc.). The numbered usecase scripts in this folder
(``01_low_stub.py``, ``02_process_list.py`` ...) all import this class and
drive ``pymemwalker.Walker`` with it:

    from sample_acquisition import SampleAcquisition
    acq = SampleAcquisition()

Until you implement the three methods, ``SampleAcquisition()`` raises
``NotImplementedError`` and the demos exit early — that is expected.

Once the methods return real bytes, Walker does the rest — kernel CR3
discovery, ntoskrnl PE export resolution, EPROCESS chain walking,
image-base resolution — using only the bytes your three methods return.
No symbol server, no PDB, no native build.

Lifecycle (NOT part of the Protocol — see ``pymemwalker._acquisition``):
open / prepare your source in ``__init__`` so reads work immediately. If
it holds an OS resource (file, driver, device), add ``close()`` to release
it and the *caller* closes it — Walker never does::

    acq = SampleAcquisition()   # __init__ opens / prepares your source
    walker = Walker(acq)        # borrows acq, only reads via read_pa
    ...
    acq.close()                 # caller releases — NOT walker.close()

Adding ``__enter__`` / ``__exit__`` (below) lets short scripts use
``with SampleAcquisition() as acq:`` instead of a manual ``close()``.

Example fill-in for a raw memory dump file (.raw / .vmem):

    import mmap

    class SampleAcquisition:
        def __init__(self, path: str = "memory.raw"):
            self._f = open(path, "rb")
            self._mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)

        def read_pa(self, pa: int, size: int) -> bytes:
            if pa < 0 or pa >= len(self._mm):
                return b""
            return bytes(self._mm[pa:min(pa + size, len(self._mm))])

        def write_pa(self, pa: int, data: bytes) -> bool:
            return False

        @property
        def max_pa(self) -> int:
            return len(self._mm)

        def close(self) -> None:        # release what __init__ acquired
            self._mm.close()
            self._f.close()
"""
from __future__ import annotations


class SampleAcquisition:
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

    # ------------------------------------------------------------------ #
    # Optional lifecycle — NOT part of PhysicalMemoryAcquisition.
    # Implement these only if your backend holds an OS resource (open
    # file, loaded driver, mapped device). Release in ``close()`` what you
    # acquired in ``__init__``; the caller owns the lifetime (Walker never
    # closes you). ``__enter__`` / ``__exit__`` are sugar so callers can
    # write ``with SampleAcquisition() as acq:``.
    # ------------------------------------------------------------------ #

    # def close(self) -> None:
    #     ...  # unload driver / close handle / unmap device

    # def __enter__(self) -> "SampleAcquisition":
    #     return self

    # def __exit__(self, *exc) -> None:
    #     self.close()
