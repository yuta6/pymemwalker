"""Protocol for physical memory acquisition backends.

Users implement this Protocol with their own backend (raw dump file,
DMA hardware, VMware .vmem, hibernation file, etc.) and pass an instance
to ``Walker()``. No backend is implemented inside the library itself; a
reference implementation backed by a raw dump file is provided in
``usecase/usage.py``.

The ``@runtime_checkable`` decorator enables ``isinstance(acq, ...)``
checks at construction time so that obvious structural mistakes (missing
methods, typos) surface with a clear error.
"""
from typing import Protocol, runtime_checkable


@runtime_checkable
class PhysicalMemoryAcquisition(Protocol):
    """Access to a flat physical memory image.

    Implementations must satisfy:

      - ``read_pa(pa, size)`` returns ``bytes`` (or ``bytearray``) of
        length ``<= size``. A short return (including empty ``b''``) is
        the contract for out-of-range or invalid reads.
      - ``read_pa`` **must never raise** for out-of-range PAs. Scan loops
        call it millions of times across the entire physical address
        space; an exception there would cripple performance and require
        every caller to wrap each read in a try/except.
      - ``write_pa(pa, data)`` returns ``True`` on success, ``False``
        otherwise (out-of-range, hardware error, or simply not supported
        by this backend). Snapshot-based backends (dump files, hibernation
        images) should return ``False`` unconditionally — writes to a dead
        snapshot have no semantic meaning. Real write capability requires
        a live backend (DMA hardware, kernel driver, VM debug API).
      - ``write_pa`` **must never raise**, mirroring ``read_pa``.
      - ``max_pa`` returns a positive ``int`` upper bound for scan loops.

    Lifecycle is deliberately **not** part of this Protocol. ``Walker``
    only ever calls ``read_pa`` / ``write_pa`` / ``max_pa`` — it borrows
    the acquisition to read bytes and never owns it. Therefore:

      - Open / prepare your source in your own ``__init__`` so reads work
        the moment the object is handed to ``Walker``. That is an implied
        precondition of ``read_pa`` (it must return real bytes), not a
        method the library calls.
      - If your backend holds an OS resource (open file, loaded driver,
        mapped device), implement ``close()`` to release it — and,
        optionally, ``__enter__`` / ``__exit__`` so callers can use
        ``with``. The *caller* owns this lifecycle; there is no
        ``Walker.close()``. (memprocfs' ``Vmm`` carries ``close()`` because
        it is a concrete class, not because any base contract forces it.)

    Typical caller code::

        acq = LiveAcquisition()   # __init__ loads the driver
        walker = Walker(acq)        # borrows acq, only reads via read_pa
        ...
        acq.close()                 # caller releases — NOT walker.close()
    """

    def read_pa(self, pa: int, size: int) -> bytes:
        """Read ``size`` bytes starting at physical address ``pa``.

        Returns bytes of length up to ``size``. Returns shorter or empty
        bytes for out-of-range / invalid reads — never raises.
        """
        ...

    def write_pa(self, pa: int, data: bytes) -> bool:
        """Write ``data`` starting at physical address ``pa``.

        Returns ``True`` on success, ``False`` on any failure. Backends
        that cannot meaningfully write (snapshot files, read-only DMA)
        should return ``False`` unconditionally. Never raises.
        """
        ...

    @property
    def max_pa(self) -> int:
        """Upper bound (exclusive) of valid physical addresses.

        Used as the stop condition for full-memory scan loops.
        """
        ...
