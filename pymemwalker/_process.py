"""Process view — an ergonomic, process-bound handle over Walker reads.

``Walker`` exposes ``read_va(cr3, va, size)``: powerful but low-level. You
end up threading a bare ``cr3`` through every call and hand-unpacking bytes
with ``struct``. ``Process`` binds one process's ``cr3`` / ``base`` / ``pid``
/ ``eproc_va`` and adds typed-struct and pointer-chain reads on top, so the
common RE/forensics access pattern reads cleanly:

    proc = walker.process("r5apex_dx12.exe")
    hp = proc.read_struct(proc.read_chain(proc.base, [ENTLIST, idx * 0x20]) + HP, '<i')

Obtain one via ``Walker.process(name)`` rather than constructing directly.
"""
import struct
from typing import Sequence


class Process:
    """A read/write handle bound to one process's address space.

    Thin facade over ``Walker``: every read/write goes through the owning
    Walker's page-table cache using this process's CR3. The wrapped
    ``ProcessInfo`` is the *same object* held in the Walker's cache, so
    ``refresh()`` (which updates that object in place) is reflected here.
    """

    __slots__ = ("_walker", "_info")

    def __init__(self, walker, info):
        self._walker = walker
        self._info = info

    # -- identity ------------------------------------------------------- #
    @property
    def name(self) -> str:
        return self._info.name

    @property
    def pid(self) -> int:
        return self._info.pid

    @property
    def cr3(self) -> int:
        """DirectoryTableBase (CR3) — root of this process's page tables."""
        return self._info.cr3

    @property
    def base(self) -> int:
        """Main-EXE image base VA (0 if it could not be discovered)."""
        return self._info.base

    @property
    def eproc_va(self) -> int:
        """Kernel virtual address of this process's EPROCESS struct."""
        return self._info.eproc_va

    # -- reads ---------------------------------------------------------- #
    def read(self, va: int, size: int) -> bytes:
        """Raw read: ``size`` bytes at ``va``. Unmapped bytes come back as
        ``\\x00`` (never raises) — see ``Walker.read_va``."""
        return self._walker.read_va(self._info.cr3, va, size)

    def read_struct(self, va: int, fmt: str):
        """Read and unpack ``fmt`` (a ``struct`` format) at ``va``.

        Returns a single value when ``fmt`` has one field, otherwise the
        tuple from ``struct.unpack``. Always prefix ``fmt`` with byte order
        (``<`` little-endian) so width/alignment are explicit. Unmapped
        memory unpacks from ``\\x00`` padding (e.g. ``0`` for integers).
        """
        data = self._walker.read_va(self._info.cr3, va, struct.calcsize(fmt))
        values = struct.unpack(fmt, data)
        return values[0] if len(values) == 1 else values

    def read_ptr(self, va: int) -> int:
        """Read an 8-byte little-endian pointer (``read_struct(va, '<Q')``)."""
        data = self._walker.read_va(self._info.cr3, va, 8)
        return struct.unpack('<Q', data)[0]

    def read_chain(self, start: int, offsets: Sequence[int]) -> int:
        """Follow a multi-level pointer chain and return the final pointer.

        Each offset is *added then dereferenced* — NOT summed:

            read_chain(base, [a, b]) == read_ptr(read_ptr(base + a) + b)

        The trailing field offset is intentionally NOT part of the chain;
        add it and read with ``read_struct`` afterwards:

            ent = proc.read_chain(proc.base, [ENTLIST, idx * 0x20])
            hp  = proc.read_struct(ent + HP, '<i')

        Returns ``0`` as soon as a dereference yields a null pointer
        (broken chain), so a missing entity degrades to ``0`` rather than
        raising.
        """
        addr = start
        for off in offsets:
            addr = self.read_ptr(addr + off)
            if addr == 0:
                return 0
        return addr

    # -- scatter reads -------------------------------------------------- #
    def read_many(self, requests: list) -> list:
        """Read multiple ``(va, size)`` regions in one batch.

        Scatter-read counterpart of ``read()``: translates and
        deduplicates physical pages internally, then issues a single
        batched read to the backend.  Returns a list of ``bytes`` in
        the same order as ``requests``.
        """
        return self._walker._paging.read_va_scatter(self._info.cr3, requests)

    # -- writes (live backends only) ------------------------------------ #
    def write(self, va: int, data: bytes) -> bool:
        """Write raw ``data`` at ``va``. Returns ``True`` on success.

        Only live backends (DMA / kernel driver) write meaningfully;
        snapshot backends return ``False`` by contract.
        """
        return self._walker.write_va(self._info.cr3, va, data)

    def write_struct(self, va: int, fmt: str, *values) -> bool:
        """Pack ``values`` with ``fmt`` and write them at ``va``.

        Symmetric counterpart of ``read_struct``::

            proc.write_struct(va, '<i', 100)        # one int
            proc.write_struct(va, '<3f', x, y, z)   # a vec3
        """
        return self._walker.write_va(self._info.cr3, va, struct.pack(fmt, *values))

    # -- lifecycle ------------------------------------------------------ #
    def refresh(self) -> bool:
        """Re-read this process's DTB live (see ``Walker.refresh_process``).

        Updates the bound state in place. Returns ``True`` if refreshed,
        ``False`` if the process is gone / its EPROCESS slot was reused —
        in which case re-resolve via ``walker.process(name)`` after
        ``walker.flush_processes()``.
        """
        return self._walker.refresh_process(self._info.name) is not None

    def invalidate_translation(self, va: int, size: int) -> None:
        """Tell the walker its cached VA->PA translation for ``[va, va+size)``
        is stale, so the next read re-walks the page tables.

        Bound counterpart of ``Walker.invalidate_translation`` (the
        ``INVLPG`` to ``flush_translations``'s full flush). The consumer is
        the only layer that can *detect* a stale translation — it has the
        semantics to see a read came back garbage — so it signals the cache
        owner here. Use when a single entity's read returns garbage to
        re-walk just that region without flushing every translation.
        """
        self._walker.invalidate_translation(self._info.cr3, va, size)

    def __repr__(self) -> str:
        return (f"<Process {self._info.name!r} pid={self._info.pid} "
                f"cr3=0x{self._info.cr3:X} base=0x{self._info.base:X}>")
