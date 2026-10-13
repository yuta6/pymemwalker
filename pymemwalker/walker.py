"""Top-level Walker class: user-facing entry point for pymemwalker.

Wires together the acquisition backend, the page-table walker, the kernel
CR3 discovery, and the EPROCESS chain walker. All the expensive scans run
once in ``__init__``; subsequent calls hit caches.
"""
import logging
import struct
from typing import Optional

from ._acquisition import PhysicalMemoryAcquisition
from ._paging import Paging
from ._kernel import find_kernel_cr3, discover_offsets
from ._eprocess import (
    ProcessInfo,
    list_processes,
    discover_peb_offset,
    discover_section_base,
)
from ._process import Process

_log = logging.getLogger("pymemwalker")


def _name_matches(stored: str, query: str) -> bool:
    """Case-insensitive process-name match that tolerates EPROCESS
    ``ImageFileName`` truncation.

    ``ImageFileName`` is a 15-byte field (~14 usable chars + NUL), so a name
    like ``"r5apex_dx12.exe"`` (15 chars) is stored truncated as
    ``"r5apex_dx12.ex"``. A stored name at the truncation limit therefore
    matches any longer query it is a prefix of.
    """
    s, q = stored.lower(), query.lower()
    if s == q:
        return True
    return len(s) >= 14 and q.startswith(s)


class Walker:
    """Memory-image analysis context.

    Construction performs a few seconds of physical-memory scanning to
    locate the kernel CR3 and derive EPROCESS field offsets. Everything
    after that runs against cached state.
    """

    def __init__(self, acq: PhysicalMemoryAcquisition, cache_pages: bool = True):
        # cache_pages=False is for LIVE backends (memory changes every frame):
        # physical page contents are never retained, so reads are always fresh
        # and there is no need to flush_pages() each frame. The TLB still
        # caches translations. Leave True for snapshots (a dump never changes).
        # Structural check: missing methods / typos surface here.
        if not isinstance(acq, PhysicalMemoryAcquisition):
            raise TypeError(
                "acq must implement PhysicalMemoryAcquisition "
                "(needs read_pa(pa, size) -> bytes and max_pa property)"
            )

        # Behavioral sanity: catches common implementation bugs early.
        self._validate_acquisition(acq)

        self._acq = acq
        self._paging = Paging(acq, cache_pages=cache_pages)

        # One-time discovery. Results are immutable for the program's lifetime.
        # Low Stub yields both the kernel CR3 and a kernel-VA inside ntoskrnl;
        # the latter seeds ntoskrnl-base discovery, which in turn lets us
        # resolve PsInitialSystemProcess and reach System EPROCESS directly.
        self._kernel_cr3: int
        self._kernel_entry_va: int
        self._kernel_cr3, self._kernel_entry_va = find_kernel_cr3(acq)
        self._offsets: dict = discover_offsets(
            self._paging, self._kernel_cr3, self._kernel_entry_va
        )

        # Lazy / refreshable caches.
        self._processes: Optional[list[ProcessInfo]] = None

    @property
    def kernel_cr3(self) -> int:
        """Physical address of the kernel PML4."""
        return self._kernel_cr3

    @property
    def offsets(self) -> dict:
        """Derived EPROCESS field offsets. Mostly for diagnostics."""
        return dict(self._offsets)

    def list_processes(self) -> list[ProcessInfo]:
        """Enumerate all processes via the ActiveProcessLinks chain.

        On first call: walks the chain, then runs SectionBaseAddress
        offset discovery against the result and re-walks to populate
        ``base`` for every process. Cached afterwards.
        """
        if self._processes is not None:
            return self._processes

        procs = list_processes(self._paging, self._kernel_cr3, self._offsets)

        # Infer the field used to recover each process's image base.
        # Modern Windows: PEB.ImageBaseAddress (Peb offset in EPROCESS).
        # Older builds:   SectionBaseAddress field directly in EPROCESS.
        # Whichever resolves first wins; re-walk to populate ``base``.
        discovered = False
        if 'Peb' not in self._offsets and 'SectionBaseAddress' not in self._offsets and procs:
            peb_off = discover_peb_offset(
                self._paging, self._kernel_cr3, self._offsets, procs
            )
            if peb_off is not None:
                self._offsets['Peb'] = peb_off
                discovered = True
                _log.info(f"  [discover_peb_offset] Peb @ EPROCESS+0x{peb_off:X}")
            else:
                sec_off = discover_section_base(
                    self._paging, self._kernel_cr3, self._offsets, procs
                )
                if sec_off is not None:
                    self._offsets['SectionBaseAddress'] = sec_off
                    discovered = True
        if discovered:
            procs = list_processes(self._paging, self._kernel_cr3, self._offsets)

        self._processes = procs
        return procs

    def process(self, name: str) -> Optional[Process]:
        """Return a ``Process`` view for the process matching ``name``
        (case-insensitive), or None if no such process exists.

        The view binds this process's CR3 / base / pid / eproc_va and adds
        typed-struct and pointer-chain reads — the ergonomic entry point
        for actually reading a process's memory. ``cr3_by_name`` /
        ``base_by_name`` remain for callers that just want the raw values.
        """
        for p in self.list_processes():
            if _name_matches(p.name, name):
                return Process(self, p)
        return None

    def cr3_by_name(self, name: str) -> Optional[int]:
        """Return DirectoryTableBase (CR3) for a process matching ``name``
        (case-insensitive). Returns None if no such process exists."""
        for p in self.list_processes():
            if _name_matches(p.name, name):
                return p.cr3
        return None

    def base_by_name(self, name: str) -> Optional[int]:
        """Return SectionBaseAddress for a process matching ``name``
        (case-insensitive). Returns None if no such process or if the
        base could not be discovered."""
        for p in self.list_processes():
            if _name_matches(p.name, name):
                return p.base if p.base else None
        return None

    def read_va(self, cr3: int, va: int, size: int) -> bytes:
        """Read ``size`` bytes at virtual address ``va`` using ``cr3`` as
        the page-table root. Returns ``\\x00``-padded bytes for any
        paged-out / invalid regions."""
        return self._paging.read_va(cr3, va, size)

    def read_pa(self, pa: int, size: int) -> bytes:
        """Read ``size`` bytes at physical address ``pa`` (with caching)."""
        return self._paging.read_pa(pa, size)

    def write_va(self, cr3: int, va: int, data: bytes) -> bool:
        """Write ``data`` at virtual address ``va`` using ``cr3`` as the
        page-table root. Returns ``True`` on success, ``False`` on the
        first failure (paged-out page, backend rejection, etc.).

        Note: only live backends (DMA hardware, kernel driver) can do
        meaningful writes. Snapshot-based backends (dump files) return
        ``False`` unconditionally by their own contract.
        """
        return self._paging.write_va(cr3, va, data)

    def write_pa(self, pa: int, data: bytes) -> bool:
        """Write ``data`` at physical address ``pa``. Returns ``True`` on
        success. Invalidates any cached page overlapping the range."""
        return self._paging.write_pa(pa, data)

    def refresh_process(self, name: str) -> Optional[int]:
        """Re-read just one cached process's DTB from its EPROCESS, live.

        Cheap targeted refresh: instead of re-walking the whole
        ActiveProcessLinks chain (``flush_processes``), this re-reads the
        ``DirectoryTableBase`` of the already-known process at its cached
        ``eproc_va``, bypassing the physical page cache so the value
        reflects current memory. The cached entry is updated in place and
        the (possibly new) CR3 is returned.

        Returns ``None`` if the process is not in the cache, or if its
        EPROCESS slot no longer holds a process of this name (exited /
        slot reused) — in that case call ``flush_processes`` and re-resolve
        by name.

        The image base is NOT re-read (it is stable for a process's
        lifetime); use ``flush_processes`` for a full re-discovery.
        Normal Windows keeps a live process's CR3 fixed for its lifetime,
        so this is only needed for backends/targets that rotate the DTB.
        """
        if self._processes is None:
            self.list_processes()

        dtb_off = self._offsets['DirectoryTableBase']
        name_off = self._offsets['ImageFileName']
        for p in self._processes:
            if p.name.lower() != name.lower():
                continue
            # Force a fresh read of the EPROCESS page(s), not the cache.
            self._paging.invalidate_va(self._kernel_cr3, p.eproc_va, 0x1000)
            # Validate the slot still belongs to this process.
            name_data = self._paging.read_va(
                self._kernel_cr3, p.eproc_va + name_off, 15
            )
            if name_data.rstrip(b'\x00').decode(errors='replace').lower() != name.lower():
                return None
            cr3_data = self._paging.read_va(
                self._kernel_cr3, p.eproc_va + dtb_off, 8
            )
            if len(cr3_data) != 8:
                return None
            p.cr3 = struct.unpack('<Q', cr3_data)[0]
            return p.cr3
        return None

    def flush_processes(self) -> None:
        """Forget the cached process list, physical pages, and TLB.

        Call this when processes may have started or exited and the cached
        EPROCESS chain is stale. The kernel CR3 and derived offsets are
        NOT touched (they are immutable for the program's lifetime).

        Changed in 0.3.5: with cache_pages=True, this invalidates ALL cached
        physical pages, including arbitrary data read through read_pa/read_va,
        not only EPROCESS data. Subsequent reads reacquire bytes from the
        acquisition backend; live-memory values may therefore differ from
        previously cached values. Static snapshots keep the same contents,
        but also incur fresh backend reads after this call.

        This does not write target memory or change the VA->PA algorithm.
        With cache_pages=False there are no retained physical pages to
        invalidate; the translation cache is still cleared as before.
        """
        self._processes = None
        self._paging.flush_pages()
        self._paging.flush_translations()

    def flush_translations(self) -> None:
        """Drop only the VA->PA translation cache.

        Use this if a process's memory layout may have changed (e.g.
        DLL load/unload) but the process itself is still alive.
        """
        self._paging.flush_translations()

    def flush_pages(self) -> None:
        """Drop the physical page cache.

        Needed only for live acquisition backends where the underlying
        memory can change between reads. For static dump-file backends
        this has no effect in practice.
        """
        self._paging.flush_pages()

    def invalidate_translation(self, cr3: int, va: int, size: int) -> None:
        """Drop cached VA->PA *translations* for ``[va, va+size)`` so the
        next read re-walks the page tables. Targeted counterpart of
        ``flush_translations`` (the ``INVLPG`` to its full flush) — use when
        a stale translation is returning the wrong physical page for a
        remapped/freed region, without paying a full re-walk of everything."""
        self._paging.invalidate_translation(cr3, va, size)

    @staticmethod
    def _validate_acquisition(acq: PhysicalMemoryAcquisition) -> None:
        """Light behavioral sanity check on the backend.

        Catches common implementation mistakes early: returning non-bytes,
        raising on out-of-range, returning a nonsensical max_pa.
        """
        try:
            max_pa = acq.max_pa
        except Exception as e:
            raise TypeError(f"acq.max_pa raised: {e!r}") from e
        if not isinstance(max_pa, int) or max_pa <= 0:
            raise ValueError(
                f"acq.max_pa must be a positive int, got {max_pa!r}"
            )

        try:
            result = acq.read_pa(0, 16)
        except Exception as e:
            raise TypeError(f"acq.read_pa(0, 16) raised: {e!r}") from e
        if not isinstance(result, (bytes, bytearray)):
            raise TypeError(
                f"acq.read_pa must return bytes, got {type(result).__name__}"
            )
        if len(result) > 16:
            raise ValueError(
                f"acq.read_pa(0, 16) returned {len(result)} bytes (must be <= 16)"
            )

        # Out-of-range reads must not raise — scan loops depend on this.
        try:
            oob = acq.read_pa(max_pa + 0x1000, 16)
        except Exception as e:
            raise ValueError(
                f"acq.read_pa must not raise for out-of-range PA, got: {e!r}"
            ) from e
        if not isinstance(oob, (bytes, bytearray)):
            raise TypeError(
                "acq.read_pa must return bytes for out-of-range reads too"
            )

        # write_pa must not raise either; its return type must be bool.
        # We probe with a zero-byte write (semantically a no-op) to avoid
        # touching any real memory even on backends that do support writes.
        try:
            wresult = acq.write_pa(0, b"")
        except Exception as e:
            raise TypeError(
                f"acq.write_pa(0, b'') raised: {e!r}; "
                "write_pa must never raise (return False instead)"
            ) from e
        if not isinstance(wresult, bool):
            raise TypeError(
                f"acq.write_pa must return bool, got {type(wresult).__name__}"
            )
