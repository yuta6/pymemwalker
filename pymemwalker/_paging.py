"""x86-64 4-level page walk: virtual-address to physical-address translation.

Only 4-level paging is supported (PML4 -> PDPT -> PD -> PT).
5-level (LA57), PAE, and legacy 32-bit modes are out of scope.

PTE bit layout (Intel SDM Vol 3, Table 4-15):
  bit 0     : Present (P)
  bit 7     : Page Size (PS) - on PDPT/PD entries, 1 means a huge/large page
  bits 12-51: Physical page frame address
  bit 63    : NX (ignored here)

Virtual address breakdown (48-bit canonical):
  bits 47-39: PML4 index (9 bits)
  bits 38-30: PDPT index (9 bits)
  bits 29-21: PD   index (9 bits)
  bits 20-12: PT   index (9 bits)
  bits 11-0 : Page offset (12 bits)
"""
import struct
from typing import Optional

from ._acquisition import PhysicalMemoryAcquisition


# Mask for the physical page frame address inside a PTE (bits 12-51).
PFN_MASK = 0x000F_FFFF_FFFF_F000
# PTE present bit.
PTE_PRESENT = 1
# PTE page-size bit: on PDPT entries marks a 1 GB huge page,
# on PD entries marks a 2 MB large page.
PTE_PAGE_SIZE = 1 << 7


def va_to_pa(acq: PhysicalMemoryAcquisition, cr3: int, va: int) -> Optional[int]:
    """Walk the 4-level page tables to translate VA to PA.

    Returns None if any level along the path is paged out or invalid.
    This function is stateless — wrap it with the ``Paging`` class below
    to get a TLB-style translation cache and a physical page cache.
    """
    pml4_idx = (va >> 39) & 0x1FF
    pdpt_idx = (va >> 30) & 0x1FF
    pd_idx   = (va >> 21) & 0x1FF
    pt_idx   = (va >> 12) & 0x1FF
    offset   = va & 0xFFF

    # PML4
    pml4e_bytes = acq.read_pa((cr3 & PFN_MASK) + pml4_idx * 8, 8)
    if len(pml4e_bytes) != 8:
        return None
    pml4e = struct.unpack('<Q', pml4e_bytes)[0]
    if not (pml4e & PTE_PRESENT):
        return None

    # PDPT
    pdpte_bytes = acq.read_pa((pml4e & PFN_MASK) + pdpt_idx * 8, 8)
    if len(pdpte_bytes) != 8:
        return None
    pdpte = struct.unpack('<Q', pdpte_bytes)[0]
    if not (pdpte & PTE_PRESENT):
        return None
    if pdpte & PTE_PAGE_SIZE:                          # 1 GB huge page
        return (pdpte & 0x000F_FFFF_C000_0000) + (va & 0x3FFF_FFFF)

    # PD
    pde_bytes = acq.read_pa((pdpte & PFN_MASK) + pd_idx * 8, 8)
    if len(pde_bytes) != 8:
        return None
    pde = struct.unpack('<Q', pde_bytes)[0]
    if not (pde & PTE_PRESENT):
        return None
    if pde & PTE_PAGE_SIZE:                            # 2 MB large page
        return (pde & 0x000F_FFFF_FFE0_0000) + (va & 0x001F_FFFF)

    # PT
    pte_bytes = acq.read_pa((pde & PFN_MASK) + pt_idx * 8, 8)
    if len(pte_bytes) != 8:
        return None
    pte = struct.unpack('<Q', pte_bytes)[0]
    if not (pte & PTE_PRESENT):
        return None
    return (pte & PFN_MASK) + offset


class Paging:
    """Caching wrapper around ``va_to_pa`` and physical reads.

    Two layers of cache:
      _tlb         : (cr3, va_page) -> pa_page    short-lived; clear with flush_translations()
      _page_cache  : pa_page        -> 4KB bytes  long-lived if the backend is a snapshot
    """

    def __init__(self, acq: PhysicalMemoryAcquisition, cache_pages: bool = True):
        self._acq = acq
        self._tlb: dict[tuple[int, int], int] = {}
        self._page_cache: dict[int, bytes] = {}
        # cache_pages=False: never retain physical page contents (every read
        # hits the backend = always fresh). For LIVE backends where memory
        # changes every frame, this removes the need to flush_pages() each
        # frame. The TLB (translations) is unaffected. Snapshots should keep
        # this True (a dump never changes; caching is a big win).
        self._cache_pages = cache_pages

    def va_to_pa(self, cr3: int, va: int) -> Optional[int]:
        va_page = va & ~0xFFF
        offset = va & 0xFFF
        key = (cr3, va_page)
        if key in self._tlb:
            return self._tlb[key] + offset
        pa = va_to_pa(self._acq, cr3, va_page)
        if pa is None:
            return None
        self._tlb[key] = pa
        return pa + offset

    def read_pa(self, pa: int, size: int) -> bytes:
        """Read from physical memory, caching whole 4KB pages."""
        out = bytearray()
        while size > 0:
            page = pa & ~0xFFF
            in_page = pa & 0xFFF
            take = min(0x1000 - in_page, size)
            if self._cache_pages and page in self._page_cache:
                chunk = self._page_cache[page]
            else:
                chunk = self._acq.read_pa(page, 0x1000)
                if self._cache_pages and len(chunk) == 0x1000:
                    self._page_cache[page] = chunk
            if len(chunk) >= in_page + take:
                out.extend(chunk[in_page:in_page + take])
            else:
                out.extend(b'\x00' * take)
            pa += take
            size -= take
        return bytes(out)

    def read_va(self, cr3: int, va: int, size: int) -> bytes:
        """Read ``size`` bytes starting at virtual address ``va``.

        Splits the request at 4KB page boundaries internally. Bytes
        belonging to paged-out / invalid pages are returned as ``\\x00``.
        """
        out = bytearray()
        while size > 0:
            page_va = va & ~0xFFF
            in_page = va & 0xFFF
            take = min(0x1000 - in_page, size)
            pa_page = self.va_to_pa(cr3, page_va)
            if pa_page is None:
                out.extend(b'\x00' * take)
            else:
                out.extend(self.read_pa((pa_page & ~0xFFF) | in_page, take))
            va += take
            size -= take
        return bytes(out)

    def read_va_scatter(self, cr3: int, requests: list) -> list:
        """Read multiple ``(va, size)`` regions in one batch.

        Translates all VAs to PAs, deduplicates physical pages, reads
        them via a single ``read_pa_scatter`` call, then assembles the
        requested byte ranges. Cross-page requests are handled correctly.

        Returns a list of ``bytes`` in the same order as ``requests``.
        Invalid/paged-out regions are zero-filled, matching ``read_va``.
        """
        # Phase 1: translate all VA pages and collect unique PA pages.
        # Each request may span multiple pages; track (req_idx, offset_in_result, pa, in_page, take).
        segments = []
        unique_pages = {}
        for req_idx, (va, size) in enumerate(requests):
            result_off = 0
            rem = size
            cur_va = va
            while rem > 0:
                page_va = cur_va & ~0xFFF
                in_page = cur_va & 0xFFF
                take = min(0x1000 - in_page, rem)
                pa_page = self.va_to_pa(cr3, page_va)
                segments.append((req_idx, result_off, pa_page, in_page, take))
                if pa_page is not None and pa_page not in unique_pages:
                    unique_pages[pa_page] = None
                cur_va += take
                result_off += take
                rem -= take

        # Phase 2: batch-read all unique physical pages.
        if unique_pages:
            page_list = list(unique_pages.keys())
            page_data = self._acq.read_pa_scatter(
                [(pa, 0x1000) for pa in page_list]
            )
            for pa, data in zip(page_list, page_data):
                unique_pages[pa] = data

        # Phase 3: assemble results from cached page data.
        results = [bytearray(size) for _, (_, size) in enumerate(requests)]
        for req_idx, result_off, pa_page, in_page, take in segments:
            if pa_page is None:
                pass  # already zero-filled
            else:
                page = unique_pages[pa_page]
                if page and len(page) >= in_page + take:
                    results[req_idx][result_off:result_off + take] = page[in_page:in_page + take]

        return [bytes(r) for r in results]

    def write_pa(self, pa: int, data: bytes) -> bool:
        """Write ``data`` to physical memory. Invalidates any cached
        page that overlaps the written range. Returns the backend's
        success indication; partial writes propagate as ``False``."""
        if not data:
            return True
        ok = self._acq.write_pa(pa, data)
        # Invalidate any cached page overlapping the written range so
        # subsequent reads see the new contents.
        start_page = pa & ~0xFFF
        end_page = (pa + len(data) - 1) & ~0xFFF
        page = start_page
        while page <= end_page:
            self._page_cache.pop(page, None)
            page += 0x1000
        return ok

    def write_va(self, cr3: int, va: int, data: bytes) -> bool:
        """Write ``data`` starting at virtual address ``va``.

        Splits the request at 4KB page boundaries and translates each
        page through ``cr3``. Returns ``False`` on the first failure
        (including any page that cannot be translated).
        """
        pos = 0
        while pos < len(data):
            page_va = (va + pos) & ~0xFFF
            in_page = (va + pos) & 0xFFF
            take = min(0x1000 - in_page, len(data) - pos)
            pa_page = self.va_to_pa(cr3, page_va)
            if pa_page is None:
                return False
            ok = self.write_pa((pa_page & ~0xFFF) | in_page, data[pos:pos + take])
            if not ok:
                return False
            pos += take
        return True

    def invalidate_va(self, cr3: int, va: int, size: int) -> None:
        """Drop the cached physical pages backing ``[va, va+size)`` so the
        next read re-fetches them from the backend.

        Use on live backends to force a fresh read of a region that may
        have changed since it was last cached — e.g. re-reading an
        EPROCESS field whose value is volatile. The VA->PA translation
        (TLB) is left intact: page-table mappings are stable even when the
        page *contents* change. No-op if the page cache is empty.
        """
        end = va + size - 1
        page_va = va & ~0xFFF
        while page_va <= end:
            pa = self.va_to_pa(cr3, page_va)
            if pa is not None:
                self._page_cache.pop(pa & ~0xFFF, None)
            page_va += 0x1000

    def invalidate_translation(self, cr3: int, va: int, size: int) -> None:
        """Drop the cached VA->PA translations for ``[va, va+size)`` so the
        next read re-walks the page tables.

        The targeted form of ``flush_translations`` — like the CPU's
        ``INVLPG`` versus a full TLB flush. Use when a region's *mapping*
        may have changed (page remapped / freed / paged in to a different
        frame) and a stale translation is now returning the wrong physical
        page. ``invalidate_va`` drops page *contents*; this drops the
        *translation*. No-op for pages not currently cached.
        """
        end = va + size - 1
        page = va & ~0xFFF
        while page <= end:
            self._tlb.pop((cr3, page), None)
            page += 0x1000

    def flush_translations(self) -> None:
        """Drop the TLB cache. Keeps the physical page cache."""
        self._tlb.clear()

    def flush_pages(self) -> None:
        """Drop the physical page cache. Needed only for live backends
        where the underlying memory can change between reads."""
        self._page_cache.clear()
