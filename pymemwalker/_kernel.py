"""Kernel CR3 discovery and System EPROCESS resolution.

These run once at ``Walker.__init__`` time. All discovery is done by
reading physical memory and parsing kernel-image PE headers in situ —
no symbol server, no PDB downloads.

Two-step process (mirrors MemProcFS's canonical pipeline):

  1. ``find_kernel_cr3`` — parse the Processor Start Block ("Low Stub")
     in the first 1 MiB of physical memory to obtain the kernel PML4 PA
     and a kernel VA inside ntoskrnl.exe.

  2. ``discover_offsets`` —
       a. walk backwards in kernel VA from the entry VA until we hit
          ntoskrnl.exe's MZ + PE header,
       b. parse the PE export table to locate ``PsInitialSystemProcess``,
       c. read its value to obtain the System EPROCESS VA,
       d. translate to PA, read the struct, derive field offsets.

No physical-memory scanning is needed past Phase 1.
"""
import logging
import struct
import time
from typing import Optional, Tuple

from ._acquisition import PhysicalMemoryAcquisition

_log = logging.getLogger("pymemwalker")


# Offset of DirectoryTableBase inside _EPROCESS. This is _KPROCESS.DirectoryTableBase,
# which has been at 0x28 since Win7 — we treat it as a fixed Windows kernel convention.
DTB_OFFSET_IN_EPROCESS = 0x28

# Upper bound on EPROCESS size (actual is ~0x900 on modern Windows).
EPROCESS_SIZE_MAX = 0x1000

# A canonical kernel-space virtual address on x64 has its top 16 bits set.
KERNEL_VA_MIN = 0xFFFF_0000_0000_0000


# ============================================================
# Phase 1: kernel CR3 discovery via Low Stub (Processor Start Block)
# ============================================================
#
# Windows places a Processor Start Block — the real-mode stub the BSP/AP
# CPUs jump to at boot — at a 4 KiB-aligned page below 1 MiB of physical
# memory. The page begins with the signature 0x00000001000600E9 (a real-
# mode JMP plus a magic constant) and stores the kernel PML4 physical
# address at offset 0xA0 from page start.
#
# This is the canonical first step MemProcFS uses; see
# VmmWinInit_DTB_FindValidate_X64_LowStub() in vmm/vmmwininit.c.
# Self-referencing-PML4 scan is only their fallback when this fails.

# Scan covers physical pages 0x1000 .. 0x100000 (mirrors MemProcFS).
LOW_STUB_SCAN_LIMIT  = 0x100000

# Signature: real-mode JMP plus magic at the top of the stub page.
# Byte 1 (= the JMP offset's low byte) varies between builds, so the
# match is masked. Equivalent C: (page_qword & MASK) == SIGNATURE.
LOW_STUB_SIGNATURE   = 0x00000001000600E9
LOW_STUB_SIG_MASK    = 0xFFFFFFFFFFFF00FF

# Kernel virtual entry point at +0x70: top bits must match canonical
# kernel-VA prefix and bottom 2 bits must be clear.
LOW_STUB_ENTRY_OFF   = 0x70
LOW_STUB_ENTRY_MASK  = 0xFFFFF80000000003
LOW_STUB_ENTRY_VAL   = 0xFFFFF80000000000

# Kernel PML4 physical address at +0xA0: must be page-aligned and fit
# in the lower 40 bits of physical address space.
LOW_STUB_CR3_OFF     = 0xA0
LOW_STUB_CR3_BADBITS = 0xFFFFFF0000000FFF


def find_kernel_cr3(acq: PhysicalMemoryAcquisition) -> Tuple[int, int]:
    """Discover the kernel CR3 (and entry VA) via Windows' Processor Start Block.

    Mirrors ``VmmWinInit_DTB_FindValidate_X64_LowStub`` in MemProcFS
    (``vmm/vmmwininit.c``): every 4 KiB-aligned page in the first 1 MiB
    is tested for the masked stub signature, a sanity check on the kernel
    entry-point VA, and a sanity check on the PML4 physical address.
    Scans at most 256 pages — returns in well under a second on any
    sane backend.

    Returns ``(kernel_cr3, kernel_entry_va)``. The entry VA is a kernel
    virtual address inside ntoskrnl.exe and is used downstream by
    ``find_ntoskrnl_base`` to locate the kernel image.
    """
    t0 = time.perf_counter()

    for pa in range(0x1000, LOW_STUB_SCAN_LIMIT, 0x1000):
        page = acq.read_pa(pa, 0x1000)
        if len(page) < LOW_STUB_CR3_OFF + 8:
            continue

        sig = struct.unpack_from('<Q', page, 0)[0]
        if (sig & LOW_STUB_SIG_MASK) != LOW_STUB_SIGNATURE:
            continue

        entry = struct.unpack_from('<Q', page, LOW_STUB_ENTRY_OFF)[0]
        if (entry & LOW_STUB_ENTRY_MASK) != LOW_STUB_ENTRY_VAL:
            continue

        cr3 = struct.unpack_from('<Q', page, LOW_STUB_CR3_OFF)[0]
        if cr3 & LOW_STUB_CR3_BADBITS:
            continue
        if cr3 == 0 or cr3 >= acq.max_pa:
            continue

        elapsed = time.perf_counter() - t0
        _log.info(f"  [find_kernel_cr3] Low Stub at PA=0x{pa:X}, "
              f"kernel CR3 = 0x{cr3:X}, entry VA = 0x{entry:X} "
              f"({elapsed * 1000:.0f} ms)")
        return cr3, entry

    raise RuntimeError(
        "Processor Start Block (Low Stub) not found in the first 1 MiB. "
        "The target is either not Windows x64, has been booted under "
        "unusual conditions, or the acquisition backend is misreporting "
        "low physical memory."
    )


# ============================================================
# Phase 2: ntoskrnl base + PE export resolution + System EPROCESS
# ============================================================
#
# This is MemProcFS's canonical path (see VmmWinInit_FindNtosBase and
# VmmWinInit_FindSystemEPROCESS in vmm/vmmwininit.c):
#
#   1. Walk backwards in kernel VA space from the entry-point VA we
#      already have (from the Low Stub) until we hit an MZ DOS header
#      + PE signature — that's ntoskrnl's image base.
#   2. Parse the kernel image's PE export directory.
#   3. Look up the named export "PsInitialSystemProcess".
#   4. Read 8 bytes at that VA — it is the kernel VA of System EPROCESS.
#   5. Translate to PA, read the struct, derive field offsets from a
#      known-good System EPROCESS (so no false positives possible).
#
# No symbol server, no PDB. The export table is part of the PE image
# itself and lives in kernel memory once Windows has loaded ntoskrnl.

# Walk this far back from the entry VA at most. ntoskrnl is < 20 MiB.
NTOSKRNL_MAX_BACK_SEARCH = 32 * 1024 * 1024

# Accepted image names for the kernel image. Different Windows builds use
# different names; we match any of them case-insensitively.
NTOSKRNL_NAMES = (b"ntoskrnl.exe", b"ntkrnlmp.exe", b"ntoskrnl.efi")


def _read_image_name(paging, kernel_cr3: int, image_base: int, e_lfanew: int) -> Optional[bytes]:
    """Read the module name from a PE's IMAGE_EXPORT_DIRECTORY.Name field.

    Returns the lower-cased name bytes (e.g. ``b"ntoskrnl.exe"``), or
    ``None`` if the PE has no export directory or anything fails along
    the way.
    """
    try:
        nt = paging.read_va(kernel_cr3, image_base + e_lfanew, 0x108)
        if len(nt) < 0x90 or nt[:4] != b'PE\x00\x00':
            return None
        export_rva = struct.unpack_from('<I', nt, 0x88)[0]
        if export_rva == 0:
            return None
        edir = paging.read_va(kernel_cr3, image_base + export_rva, 0x10)
        if len(edir) < 0x10:
            return None
        name_rva = struct.unpack_from('<I', edir, 0x0C)[0]
        name_data = paging.read_va(kernel_cr3, image_base + name_rva, 64)
        null = name_data.find(b'\x00')
        if null < 0:
            return None
        return name_data[:null].lower()
    except Exception:
        return None


def find_ntoskrnl_base(paging, kernel_cr3: int, kernel_entry_va: int) -> int:
    """Locate ntoskrnl.exe's image base by stepping backwards from a known
    kernel-VA inside it.

    Each MZ candidate is validated against the PE export directory's
    module-name field — we keep walking until we hit an image whose name
    matches one of ``NTOSKRNL_NAMES``. This avoids accidentally returning
    the base of some other kernel module (HAL, ci.dll, etc.) that happens
    to be present in the search window.
    """
    pa = kernel_entry_va & ~0xFFF
    limit = max(0, kernel_entry_va - NTOSKRNL_MAX_BACK_SEARCH) & ~0xFFF
    t0 = time.perf_counter()
    candidates_examined: list[tuple[int, Optional[bytes]]] = []

    while pa >= limit:
        dos = paging.read_va(kernel_cr3, pa, 0x40)
        if len(dos) >= 0x40 and dos[:2] == b'MZ':
            e_lfanew = struct.unpack_from('<I', dos, 0x3C)[0]
            if 0 < e_lfanew < 0x1000:
                sig = paging.read_va(kernel_cr3, pa + e_lfanew, 4)
                if sig == b'PE\x00\x00':
                    name = _read_image_name(paging, kernel_cr3, pa, e_lfanew)
                    candidates_examined.append((pa, name))
                    if name is not None and name in NTOSKRNL_NAMES:
                        elapsed = time.perf_counter() - t0
                        _log.info(f"  [find_ntoskrnl_base] {name.decode()} @ "
                              f"VA=0x{pa:X} ({elapsed * 1000:.0f} ms, "
                              f"{len(candidates_examined)} candidate(s) examined)")
                        return pa
        pa -= 0x1000

    seen = "; ".join(
        f"0x{p:X}={n.decode(errors='replace') if n else '<no export>'}"
        for p, n in candidates_examined
    )
    raise RuntimeError(
        f"ntoskrnl base not found scanning back from entry VA 0x{kernel_entry_va:X}. "
        f"Saw {len(candidates_examined)} PE candidate(s): {seen}"
    )


def resolve_pe_export(
    paging,
    kernel_cr3: int,
    image_base: int,
    export_name: str,
) -> int:
    """Resolve a named export inside a PE32+ image loaded at ``image_base``
    (kernel VA). Returns the export's VA. Raises if the image is malformed
    or the name is not present.
    """
    target = export_name.encode()

    dos = paging.read_va(kernel_cr3, image_base, 0x40)
    if dos[:2] != b'MZ':
        raise ValueError(f"not a PE image at VA 0x{image_base:X}")
    e_lfanew = struct.unpack_from('<I', dos, 0x3C)[0]

    nt_va = image_base + e_lfanew
    nt = paging.read_va(kernel_cr3, nt_va, 0x108)
    if nt[:4] != b'PE\x00\x00':
        raise ValueError(f"PE signature missing at VA 0x{nt_va:X}")

    magic = struct.unpack_from('<H', nt, 0x18)[0]
    if magic != 0x20B:
        raise ValueError(f"expected PE32+ (Magic=0x20B), got 0x{magic:X}")

    # DataDirectory[0] (Export) lives at OptionalHeader +0x70.
    # OptionalHeader starts at nt +0x18, so absolute is nt +0x88.
    export_rva = struct.unpack_from('<I', nt, 0x88)[0]
    if export_rva == 0:
        raise ValueError("no export directory")

    # IMAGE_EXPORT_DIRECTORY is 40 bytes.
    edir = paging.read_va(kernel_cr3, image_base + export_rva, 40)
    num_names         = struct.unpack_from('<I', edir, 0x18)[0]
    addr_funcs_rva    = struct.unpack_from('<I', edir, 0x1C)[0]
    addr_names_rva    = struct.unpack_from('<I', edir, 0x20)[0]
    addr_ordinals_rva = struct.unpack_from('<I', edir, 0x24)[0]

    if num_names == 0:
        raise ValueError("no named exports")

    name_ptrs = paging.read_va(kernel_cr3,
                               image_base + addr_names_rva,
                               num_names * 4)

    for i in range(num_names):
        name_rva = struct.unpack_from('<I', name_ptrs, i * 4)[0]
        name_data = paging.read_va(kernel_cr3, image_base + name_rva, 256)
        null = name_data.find(b'\x00')
        if null < 0 or name_data[:null] != target:
            continue

        ord_data = paging.read_va(kernel_cr3,
                                  image_base + addr_ordinals_rva + i * 2, 2)
        ordinal = struct.unpack('<H', ord_data)[0]

        func_data = paging.read_va(kernel_cr3,
                                   image_base + addr_funcs_rva + ordinal * 4, 4)
        func_rva = struct.unpack('<I', func_data)[0]
        return image_base + func_rva

    raise ValueError(f"export not found: {export_name}")




def discover_offsets(
    paging,
    kernel_cr3: int,
    kernel_entry_va: int,
) -> dict:
    """Locate the System process and derive EPROCESS field offsets.

    Uses MemProcFS's canonical path: ntoskrnl image base from the Low
    Stub's entry VA, then the exported global ``PsInitialSystemProcess``
    to obtain the System EPROCESS VA directly. No physical scan, no
    false positives.

    Returned dict keys:
      eprocess_pa         physical address of System EPROCESS
      eprocess_va         kernel virtual address of System EPROCESS
      DirectoryTableBase  0x28 (constant)
      ImageFileName       offset within EPROCESS
      UniqueProcessId     offset within EPROCESS
      ActiveProcessLinks  offset within EPROCESS

    ``SectionBaseAddress`` is intentionally not derived here — System
    has no main image, so we leave that to a later pass against a user
    process (``eprocess.discover_section_base``).
    """
    t0 = time.perf_counter()

    ntos_base = find_ntoskrnl_base(paging, kernel_cr3, kernel_entry_va)
    ps_init_va = resolve_pe_export(paging, kernel_cr3, ntos_base,
                                   "PsInitialSystemProcess")
    _log.info(f"  [discover_offsets] PsInitialSystemProcess @ VA=0x{ps_init_va:X}")

    eproc_va_bytes = paging.read_va(kernel_cr3, ps_init_va, 8)
    if len(eproc_va_bytes) != 8:
        raise RuntimeError("could not read PsInitialSystemProcess pointer")
    system_eproc_va = struct.unpack('<Q', eproc_va_bytes)[0]
    if system_eproc_va < KERNEL_VA_MIN:
        raise RuntimeError(
            f"PsInitialSystemProcess holds non-kernel VA 0x{system_eproc_va:X}"
        )
    _log.info(f"  [discover_offsets] System EPROCESS @ VA=0x{system_eproc_va:X}")

    system_eproc_pa = paging.va_to_pa(kernel_cr3, system_eproc_va)
    if system_eproc_pa is None:
        raise RuntimeError(
            f"could not translate System EPROCESS VA 0x{system_eproc_va:X}"
        )
    _log.info(f"  [discover_offsets] System EPROCESS @ PA=0x{system_eproc_pa:X}")

    eproc_data = paging.read_pa(system_eproc_pa, EPROCESS_SIZE_MAX)
    if len(eproc_data) < EPROCESS_SIZE_MAX:
        raise RuntimeError("partial read of System EPROCESS")

    # Sanity: DTB at +0x28 should equal kernel_cr3. If it doesn't, we may
    # be looking at a newer build that stores user/kernel DTBs differently.
    dtb_stored = struct.unpack_from('<Q', eproc_data, DTB_OFFSET_IN_EPROCESS)[0]
    if dtb_stored != kernel_cr3:
        _log.warning(f"  [discover_offsets] EPROCESS+0x28 = 0x{dtb_stored:X} "
              f"!= kernel_cr3 = 0x{kernel_cr3:X} (encoded DTB?)")

    # We have known-good System EPROCESS bytes — derive field offsets.
    offsets = _verify_system_eprocess(eproc_data)
    if offsets is None:
        raise RuntimeError(
            "System EPROCESS bytes lack expected layout patterns "
            "(\"System\\0\", PID=4, kernel-VA LIST_ENTRY); the Windows "
            "build may have an unfamiliar struct layout."
        )

    offsets['eprocess_pa'] = system_eproc_pa
    offsets['eprocess_va'] = system_eproc_va
    offsets['DirectoryTableBase'] = DTB_OFFSET_IN_EPROCESS

    elapsed = time.perf_counter() - t0
    _log.info(f"  [discover_offsets] complete in {elapsed:.2f}s")
    return offsets


def _verify_system_eprocess(eproc_data: bytes) -> Optional[dict]:
    """Confirm an EPROCESS candidate is the System process and derive offsets.

    Three checks (any failure rejects the candidate):
      - "System\\0" is present somewhere in the struct (ImageFileName field).
      - The QWORD value 4 is present somewhere (UniqueProcessId field).
      - The 16 bytes immediately after UniqueProcessId form a LIST_ENTRY
        with both Flink and Blink in the canonical kernel-VA range.
    """
    # ImageFileName
    name_off = eproc_data.find(b'System\x00')
    if name_off < 0:
        return None

    # UniqueProcessId — HANDLE is ULONG_PTR (8 bytes on x64).
    pid_off = None
    for off in range(0, len(eproc_data) - 8, 8):
        if struct.unpack_from('<Q', eproc_data, off)[0] == 4:
            pid_off = off
            break
    if pid_off is None:
        return None

    # ActiveProcessLinks immediately follows UniqueProcessId by convention.
    apl_off = pid_off + 8
    if apl_off + 16 > len(eproc_data):
        return None
    flink, blink = struct.unpack_from('<QQ', eproc_data, apl_off)
    if not (flink >= KERNEL_VA_MIN and blink >= KERNEL_VA_MIN):
        return None

    return {
        'ImageFileName':      name_off,
        'UniqueProcessId':    pid_off,
        'ActiveProcessLinks': apl_off,
    }
