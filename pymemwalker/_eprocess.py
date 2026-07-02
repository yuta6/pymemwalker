"""EPROCESS chain walking and SectionBaseAddress offset discovery.

Once ``_kernel.discover_offsets`` has located the four core EPROCESS
field offsets (DTB / Name / PID / ActiveProcessLinks), this module walks
the circular ``ActiveProcessLinks`` list to enumerate all processes, and
infers the ``SectionBaseAddress`` offset from a user-mode process's
contents.
"""
import struct
from dataclasses import dataclass
from typing import Optional

from ._paging import Paging


# Canonical kernel-space virtual address minimum on x64.
KERNEL_VA_MIN = 0xFFFF_0000_0000_0000
# Canonical user-space virtual address maximum on x64 (48-bit canonical).
USER_VA_MAX = 0x0000_7FFF_FFFF_FFFF


@dataclass
class ProcessInfo:
    """Basic info about one process. Returned by ``Walker.list_processes``."""
    pid: int
    name: str
    cr3: int          # DirectoryTableBase: root of this process's page tables.
    base: int         # SectionBaseAddress: main EXE image base VA. 0 if unknown.
    eproc_va: int     # Kernel virtual address of this EPROCESS struct.


def list_processes(
    paging: Paging,
    kernel_cr3: int,
    offsets: dict,
) -> list[ProcessInfo]:
    """Walk the circular ActiveProcessLinks chain to enumerate all processes.

    Starts at the System process (whose PA is known from ``discover_offsets``)
    and follows Flink pointers until coming back to System.

    If ``offsets`` contains ``SectionBaseAddress``, each process's image base
    is populated; otherwise ``base=0`` for every entry.
    """
    apl_off = offsets['ActiveProcessLinks']
    system_eproc_pa = offsets['eprocess_pa']

    # Read System's ActiveProcessLinks directly via PA (its VA isn't known yet).
    system_apl_data = paging.read_pa(system_eproc_pa + apl_off, 16)
    system_flink, _ = struct.unpack('<QQ', system_apl_data)

    # Recover System's own ActiveProcessLinks VA: the next process's Blink
    # (offset +8 within its ActiveProcessLinks) points back to it.
    next_blink_data = paging.read_va(kernel_cr3, system_flink + 8, 8)
    if len(next_blink_data) != 8:
        return []
    system_apl_va = struct.unpack('<Q', next_blink_data)[0]
    system_eproc_va = system_apl_va - apl_off

    results: list[ProcessInfo] = []

    # System first; read it via PA since we still have it.
    system_info = _read_eprocess_via_va(paging, kernel_cr3, system_eproc_va, offsets)
    if system_info is None:
        system_info = _read_eprocess_via_pa(paging, system_eproc_pa, offsets, system_eproc_va)
    results.append(system_info)

    # Walk Flinks until we cycle back.
    current_eproc_va = system_flink - apl_off
    visited: set[int] = {system_eproc_va}

    while current_eproc_va not in visited:
        visited.add(current_eproc_va)
        info = _read_eprocess_via_va(paging, kernel_cr3, current_eproc_va, offsets)
        if info is None:
            break
        results.append(info)

        flink_data = paging.read_va(kernel_cr3, current_eproc_va + apl_off, 8)
        if len(flink_data) != 8:
            break
        next_apl_va = struct.unpack('<Q', flink_data)[0]
        if next_apl_va < KERNEL_VA_MIN:
            break                          # corrupt VA, chain broken
        current_eproc_va = next_apl_va - apl_off

    return results


def _read_eprocess_via_va(
    paging: Paging,
    kernel_cr3: int,
    eproc_va: int,
    offsets: dict,
) -> Optional[ProcessInfo]:
    """Build a ProcessInfo by reading EPROCESS fields through VA translation."""
    pid_data = paging.read_va(kernel_cr3, eproc_va + offsets['UniqueProcessId'], 8)
    if len(pid_data) != 8:
        return None
    pid = struct.unpack('<Q', pid_data)[0]

    name_data = paging.read_va(kernel_cr3, eproc_va + offsets['ImageFileName'], 15)
    name = name_data.rstrip(b'\x00').decode(errors='replace')

    cr3_data = paging.read_va(kernel_cr3, eproc_va + offsets['DirectoryTableBase'], 8)
    if len(cr3_data) != 8:
        return None
    cr3 = struct.unpack('<Q', cr3_data)[0]

    base = _resolve_image_base(paging, kernel_cr3, eproc_va, cr3, offsets)

    return ProcessInfo(pid=pid, name=name, cr3=cr3, base=base, eproc_va=eproc_va)


def _read_eprocess_via_pa(
    paging: Paging,
    eproc_pa: int,
    offsets: dict,
    eproc_va: int,
) -> ProcessInfo:
    """Build a ProcessInfo by reading EPROCESS fields directly from PA.

    Used for the System process on the very first read, before any VA
    translation against the chain has been established.
    """
    pid = struct.unpack('<Q', paging.read_pa(eproc_pa + offsets['UniqueProcessId'], 8))[0]
    name_data = paging.read_pa(eproc_pa + offsets['ImageFileName'], 15)
    name = name_data.rstrip(b'\x00').decode(errors='replace')
    cr3 = struct.unpack('<Q', paging.read_pa(eproc_pa + offsets['DirectoryTableBase'], 8))[0]

    # PA-read variant of the base resolver. The PEB lookup still needs VA
    # translation for the user-mode PEB itself, so we pass eproc_va too.
    base = _resolve_image_base_pa(paging, eproc_pa, eproc_va, cr3, offsets)

    return ProcessInfo(pid=pid, name=name, cr3=cr3, base=base, eproc_va=eproc_va)


def _resolve_image_base(
    paging: Paging,
    kernel_cr3: int,
    eproc_va: int,
    proc_cr3: int,
    offsets: dict,
) -> int:
    """Read the process's main-EXE image base.

    Strategy (in order):

      1. ``Peb`` offset is known — read the PEB VA from EPROCESS via the
         kernel CR3, then read ``PEB.ImageBaseAddress`` (+0x10) via the
         **process's own CR3**. This is the modern Windows path; the
         ``SectionBaseAddress`` field was removed in recent builds.

      2. ``SectionBaseAddress`` offset is known — read the user-mode VA
         directly from EPROCESS via the kernel CR3. Used as a fallback
         for older Windows builds where that field still exists.

      3. Neither offset discovered yet — returns 0.
    """
    if 'Peb' in offsets:
        peb_ptr = paging.read_va(kernel_cr3, eproc_va + offsets['Peb'], 8)
        if len(peb_ptr) == 8:
            peb_va = struct.unpack('<Q', peb_ptr)[0]
            if peb_va and proc_cr3:
                base_bytes = paging.read_va(proc_cr3, peb_va + 0x10, 8)
                if len(base_bytes) == 8:
                    return struct.unpack('<Q', base_bytes)[0]
    if 'SectionBaseAddress' in offsets:
        base_bytes = paging.read_va(kernel_cr3, eproc_va + offsets['SectionBaseAddress'], 8)
        if len(base_bytes) == 8:
            return struct.unpack('<Q', base_bytes)[0]
    return 0


def _resolve_image_base_pa(
    paging: Paging,
    eproc_pa: int,
    eproc_va: int,
    proc_cr3: int,
    offsets: dict,
) -> int:
    """Same as ``_resolve_image_base`` but reads the PEB pointer from PA
    (used for the very first System read where we know only the PA)."""
    if 'Peb' in offsets:
        peb_ptr = paging.read_pa(eproc_pa + offsets['Peb'], 8)
        if len(peb_ptr) == 8:
            peb_va = struct.unpack('<Q', peb_ptr)[0]
            if peb_va and proc_cr3:
                base_bytes = paging.read_va(proc_cr3, peb_va + 0x10, 8)
                if len(base_bytes) == 8:
                    return struct.unpack('<Q', base_bytes)[0]
    if 'SectionBaseAddress' in offsets:
        base_bytes = paging.read_pa(eproc_pa + offsets['SectionBaseAddress'], 8)
        if len(base_bytes) == 8:
            return struct.unpack('<Q', base_bytes)[0]
    return 0


# Processes that have NO user-mode PEB. They live in kernel space only
# (System, the Secure System enclave, Registry, MemCompression, etc.) —
# we must not pick them as the "user" reference when looking for the
# Peb offset, or every offset will look like 0.
_NO_PEB_NAMES = {
    "system",
    "secure system",
    "registry",
    "memcompression",
    "minimal",
}

# Preferred references for the Peb-offset search, in priority order.
# These are all early-boot session-0 processes — stable layout, never
# paged out, deterministic by name. We use this priority so that the
# search converges in one iteration on a healthy system, and so the
# behaviour is reproducible across runs (MemProcFS uses smss.exe by
# the same rationale).
_PEB_PRIORITY_NAMES = (
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
)


def discover_peb_offset(
    paging: Paging,
    kernel_cr3: int,
    offsets: dict,
    processes: list[ProcessInfo],
) -> Optional[int]:
    """Infer the EPROCESS.Peb offset using the SYSTEM-vs-user contrast.

    Strategy (close to MemProcFS's ``VmmWinProcess_OffsetLocator64``):

      ① System has ``Peb == 0`` (kernel-only, no user-mode address space).
      ② A genuinely user-mode process (smss.exe, etc.) has a valid
         user-VA there.
      ③ Reading ``PEB.ImageBaseAddress`` (PEB+0x10) through that process's
         own CR3 yields another valid user VA.
      ④ That VA's first two bytes are ``"MZ"`` (the main EXE's PE header).

    The kernel-only processes listed in ``_NO_PEB_NAMES`` are filtered
    out so they aren't used as the "user" reference (they also have
    Peb=0 and would defeat check ②).
    """
    system = next((p for p in processes if p.pid == 4), None)
    if system is None:
        return None

    real_user_procs = [
        p for p in processes
        if p.pid not in (0, 4)
        and p.cr3
        and p.name.lower() not in _NO_PEB_NAMES
    ]
    if len(real_user_procs) < 2:
        return None

    # Sort references by priority — smss.exe first, then other early-boot
    # session-0 processes, then everything else (chain order).
    def _priority(p: ProcessInfo) -> int:
        try:
            return _PEB_PRIORITY_NAMES.index(p.name.lower())
        except ValueError:
            return len(_PEB_PRIORITY_NAMES)
    real_user_procs.sort(key=_priority)

    system_data = paging.read_va(kernel_cr3, system.eproc_va, 0x1000)
    if len(system_data) < 0x1000:
        return None

    # Try the first few real user processes as the reference — paged-out
    # PEBs occasionally break a single sample, so we round-robin.
    for first in real_user_procs[:5]:
        user_data = paging.read_va(kernel_cr3, first.eproc_va, 0x1000)
        if len(user_data) < 0x1000:
            continue

        candidates: list[int] = []
        for off in range(0, 0x1000 - 8, 8):
            if struct.unpack_from('<Q', system_data, off)[0] != 0:
                continue                          # ① System must be 0
            peb_va = struct.unpack_from('<Q', user_data, off)[0]
            if peb_va == 0 or peb_va > USER_VA_MAX or (peb_va & 0xFFF):
                continue                          # ② user VA, page-aligned

            ib_bytes = paging.read_va(first.cr3, peb_va + 0x10, 8)
            if len(ib_bytes) != 8:
                continue
            image_base = struct.unpack('<Q', ib_bytes)[0]
            if image_base == 0 or image_base > USER_VA_MAX or (image_base & 0xFFF):
                continue

            header = paging.read_va(first.cr3, image_base, 2)
            if header != b'MZ':
                continue                          # ④
            candidates.append(off)

        # Pick verifiers with DISTINCT names. Windows runs many copies of
        # csrss.exe (one per session); taking the first three by priority
        # would grab three csrss siblings, and if their PEBs are all paged
        # out the correct offset gets rejected. Distinct names guarantee a
        # diverse set (csrss / wininit / services / lsass ...), so at least
        # one resident PEB is almost always present.
        verify_procs = _distinct_by_name(
            [p for p in real_user_procs if p is not first], 4
        )
        for off in candidates:
            if _verify_peb_offset(paging, kernel_cr3, verify_procs, off):
                return off

    return None


def _distinct_by_name(
    processes: list[ProcessInfo], limit: int
) -> list[ProcessInfo]:
    """First ``limit`` processes with pairwise-distinct (case-insensitive)
    names, preserving input order."""
    out: list[ProcessInfo] = []
    seen: set[str] = set()
    for p in processes:
        key = p.name.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
        if len(out) >= limit:
            break
    return out


def _verify_peb_offset(
    paging: Paging,
    kernel_cr3: int,
    processes: list[ProcessInfo],
    candidate_off: int,
) -> bool:
    """Confirm a candidate Peb offset across several reference processes.

    Each process falls into one of three buckets:

      • confirm      — the full ``EPROCESS+off → PEB → ImageBaseAddress →
                       "MZ"`` chain resolves.
      • contradict   — the offset provably does NOT hold a PEB pointer: a
                       non-zero value that is not a page-aligned user VA, or
                       an ImageBase that IS a valid user VA but whose header
                       is readable and not ``"MZ"``.
      • inconclusive — the pointer looks right but the PEB page (or the image
                       header page) is paged out, so the chain can't be
                       completed. Also ``peb_va == 0`` (some processes
                       legitimately have no PEB).

    A paged-out PEB is *inconclusive*, not a failure. In a live capture,
    non-session-0 copies of a process (e.g. per-session ``csrss.exe``)
    frequently have their PEB paged out; counting those as failures used to
    reject an otherwise-correct offset whenever the verifiers happened to be
    several paged-out siblings of the same process.

    Accept when at least one process confirms and none contradict.
    """
    confirms = 0
    for p in processes:
        peb_data = paging.read_va(kernel_cr3, p.eproc_va + candidate_off, 8)
        if len(peb_data) != 8:
            continue                                  # inconclusive
        peb_va = struct.unpack('<Q', peb_data)[0]
        if peb_va == 0:
            continue                                  # inconclusive (no PEB)
        if peb_va > USER_VA_MAX or (peb_va & 0xFFF):
            return False                              # contradiction: not a PEB ptr
        ib_bytes = paging.read_va(p.cr3, peb_va + 0x10, 8)
        if len(ib_bytes) != 8:
            continue                                  # inconclusive (PEB paged out)
        image_base = struct.unpack('<Q', ib_bytes)[0]
        if image_base == 0 or image_base > USER_VA_MAX or (image_base & 0xFFF):
            continue                                  # inconclusive
        header = paging.read_va(p.cr3, image_base, 2)
        if header == b'MZ':
            confirms += 1
        elif len(header) == 2:
            return False                              # contradiction: not an image
        # else: header page unreadable -> inconclusive
    return confirms >= 1


def discover_section_base(
    paging: Paging,
    kernel_cr3: int,
    offsets: dict,
    processes: list[ProcessInfo],
) -> Optional[int]:
    """Infer the SectionBaseAddress offset by inspecting a user-mode EPROCESS.

    A QWORD at offset X within EPROCESS is a SectionBaseAddress candidate when:
      - It is a non-zero user-space VA (``0 < value <= USER_VA_MAX``).
      - It is page-aligned (``value & 0xFFF == 0``).
      - Walking it via the owning process's CR3 yields a page whose first
        two bytes are ``b'MZ'`` (PE image header signature).

    For robustness, a candidate offset is only accepted if it satisfies
    these conditions for several distinct user processes.
    """
    candidates_proc: list[ProcessInfo] = [
        p for p in processes
        if p.pid != 4 and p.pid != 0 and p.cr3 != 0
    ]
    if len(candidates_proc) < 2:
        return None

    first = candidates_proc[0]
    eproc_data = paging.read_va(kernel_cr3, first.eproc_va, 0x1000)
    if len(eproc_data) < 0x1000:
        return None

    candidate_offsets: list[int] = []
    for off in range(0, 0x1000 - 8, 8):
        value = struct.unpack_from('<Q', eproc_data, off)[0]
        if value == 0 or value > USER_VA_MAX or (value & 0xFFF):
            continue
        header = paging.read_va(first.cr3, value, 2)
        if header == b'MZ':
            candidate_offsets.append(off)

    if not candidate_offsets:
        return None

    for off in candidate_offsets:
        if _verify_section_base_offset(paging, kernel_cr3, candidates_proc[1:4], off):
            return off

    return None


def _verify_section_base_offset(
    paging: Paging,
    kernel_cr3: int,
    processes: list[ProcessInfo],
    candidate_off: int,
) -> bool:
    """Check that ``candidate_off`` resolves to a valid 'MZ' header for every
    process in ``processes``."""
    for p in processes:
        value_data = paging.read_va(kernel_cr3, p.eproc_va + candidate_off, 8)
        if len(value_data) != 8:
            return False
        value = struct.unpack('<Q', value_data)[0]
        if value == 0 or value > USER_VA_MAX or (value & 0xFFF):
            return False
        header = paging.read_va(p.cr3, value, 2)
        if header != b'MZ':
            return False
    return True
