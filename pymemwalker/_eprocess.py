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

# EPROCESS.Peb fuzzing window, mirroring MemProcFS VmmWinProcess_OffsetLocator64
# (it scans [0x280, 0x580) for the Peb slot). References tried before giving up.
PEB_SCAN_LO = 0x280
PEB_SCAN_HI = 0x580
PEB_MAX_REFS = 8


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
    and follows Flink pointers until coming back to System. The standalone
    list head inside ntoskrnl is traversed but is never decoded as EPROCESS.

    If ``offsets`` contains ``SectionBaseAddress``, each process's image base
    is populated; otherwise ``base=0`` for every entry.
    """
    apl_off = offsets['ActiveProcessLinks']
    system_eproc_pa = offsets['eprocess_pa']

    # Read System's ActiveProcessLinks through its known physical address.
    system_apl_data = paging.read_pa(system_eproc_pa + apl_off, 16)
    if len(system_apl_data) != 16:
        return []
    system_flink, _ = struct.unpack('<QQ', system_apl_data)

    system_eproc_va = offsets.get('eprocess_va')
    if system_eproc_va is None:
        # Compatibility with callers supplying only the physical address.
        if system_flink < KERNEL_VA_MIN:
            return []
        next_blink_data = paging.read_va(kernel_cr3, system_flink + 8, 8)
        if len(next_blink_data) != 8:
            return []
        system_apl_va = struct.unpack('<Q', next_blink_data)[0]
        if system_apl_va < KERNEL_VA_MIN:
            return []
        system_eproc_va = system_apl_va - apl_off
    system_apl_va = system_eproc_va + apl_off

    results: list[ProcessInfo] = []

    # System first; read it via PA since we still have it.
    system_info = _read_eprocess_via_va(paging, kernel_cr3, system_eproc_va, offsets)
    if system_info is None:
        system_info = _read_eprocess_via_pa(paging, system_eproc_pa, offsets, system_eproc_va)
    if system_info is None:
        return []
    results.append(system_info)

    # EPROCESS lives in pool memory; a LIST_ENTRY in the kernel image is a
    # list head, including when System is not the first entry in the list.
    ntos_base = offsets.get('ntoskrnl_base', 0)
    ntos_end = ntos_base + offsets.get('ntoskrnl_size', 0)
    current_apl_va = system_flink
    visited: set[int] = {system_apl_va}

    while current_apl_va >= KERNEL_VA_MIN and current_apl_va not in visited:
        visited.add(current_apl_va)
        link_data = paging.read_va(kernel_cr3, current_apl_va, 16)
        if len(link_data) != 16:
            break
        flink, blink = struct.unpack('<QQ', link_data)
        if flink < KERNEL_VA_MIN or blink < KERNEL_VA_MIN:
            break
        if not ntos_base <= current_apl_va < ntos_end:
            info = _read_eprocess_via_va(
                paging, kernel_cr3, current_apl_va - apl_off, offsets
            )
            if info is not None:
                results.append(info)
        current_apl_va = flink

    return results


def _decode_eprocess_fields(
    pid_data: bytes, name_data: bytes, cr3_data: bytes
) -> Optional[tuple[int, str, int]]:
    """Reject incomplete/zero-padded records before exposing ProcessInfo."""
    if len(pid_data) != 8 or len(name_data) != 15 or len(cr3_data) != 8:
        return None
    pid = struct.unpack('<Q', pid_data)[0]
    name = name_data.split(b'\x00', 1)[0].decode(errors='replace')
    # Windows process IDs are DWORDs; a kernel pointer is not a PID. A zero
    # CR3 is allowed for kernel-only processes, so it is not a validity test.
    if pid > 0xFFFFFFFF or not name:
        return None
    return pid, name, struct.unpack('<Q', cr3_data)[0]


def _read_eprocess_via_va(
    paging: Paging,
    kernel_cr3: int,
    eproc_va: int,
    offsets: dict,
) -> Optional[ProcessInfo]:
    """Build a ProcessInfo by reading EPROCESS fields through VA translation."""
    pid_data = paging.read_va(kernel_cr3, eproc_va + offsets['UniqueProcessId'], 8)
    name_data = paging.read_va(kernel_cr3, eproc_va + offsets['ImageFileName'], 15)
    cr3_data = paging.read_va(kernel_cr3, eproc_va + offsets['DirectoryTableBase'], 8)
    fields = _decode_eprocess_fields(pid_data, name_data, cr3_data)
    if fields is None:
        return None
    pid, name, cr3 = fields

    base = _resolve_image_base(paging, kernel_cr3, eproc_va, cr3, offsets)

    return ProcessInfo(pid=pid, name=name, cr3=cr3, base=base, eproc_va=eproc_va)


def _read_eprocess_via_pa(
    paging: Paging,
    eproc_pa: int,
    offsets: dict,
    eproc_va: int,
) -> Optional[ProcessInfo]:
    """Build a ProcessInfo by reading EPROCESS fields directly from PA.

    Used for the System process on the very first read, before any VA
    translation against the chain has been established.
    """
    pid_data = paging.read_pa(eproc_pa + offsets['UniqueProcessId'], 8)
    name_data = paging.read_pa(eproc_pa + offsets['ImageFileName'], 15)
    cr3_data = paging.read_pa(eproc_pa + offsets['DirectoryTableBase'], 8)
    fields = _decode_eprocess_fields(pid_data, name_data, cr3_data)
    if fields is None:
        return None
    pid, name, cr3 = fields

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
    """Infer the EPROCESS.Peb offset, mirroring MemProcFS's
    ``VmmWinProcess_OffsetLocator64`` fuzzing strategy.

    The Peb slot is 0 in the System process (kernel-only, no user PEB) but a
    valid, page-aligned user VA in a user process; the page it points to is
    present and does **not** start with ``"MZ"`` (an ``MZ`` page at that slot
    is the image base — i.e. SectionBaseAddress — not the PEB).

    Robustness (why this replaced the earlier cross-verify scheme):

      * Presence is decided by ``va_to_pa()`` returning a physical address,
        never by a zero-filled read. A paged-out page is *unknown* (skip),
        never a *contradiction*. Backends that zero-pad holes (e.g. a DumpIt
        live view) used to make a paged-out reference look like a "readable
        non-MZ" contradiction and reject the real offset.
      * One reference process settles it; if its PEB is paged out we fall back
        to the next reference (up to ``PEB_MAX_REFS``). A single paged-out
        reference can no longer poison the result.
    """
    system = next((p for p in processes if p.pid == 4), None)
    if system is None:
        return None
    system_data = paging.read_va(kernel_cr3, system.eproc_va, 0x1000)
    if len(system_data) < 0x1000:
        return None

    real_user_procs = [
        p for p in processes
        if p.pid not in (0, 4)
        and p.cr3
        and p.name.lower() not in _NO_PEB_NAMES
    ]

    # smss.exe / csrss.exe / ... first: early-boot, stable layout, rarely paged.
    def _priority(p: ProcessInfo) -> int:
        try:
            return _PEB_PRIORITY_NAMES.index(p.name.lower())
        except ValueError:
            return len(_PEB_PRIORITY_NAMES)
    real_user_procs.sort(key=_priority)

    # Distinct names so a paged-out reference is followed by a genuinely
    # different process, not another paged-out sibling of the same image.
    for ref in _distinct_by_name(real_user_procs, PEB_MAX_REFS):
        ref_data = paging.read_va(kernel_cr3, ref.eproc_va, 0x1000)
        if len(ref_data) < 0x1000:
            continue
        off = _peb_offset_from_reference(paging, system_data, ref_data, ref.cr3)
        if off is not None:
            return off
    return None


def _peb_offset_from_reference(
    paging: Paging,
    system_data: bytes,
    ref_data: bytes,
    ref_cr3: int,
) -> Optional[int]:
    """Scan the Peb window for the first offset that behaves like a PEB for
    this one reference process, or None if its PEB looks paged out (so the
    caller moves on to another reference)."""
    for off in range(PEB_SCAN_LO, PEB_SCAN_HI, 8):
        if struct.unpack_from('<Q', system_data, off)[0] != 0:
            continue                                   # (1) System.Peb must be 0
        peb_va = struct.unpack_from('<Q', ref_data, off)[0]
        if peb_va == 0 or peb_va > USER_VA_MAX or (peb_va & 0xFFF):
            continue                                   # (2) user VA, page-aligned
        pa = paging.va_to_pa(ref_cr3, peb_va)
        if pa is None:
            continue                                   # (3) paged out -> unknown, skip
        head = paging.read_pa(pa, 2)
        if len(head) < 2 or head == b'MZ':
            continue                                   # (4) MZ page = image base, not PEB
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
