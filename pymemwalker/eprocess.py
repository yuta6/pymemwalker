"""EPROCESS chain walking and SectionBaseAddress offset discovery.

Once ``kernel.discover_offsets`` has located the four core EPROCESS field
offsets (DTB / Name / PID / ActiveProcessLinks), this module walks the
circular ``ActiveProcessLinks`` list to enumerate all processes, and
infers the ``SectionBaseAddress`` offset from a user-mode process's
contents.
"""
import struct
from dataclasses import dataclass
from typing import Optional

from .paging import Paging


# Canonical kernel-space virtual address minimum on x64.
KERNEL_VA_MIN = 0xFFFF_0000_0000_0000
# Canonical user-space virtual address maximum on x64 (48-bit canonical).
USER_VA_MAX = 0x0000_7FFF_FFFF_FFFF


@dataclass
class ProcessInfo:
    """Basic info about one process. Returned by ``Vmm.list_processes``."""
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

    base = 0
    if 'SectionBaseAddress' in offsets:
        base_data = paging.read_va(kernel_cr3, eproc_va + offsets['SectionBaseAddress'], 8)
        if len(base_data) == 8:
            base = struct.unpack('<Q', base_data)[0]

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

    base = 0
    if 'SectionBaseAddress' in offsets:
        base_data = paging.read_pa(eproc_pa + offsets['SectionBaseAddress'], 8)
        if len(base_data) == 8:
            base = struct.unpack('<Q', base_data)[0]

    return ProcessInfo(pid=pid, name=name, cr3=cr3, base=base, eproc_va=eproc_va)


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
