"""Regression cases built from synthetic memory; no live acquisition needed."""
import struct

import pytest

from pymemwalker import Walker
from pymemwalker import _eprocess, _kernel
from pymemwalker._paging import Paging


SYSTEM = 0xFFFF800000200000
ONE = SYSTEM + 0x2000
TWO = SYSTEM + 0x4000
NTOS = 0xFFFFF80010000000
HEAD = NTOS + 0x8000
CR3 = 0x1000
PID_OFF = 0x40
APL_OFF = 0x48
NAME_OFF = 0x80


class Memory:
    def __init__(self):
        self.bytes = {}
        self.short_reads = {}
        self.va_reads = []

    def put(self, address, data):
        self.bytes.update((address + i, value) for i, value in enumerate(data))

    def qwords(self, address, *values):
        self.put(address, struct.pack('<' + 'Q' * len(values), *values))

    def read_pa(self, address, size):
        if (address, size) in self.short_reads:
            return self.short_reads[address, size]
        return bytes(self.bytes.get(address + i, 0) for i in range(size))

    def read_va(self, cr3, address, size):
        self.va_reads.append((address, size))
        return self.read_pa(address, size)

    def va_to_pa(self, cr3, address):
        return address


def ring(order=('system', 'one', 'two'), with_head=True):
    memory = Memory()
    records = {'system': (SYSTEM, 4, b'System'), 'one': (ONE, 100, b'one.exe'),
               'two': (TWO, 200, b'two.exe')}
    for address, pid, name in records.values():
        memory.qwords(address + PID_OFF, pid)
        memory.qwords(address + 0x28, CR3)
        memory.put(address + NAME_OFF, name.ljust(15, b'\x00'))
    # Deliberately plausible PID/name: excluding the head must use its
    # location, not merely hope the surrounding bytes are invalid fields.
    memory.qwords(HEAD - APL_OFF + PID_OFF, 123)
    memory.qwords(HEAD - APL_OFF + 0x28, CR3)
    memory.put(HEAD - APL_OFF + NAME_OFF, b'not-a-process\x00\x00')
    nodes = ([HEAD] if with_head else []) + [records[name][0] + APL_OFF for name in order]
    for i, node in enumerate(nodes):
        memory.qwords(node, nodes[(i + 1) % len(nodes)], nodes[(i - 1) % len(nodes)])
    offsets = {'eprocess_pa': SYSTEM, 'eprocess_va': SYSTEM,
               'UniqueProcessId': PID_OFF, 'ActiveProcessLinks': APL_OFF,
               'ImageFileName': NAME_OFF, 'DirectoryTableBase': 0x28,
               'ntoskrnl_base': NTOS, 'ntoskrnl_size': 0x100000}
    return memory, offsets


@pytest.mark.parametrize('order', [
    ('system', 'one', 'two'), ('one', 'system', 'two'), ('one', 'two', 'system'),
])
def test_list_head_is_not_an_eprocess_even_with_plausible_fields(order):
    memory, offsets = ring(order)
    processes = _eprocess.list_processes(memory, CR3, offsets)
    assert processes[0].pid == 4
    assert {p.pid for p in processes} == {4, 100, 200}
    assert len(processes) == 3
    assert (HEAD - APL_OFF + NAME_OFF, 15) not in memory.va_reads


def test_single_process_with_standalone_head():
    memory, offsets = ring(('system',))
    assert [p.pid for p in _eprocess.list_processes(memory, CR3, offsets)] == [4]


def test_legacy_offsets_without_kernel_image_or_system_va():
    memory, offsets = ring(with_head=False)
    for key in ('eprocess_va', 'ntoskrnl_base', 'ntoskrnl_size'):
        offsets.pop(key)
    assert [p.pid for p in _eprocess.list_processes(memory, CR3, offsets)] == [4, 100, 200]


def test_zero_padded_process_is_skipped_without_losing_later_entries():
    memory, offsets = ring()
    memory.put(ONE + NAME_OFF, b'\x00' * 15)
    assert [p.pid for p in _eprocess.list_processes(memory, CR3, offsets)] == [4, 200]


def test_unreadable_system_does_not_return_a_dummy_process():
    _, offsets = ring()
    assert _eprocess.list_processes(Memory(), CR3, offsets) == []


def test_short_system_links_return_empty_list():
    memory, offsets = ring()
    memory.short_reads[SYSTEM + APL_OFF, 16] = b''
    assert _eprocess.list_processes(memory, CR3, offsets) == []


def test_cycle_not_containing_system_terminates_without_duplicates():
    memory, offsets = ring()
    memory.qwords(TWO + APL_OFF, ONE + APL_OFF, ONE + APL_OFF)
    assert [p.pid for p in _eprocess.list_processes(memory, CR3, offsets)] == [4, 100, 200]


@pytest.mark.parametrize('field,size', [(PID_OFF, 8), (NAME_OFF, 15), (0x28, 8)])
def test_partial_fields_rejected_by_both_read_paths(field, size):
    memory, offsets = ring()
    memory.short_reads[ONE + field, size] = b'\x00' * (size - 1)
    assert _eprocess._read_eprocess_via_va(memory, CR3, ONE, offsets) is None
    assert _eprocess._read_eprocess_via_pa(memory, ONE, offsets, ONE) is None


def test_kernel_pointer_pid_is_rejected_by_both_read_paths():
    memory, offsets = ring()
    memory.qwords(ONE + PID_OFF, NTOS)
    assert _eprocess._read_eprocess_via_va(memory, CR3, ONE, offsets) is None
    assert _eprocess._read_eprocess_via_pa(memory, ONE, offsets, ONE) is None


def test_named_kernel_only_process_with_zero_cr3_is_preserved():
    memory, offsets = ring()
    memory.qwords(ONE + 0x28, 0)
    process = _eprocess._read_eprocess_via_va(memory, CR3, ONE, offsets)
    assert (process.pid, process.name, process.cr3) == (100, 'one.exe', 0)


def test_process_name_stops_at_first_nul():
    memory, offsets = ring()
    memory.put(ONE + NAME_OFF, b'one.exe\x00junk!!!\x00')
    assert _eprocess._read_eprocess_via_va(memory, CR3, ONE, offsets).name == 'one.exe'


def pe_headers(memory):
    memory.put(NTOS, b'MZ')
    memory.put(NTOS + 0x3C, struct.pack('<I', 0x80))
    memory.put(NTOS + 0x80, b'PE\x00\x00')
    memory.put(NTOS + 0x80 + 0x50, struct.pack('<I', 0x100000))


def test_discovery_records_kernel_image_bounds(monkeypatch):
    memory, _ = ring()
    pe_headers(memory)
    export = NTOS + 0x1000
    memory.qwords(export, SYSTEM)
    monkeypatch.setattr(_kernel, 'find_ntoskrnl_base', lambda *args: NTOS)
    monkeypatch.setattr(_kernel, 'resolve_pe_export', lambda *args: export)
    offsets = _kernel.discover_offsets(memory, CR3, NTOS + 0x2000)
    assert offsets['ntoskrnl_base'] == NTOS
    assert offsets['ntoskrnl_size'] == 0x100000
    assert [p.pid for p in _eprocess.list_processes(memory, CR3, offsets)] == [4, 100, 200]


@pytest.mark.parametrize('address,size', [(NTOS, 0x40), (NTOS + 0x80, 0x54)])
def test_partial_image_headers_do_not_crash(address, size):
    memory = Memory()
    pe_headers(memory)
    memory.short_reads[address, size] = b''
    assert _kernel._read_image_size(memory, CR3, NTOS) == 0


@pytest.mark.parametrize('cache_pages', [True, False])
def test_flush_processes_refreshes_physical_pages_and_translations(cache_pages):
    class Backend:
        value = b'A'

        def read_pa(self, address, size):
            return self.value * size

    backend = Backend()
    walker = object.__new__(Walker)
    walker._paging = Paging(backend, cache_pages=cache_pages)
    walker._processes = [object()]
    walker._paging._tlb[CR3, ONE] = 0x1000
    assert walker._paging.read_pa(0x1000, 1) == b'A'
    backend.value = b'B'
    walker.flush_processes()
    assert walker._processes is None
    assert walker._paging._tlb == {}
    assert walker._paging.read_pa(0x1000, 1) == b'B'
