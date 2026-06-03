# pymemwalker

A minimal x86-64 4-level page walk and EPROCESS chain walk implementation,
written in pure Python standard library, for learning memory forensics
fundamentals.

## What this is

Given a physical memory image of a 64-bit Windows machine, this library:

- Walks x86-64 4-level page tables (virtual → physical address translation)
- Discovers the kernel CR3 via the self-referencing PML4 trick
- Enumerates running processes by walking the `ActiveProcessLinks` chain
- Resolves process name → CR3 and reads arbitrary virtual addresses

It re-implements the core algorithms of MemProcFS / leechcore / memflow at
their analytical layer (= the `vmm` module equivalent).

## Positioning

This is a **learning project** for memory forensics fundamentals — not a
production tool. If you have a real forensics or research task, use one of
the mature, capable tools instead:

- [**memflow**](https://github.com/memflow/memflow) — Rust, modern,
  pluggable connector / OS layer model, far more correct and performant.
- [**MemProcFS**](https://github.com/ufrisk/MemProcFS) — C, the canonical
  full-featured analysis stack. Mounts memory as a virtual filesystem.
- [**Volatility 3**](https://github.com/volatilityfoundation/volatility3) —
  Python, the established academic / law-enforcement forensics framework.

If you are comfortable with Rust, **use memflow**. It is strictly the
better tool for any real workload.

The only thing pymemwalker offers that those don't:

- **Python standard library only.** Zero third-party dependencies. No
  ctypes, no symbol server, no PDB downloads, no native build. The entire
  page-walk and process-enumeration logic is `struct.unpack` and bit math.
- **Simple, readable implementation** scoped tightly to the algorithmic
  core. A short codebase you can read end-to-end in an evening and modify
  freely.

It exists because reading the equivalent C / Rust sources of those mature
tools is a steep curve when all you want is to understand *the algorithm*.
pymemwalker trades feature coverage and robustness for clarity.

## Scope

Strictly bounded to keep the code small:

- **CPU**: x86-64 only — no ARM64, no RISC-V, no 32-bit x86.
- **Paging mode**: 4-level only — no 5-level (LA57), no PAE, no legacy.
- **OS**: 64-bit Windows 10 / 11 only — no Linux, no macOS.
- **No symbol server / PDB / network access.** EPROCESS field offsets
  are discovered at runtime by scanning physical memory for the System
  process and using its known invariants (PID=4, Name="System",
  DirectoryTableBase=kernel_cr3).

Memory acquisition itself is **not implemented** — it is provided as a
`Protocol` you implement. A raw dump file backend is included in
`examples/` as a reference.

## What you can learn from reading this

1. **x86-64 4-level paging** — PML4 → PDPT → PD → PT, PTE bit layout,
   huge / large page exceptions.
2. **Kernel CR3 self-discovery** — scanning physical memory for a page
   whose PML4 entry at index 0x1ED points back to itself.
3. **Structure discovery from invariants** — using the System process's
   fixed PID / name / DTB to derive EPROCESS field offsets at runtime
   without symbols.
4. **Windows kernel linked-list walking** — traversing the EPROCESS
   `ActiveProcessLinks` circular doubly-linked list across virtual memory.

## Usage

```python
import mmap
from pymemwalker import Vmm, PhysicalMemoryAcquisition


class RawDumpAcquisition:
    """Treat a raw memory dump file as physical memory."""

    def __init__(self, path: str):
        self._f = open(path, "rb")
        self._mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)

    def read_pa(self, pa: int, size: int) -> bytes:
        if pa + size > len(self._mm):
            return b""
        return self._mm[pa:pa + size]

    @property
    def max_pa(self) -> int:
        return len(self._mm)


acq = RawDumpAcquisition("memory.raw")
vmm = Vmm(acq)                            # initial scan takes a few seconds

for p in vmm.list_processes():
    print(f"{p.pid:5}  {p.name:<20}  CR3=0x{p.cr3:X}  Base=0x{p.base:X}")

cr3 = vmm.cr3_by_name("notepad.exe")
data = vmm.read_va(cr3, 0x7FF600000000, 64)
```

## Installation

This is a public source-only project. Install directly from git:

```bash
uv add "pymemwalker @ git+https://github.com/<owner>/pymemwalker.git"
```

It is intentionally not published to PyPI.

## Status

Personal learning project. No stability guarantees, no version policy,
no issue / PR support promised. Use it to read and learn; fork it freely.

## License

MIT.
