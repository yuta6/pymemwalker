# Internals: how pymemwalker bootstraps from raw bytes

This note documents the *why* behind the magic constants and the cross-cutting
invariants — the parts that are easy to write once you know them but hard to
re-derive later. The code itself (`pymemwalker/_kernel.py`, `_paging.py`,
`_eprocess.py`) is short and linear; the difficulty lives almost entirely in
the external knowledge each line assumes (Intel SDM, the Windows kernel's
undocumented layout, the PE format). This file is that knowledge.

## The one idea: break three chicken-and-egg loops

Everything here is the same move repeated — *"to get X you seem to need X"* —
broken by reaching for something outside the loop:

| # | Circular dependency | The break |
|---|---|---|
| 1 | To read kernel memory you need the kernel **CR3** (page-table root); CR3 lives *in* kernel structures you can't read without it. | Read the **Low Stub** — a known signature page in the first 1 MiB of *physical* memory. No translation needed; CR3 is sitting there at a fixed offset. |
| 2 | To parse `EPROCESS` you need its **field offsets**; offsets normally come from **symbols (PDB)**, which we forbid. | Use ntoskrnl's own **PE export table** as the symbol source. One exported global, `PsInitialSystemProcess`, hands you the System `EPROCESS` directly. |
| 3 | To trust an `EPROCESS` you need to know its **layout**; to learn the layout you need a known-good `EPROCESS`. | The export from #2 gives a *known-good* System `EPROCESS`. Derive offsets from it by matching **System's fixed invariants** (PID 4, name `"System"`, a kernel-VA `LIST_ENTRY`). No scan, no false positives. |

## Pipeline order

```
acq.read_pa  (physical only)
   │
   ▼
① find_kernel_cr3              Low Stub @ <1 MiB  ──►  kernel_cr3 + a kernel VA inside ntoskrnl
   │                                                   (_kernel.py)
   ▼
② find_ntoskrnl_base           walk kernel VA backwards to MZ/PE  ──►  ntoskrnl image base
   │
   ▼
   resolve_pe_export            parse export table  ──►  &PsInitialSystemProcess
   │
   ▼
   deref + va_to_pa             ──►  System EPROCESS (VA, then PA)
   │
   ▼
③ _verify_system_eprocess      match System invariants  ──►  EPROCESS field offsets
   │
   ▼
   list_processes              walk ActiveProcessLinks  ──►  every process
   │                                                         + each process's own CR3 (DTB @ +0x28)
   ▼
   discover_peb_offset         kernel↔user contrast  ──►  Peb offset  ──►  image bases
```

Only step ① touches raw physical addresses. Everything after ① reads through
the page tables via `Paging.read_va`.

---

## ① Kernel CR3 — the Low Stub (`_kernel.py::find_kernel_cr3`)

Windows places a **Processor Start Block** (the real-mode stub APs jump to at
boot) on a 4 KiB-aligned page below 1 MiB of physical RAM. We scan
`0x1000 .. 0x100000` step `0x1000` (≤256 pages) and test three things:

| Field | Offset in page | Constant | Meaning |
|---|---|---|---|
| Signature | `0x00` | `(q & 0xFFFFFFFFFFFF00FF) == 0x00000001000600E9` | real-mode `JMP` + magic. The JMP-offset **byte 1 varies per build**, hence the mask. |
| Kernel entry VA | `0x70` | `(q & 0xFFFFF80000000003) == 0xFFFFF80000000000` | a kernel VA inside ntoskrnl. Top bits must be the canonical kernel prefix; bottom 2 bits clear. |
| Kernel PML4 PA (= CR3) | `0xA0` | `q & 0xFFFFFF0000000FFF == 0` and `0 < q < max_pa` | page-aligned, fits in 40-bit PA space. |

Why the physical scan breaks the egg: we never translate anything here — we
read flat physical bytes, so no CR3 is required to find CR3. The entry VA at
`+0x70` is the seed for step ②.

> Mirrors MemProcFS `VmmWinInit_DTB_FindValidate_X64_LowStub`. The
> self-referencing-PML4 scan is only MemProcFS's *fallback*; the README's
> mention of the "self-referencing PML4 trick" is out of date — the code uses
> the Low Stub.

---

## ② Symbols without a PDB (`find_ntoskrnl_base`, `resolve_pe_export`)

**Find the image base.** We already hold a kernel VA inside ntoskrnl (Low Stub
`+0x70`). Step backwards one page at a time until we hit `MZ` + `PE\0\0`, then
confirm it is *ntoskrnl* (not HAL / ci.dll) by reading the export directory's
module-name field — `ntoskrnl.exe` / `ntkrnlmp.exe` / `ntoskrnl.efi`.

**Parse the export table by hand** (a hand-rolled `GetProcAddress`):

| Struct | Field | Offset | Note |
|---|---|---|---|
| DOS header | `e_lfanew` | `+0x3C` | → NT headers |
| NT headers | `Signature` | `+0x00` | `PE\0\0` |
| NT headers | `OptionalHeader.Magic` | `+0x18` | `0x20B` = PE32+ |
| NT headers | `DataDirectory[0].VirtualAddress` (Export) | `+0x88` | = OptionalHeader(`+0x18`) + `0x70` |
| `IMAGE_EXPORT_DIRECTORY` | `Name` | `+0x0C` | module name RVA |
| | `NumberOfNames` | `+0x18` | |
| | `AddressOfFunctions` | `+0x1C` | RVA→RVA[] |
| | `AddressOfNames` | `+0x20` | RVA→RVA[] (sorted name pointers) |
| | `AddressOfNameOrdinals` | `+0x24` | RVA→u16[] |

Lookup: find the index `i` of the matching name in `AddressOfNames`, read
`ordinal = AddressOfNameOrdinals[i]`, then `func_rva = AddressOfFunctions[ordinal]`.
The result is `image_base + func_rva` — the VA of `PsInitialSystemProcess`,
which is a **global pointer**; dereferencing it (8 bytes) gives the System
`EPROCESS` kernel VA. This works because the export table is part of the PE
image and lives in kernel memory once ntoskrnl is loaded — no PDB needed.

---

## ③ EPROCESS offsets from a known-good instance (`_verify_system_eprocess`)

We now have *the* System `EPROCESS` bytes (not a candidate). Derive offsets by
matching invariants that only System satisfies:

- `ImageFileName` = position of `b"System\x00"`.
- `UniqueProcessId` = position of the QWORD `4` (System's PID is always 4).
- `ActiveProcessLinks` = `UniqueProcessId + 8` (convention: APL immediately
  follows PID), validated by requiring both `LIST_ENTRY` pointers to be in the
  canonical kernel-VA range (`>= 0xFFFF000000000000`).

Because the instance is known-good, there are **no false positives** — the
exact failure mode that sank the earlier "scan physical memory for DTB values"
approach.

> The README still describes the old "scan physical memory for the System
> process" method. The code no longer does that; it resolves
> `PsInitialSystemProcess` instead.

---

## The hard part: there are TWO CR3s in play

Once you walk the process list, every read must pick the *right* page-table
root. This is the single biggest trip-hazard after the page walk itself.

| What you are reading | Which CR3 | Why |
|---|---|---|
| `EPROCESS` structs, `ActiveProcessLinks` chain, the `Peb` **pointer** field | **`kernel_cr3`** | These live in kernel memory; the kernel page tables map them. |
| A process's **PEB contents**, `ImageBaseAddress`, the EXE's `MZ` header | **`proc_cr3`** (= that process's DTB @ `EPROCESS+0x28`) | These are **user-space VAs**; only that process's own page tables map them. |

See `_resolve_image_base` (`_eprocess.py`): the PEB *pointer* is read with
`kernel_cr3`, then `PEB.ImageBaseAddress` (`PEB+0x10`) is read with `proc_cr3`.
**The classic bug is reading a user VA with `kernel_cr3`** — it either fails to
translate or resolves to unrelated kernel data.

### Bridge invariant: System's DTB == kernel_cr3

System owns the kernel address space, so `System.EPROCESS+0x28 == kernel_cr3`.
This is the sanity check in `discover_offsets`, and it is what ties step ① to
the `EPROCESS` layer (it confirms `0x28` really is the DTB offset).

### KVA Shadow / PCID — why `+0x28` specifically, and the "encoded DTB" warning

- **KVA Shadow (KPTI, the Meltdown mitigation):** modern Windows keeps **two**
  page-table roots per process — `KernelDirectoryTableBase` at `+0x28` (maps
  *both* kernel and user space) and a separate `UserDirectoryTableBase` (maps
  the kernel minimally, used while running in user mode). For offline/dump
  analysis **always use `+0x28`**, because it maps everything you want to read.
- **PCID:** the DTB value may carry a PCID in its low 12 bits. `va_to_pa` masks
  it transparently (`cr3 & PFN_MASK`), so storing the raw DTB is fine.
- If `+0x28 != kernel_cr3`, `discover_offsets` warns ("encoded DTB?") — a hint
  that one of the above encodings is in effect on this build.

### Self-referential VA bootstrap

When the walk starts we know System's **PA** but not its **VA**
(`list_processes`). Trick: read System's `ActiveProcessLinks.Flink` (the next
process's APL kernel VA), then read that neighbour's `Blink` (`+8`), which
points back to System's own APL VA. Subtract the APL offset → System's
`EPROCESS` VA. The circular list reveals your own address by reflection.

---

## The empirical layer (the "secret sauce" heuristics)

These exist because real systems are messier than the spec — they are the
parts most likely to read as tribal knowledge.

- **`discover_peb_offset`** finds the `Peb` offset by contrast: System has
  `Peb == 0` (kernel-only), a real user process has a valid user VA there, and
  following it to `PEB.ImageBaseAddress` lands on an `MZ`. Kernel-only
  processes (`System`, `Registry`, `MemCompression`, …) are filtered out so
  they can't masquerade as the "user" reference.
- **Priority references** (`smss.exe`, `csrss.exe`, …): early-boot session-0
  processes with stable layout that are never paged out — picking them makes
  discovery converge in one pass and stay reproducible. (MemProcFS uses
  `smss.exe` for the same reason.)
- **Majority vote** (`_verify_peb_offset`, `_verify_section_base_offset`):
  accept an offset only if it holds for several processes, tolerating one
  paged-out PEB. This is robustness against partial reads, not correctness per
  se.

---

## The page walk itself (`_paging.py::va_to_pa`)

Reference: Intel SDM Vol. 3, Table 4-15. 48-bit canonical VA → PA.

```
VA bits 47..39  PML4 index   (>> 39) & 0x1FF
VA bits 38..30  PDPT index   (>> 30) & 0x1FF
VA bits 29..21  PD   index   (>> 21) & 0x1FF
VA bits 20..12  PT   index   (>> 12) & 0x1FF
VA bits 11..0   page offset  & 0xFFF
```

- **PFN_MASK = `0x000FFFFFFFFFF000`** — physical frame address is PTE bits
  12..51. Apply at every level: `next_table = entry & PFN_MASK`.
- **Present bit (0)**: if clear, the page is paged out → return `None`.
- **Page Size bit (7)** — the easy-to-get-wrong part:
  - Set on a **PDPT** entry → **1 GiB** page: `PA = (pdpte & 0x000FFFFFC0000000) + (va & 0x3FFFFFFF)`.
  - Set on a **PD** entry → **2 MiB** page: `PA = (pde & 0x000FFFFFFFE00000) + (va & 0x1FFFFF)`.
  - The big-page base mask and the in-page offset mask must be complementary;
    mismatched masks are the most common page-walk bug.

`Paging` wraps this with a TLB cache (`(cr3, va_page) → pa_page`) and a 4 KiB
physical page cache. For **live** backends the physical contents change, so
`flush_pages()` must be called periodically; for **snapshot** backends both
caches can live forever.

---

## Quick magic-constant index

| Constant | Where | Source |
|---|---|---|
| `0x00000001000600E9` / mask `…00FF` | Low Stub signature | Windows Processor Start Block |
| `+0x70` (entry VA), `+0xA0` (CR3) | Low Stub fields | Windows boot stub layout |
| `0x28` | `EPROCESS.DirectoryTableBase` | `_KPROCESS` layout, stable since Win7 |
| PID `4`, name `"System"` | System invariants | Windows convention |
| `+0x10` | `PEB.ImageBaseAddress` | `_PEB` layout |
| `0x3C`/`0x18`/`0x88`/`0x0C`/`0x18`/`0x1C`/`0x20`/`0x24` | PE header / export dir | PE/COFF spec |
| `0x20B` | PE32+ magic | PE/COFF spec |
| `0x000FFFFFFFFFF000` (PFN), bit 0 (P), bit 7 (PS) | PTE | Intel SDM Vol. 3 Table 4-15 |
| `0xFFFF000000000000` / `0x00007FFFFFFFFFFF` | kernel/user VA split | x86-64 canonical addressing |
