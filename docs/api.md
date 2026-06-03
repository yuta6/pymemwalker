# API: the `Process` view

`Walker` is the analysis context; `Walker.read_va(cr3, va, size)` is its
low-level read. That is powerful but verbose for real use — you thread a
bare `cr3` through every call and hand-unpack bytes:

```python
cr3  = walker.cr3_by_name("r5apex_dx12.exe")
base = walker.base_by_name("r5apex_dx12.exe")
local = struct.unpack('<Q', walker.read_va(cr3, base + LOCAL_PLAYER, 8))[0]
```

`Walker.process(name)` returns a `Process` that binds one process's
`cr3` / `base` / `pid` / `eproc_va` and adds typed / pointer-chain reads:

```python
proc  = walker.process("r5apex_dx12.exe")     # -> Process | None
local = proc.read_ptr(proc.base + LOCAL_PLAYER)
```

## Surface

```python
# identity
proc.name : str
proc.pid  : int
proc.cr3  : int          # DirectoryTableBase
proc.base : int          # main-EXE image base VA (0 if undiscovered)
proc.eproc_va : int      # kernel VA of the EPROCESS

# reads
proc.read(va, size)            -> bytes        # raw; unmapped -> \x00
proc.read_struct(va, fmt)      -> value|tuple  # struct.unpack; scalar if 1 field
proc.read_ptr(va)              -> int          # read_struct(va, '<Q')
proc.read_chain(start, [o, …]) -> int          # multi-level pointer

# writes (live backends only)
proc.write(va, data)           -> bool
proc.write_struct(va, fmt, *v) -> bool

# lifecycle
proc.refresh()                 -> bool         # re-read DTB live; False if gone
```

## Design decisions (and why)

These are the calls that shaped the surface — recorded so the rationale
survives, and as a reference for a future kernel-side implementation.

### `read_struct`, not a family of `read_uN` / `read_iN` / `read_fN`

Named per-type methods (`read_u8 … read_f64 … read_ptr`, plus write twins)
balloon to ~20 functions. `read_struct(va, fmt)` collapses them into one
orthogonal primitive built straight on `struct.unpack`:

- It is *more* capable than the typed family — multi-field reads
  (`'<3f'` for a vec3, `'<2i4f'` for a mixed record) come for free.
- It maps 1:1 onto how callers already think (`struct.unpack('<Q', …)`).
- One primitive translates cleanly to C later; 20 methods do not.

A single field unpacks to a scalar (no `[0]` noise); multiple fields
return the tuple.

### No `read_type(va, 'u64')`

A stringly-typed `read_type(va, 'u64')` is exactly `read_struct(va, '<Q')`
— redundant once `read_struct` exists, and it cannot express multi-field
reads. Dropped. (In a typed language this niche is filled elegantly by a
template, `read<T>(addr)`; Python has no compile-time equivalent, so the
`struct` format string is the pragmatic stand-in.)

### `read_ptr` is the one sugar kept

Pointer reads dominate real code (every chain hop, every object handle), so
`read_ptr(va)` earns its place as an alias for `read_struct(va, '<Q')`.
It is the only per-type convenience; everything else goes through
`read_struct`.

### `read_chain` dereferences — it does not sum offsets

A multi-level pointer is *deref at each level*, not additive:

```python
read_chain(base, [a, b]) == read_ptr(read_ptr(base + a) + b)
```

The trailing field offset is deliberately left out of the chain — the
chain resolves a *pointer*, `read_struct` reads the *value*:

```python
ent = proc.read_chain(proc.base, [ENTLIST, idx * 0x20])
hp  = proc.read_struct(ent + HP, '<i')
```

A null dereference mid-chain returns `0` (broken chain → missing entity
degrades to `0`) rather than raising.

### Failure semantics: zero, not exception

`read_va` zero-pads unmapped / paged-out memory and never raises, so
`read_struct` of an unmapped address unpacks `0` (and `read_chain` short-
circuits to `0`). This suits tight per-frame loops — "not there = 0" — and
avoids per-read `try/except`. A future `strict=True` could opt into raising.

## Relation to memprocfs

This is intentionally a thin, narrow layer — not a competitor to memprocfs
(scatter/DMA pipelining, modules, VAD, handles, symbols, FS mount). The one
thing it aims to beat memprocfs at is *readability for the narrow RE case*:
`proc.read_struct(chain(...) + HP, '<i')` versus the imperative
`scatter.prepare / execute / read`. Scatter is deliberately **not**
implemented — on a non-DMA backend (a local driver-read source) its win is bounded by
intra-struct locality, and the simpler "block-read a struct, slice in
Python" pattern captures most of it. See `internals.md` for the read-path
performance reasoning.
