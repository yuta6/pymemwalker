"""pymemwalker — minimal x86-64 page walk + EPROCESS chain walk in pure
Python standard library, for learning memory forensics fundamentals.

Design constraints:
  - Acquisition (physical memory access) is a Protocol; user brings the backend.
  - Scope is x86-64 4-level paging + 64-bit Windows 10/11 only.
  - No Windows symbol server / PDB / network dependency: EPROCESS field
    offsets are discovered at runtime by scanning the System process.
  - Python standard library only.
  - One-time scan at construction (a few seconds); cached afterwards.

Public API:
  Walker                       — top-level class users instantiate.
  Process                      — ergonomic per-process read/write view
                                 (from Walker.process(name)).
  PhysicalMemoryAcquisition    — Protocol users implement for their backend.
  ProcessInfo                  — return type of Walker.list_processes().

Internal modules (``_acquisition``, ``_paging``, ``_kernel``, ``_eprocess``,
``_process``) are implementation details and not part of the public API.
"""
import logging as _logging

# Library best practice: attach a NullHandler so importing pymemwalker never
# emits log output unless the *application* configures logging. Discovery
# diagnostics log at INFO and the encoded-DTB sanity check at WARNING; see them
# with:  logging.getLogger("pymemwalker").setLevel(logging.INFO); logging.basicConfig()
_logging.getLogger("pymemwalker").addHandler(_logging.NullHandler())

from .walker import Walker
from ._acquisition import PhysicalMemoryAcquisition
from ._eprocess import ProcessInfo
from ._process import Process

__all__ = ["Walker", "Process", "PhysicalMemoryAcquisition", "ProcessInfo"]
