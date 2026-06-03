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
  Vmm                          — top-level class users instantiate.
  PhysicalMemoryAcquisition    — Protocol users implement for their backend.
  ProcessInfo                  — return type of Vmm.list_processes().
"""
from .vmm import Vmm
from .acquisition import PhysicalMemoryAcquisition
from .eprocess import ProcessInfo

__all__ = ["Vmm", "PhysicalMemoryAcquisition", "ProcessInfo"]
