"""Pirx: a write-capable remediation agent whose authority is granted per
action, not per session.

Version 0.7.3.0: the ledger the gate topology can actually verify. Two
processes write one gate ledger, so appends are ordered by the kernel and
chained from what is on disk rather than from a head cached at construction.
"""

__version__ = "0.7.2.2"
