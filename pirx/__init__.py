"""Pirx: a write-capable remediation agent whose authority is granted per
action, not per session.

Version 0.7.5.1: documentation only. The documents are reconciled with the
code - the pump's attacks catalogued (F64), the two-writer ledger folded into
ARCHITECTURE, every diagram checked against the path it draws. Behaviour is
0.7.5.0's: a grant expires on the wall clock, and a spend whose clock reads
before the grant was issued is refused.
"""

__version__ = "0.7.5.1"
