"""Pirx: a write-capable remediation agent whose authority is granted per
action, not per session.

Version 0.7.6.0: a grant file is input. One that does not parse is refused
and answered, and the gate keeps serving; `gate-approve` records
`grant.issued` before it writes the grant, and writes it whole, so a crash
leaves a record without authority, never the reverse (F65).
"""

__version__ = "0.7.5.1"
