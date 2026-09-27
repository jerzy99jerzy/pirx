"""Pirx: a write-capable remediation agent whose authority is granted per
action, not per session.

Version 0.7.6.1: documentation only. The cve-digest crossing is recorded on
this side: PX-0002 and PX-0003 carried and accepted at cve-digest 0.7.18.1,
PX-0001 closed with its mirror landed. Behaviour is 0.7.6.0's: a grant file
is input, and `gate-approve` records `grant.issued` before it writes the
grant whole (F65).
"""

__version__ = "0.7.6.0"
