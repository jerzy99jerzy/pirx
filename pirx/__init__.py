"""Pirx: a write-capable remediation agent whose authority is granted per
action, not per session.

Version 0.7.5.0: a grant expires on the wall clock, as 0.7.0.0 decided and
no wiring site implemented. A spend whose clock reads before the grant was
issued is refused, which bounds what one backward clock step can buy.
"""

__version__ = "0.7.5.0"
