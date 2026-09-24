"""Pirx: a write-capable remediation agent whose authority is granted per
action, not per session.

Version 0.7.4.0: the verdict consumer accepts what the producer actually
emits. Tested against a payload cve-digest's own emitter produced, and a
pending EPSS reaches the approver as "pending", never as a zero.
"""

__version__ = "0.7.4.0"
