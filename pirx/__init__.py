"""Pirx: a write-capable remediation agent whose authority is granted per
action, not per session.

Version 0.7.6.3: documentation only. README links the manual's page under
its tagline and as its first badge. 0.7.6.2 published the manual: rendered
by `tools/build_site.py` and deployed by its own workflow, whose deploy job
is the repository's only holder of an identity token (PT22). Nothing in
this package imports the site builder or its parser; the runtime has no
dependencies. Behaviour is 0.7.6.0's: a grant file is input, and
`gate-approve` records `grant.issued` before it writes the grant whole (F65).
"""

__version__ = "0.7.6.2"
