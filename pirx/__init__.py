"""Pirx: a write-capable remediation agent whose authority is granted per
action, not per session.

Version 0.7.6.2: the manual has a page. `docs/MANUAL.md` is rendered by
`tools/build_site.py` and published to GitHub Pages by its own workflow,
whose deploy job is the first holder of an identity token in the repository
(PT22). Nothing in this package imports the site builder or its parser; the
runtime has no dependencies. Behaviour is 0.7.6.0's: a grant file is input,
and `gate-approve` records `grant.issued` before it writes the grant whole
(F65).
"""

__version__ = "0.7.6.2"
