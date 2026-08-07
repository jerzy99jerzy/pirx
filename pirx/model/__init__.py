"""The model boundary.

A model may do exactly two things in this codebase: write prose that a human
will read, and **select** an action from the registry by name. It never
issues, modifies, or validates a grant; it never supplies an action
parameter; and it never names an action that the registry does not already
contain.

Everything in this subpackage is written as though the model were an
adversary with a copy of the source, because from a control standpoint it is
indistinguishable from one.
"""
