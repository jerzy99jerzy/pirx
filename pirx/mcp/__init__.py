"""The gate: MCP tool calls held until a human grant exists.

Two modules, and the split is the same one the rest of the codebase uses.
``protocol`` parses and validates; ``gate`` decides and records. Nothing here
executes a tool: the gate forwards a request it has already refused to alter,
or it refuses.
"""
