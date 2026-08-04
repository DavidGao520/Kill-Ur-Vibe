"""Authorization gate — the scope model and its loader.

Per DESIGN-active-cli.md §Authorization Gate. The scope is the compiled
statement of what a run is authorized to touch; the egress engine
(`kuv.egress`) enforces it in code on every request.
"""

from .registrable import registrable_domain
from .scope import ActionClass, Scope, ScopeError, load_scope_file

__all__ = ["ActionClass", "Scope", "ScopeError", "load_scope_file", "registrable_domain"]
