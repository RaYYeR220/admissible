"""Fixture registration for this suite.

The helpers live in ``mcp_fixtures`` rather than here, and the name is
deliberately unique across the repository. Both packages used to keep their
builders in a module called ``conftest`` and import them with
``from conftest import ...``; that resolves through ordinary ``sys.path``, not
through pytest's per-directory machinery, so whichever suite loaded first won
for both. Each suite passed alone and three tests failed when they ran
together -- the worst way for a test to be wrong, because the green run is the
one you look at.
"""

from mcp_fixtures import chain, live  # noqa: F401 - re-exported as fixtures
