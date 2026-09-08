"""Fixture registration for this suite.

The builders live in ``admissible_fixtures`` rather than here. Both packages
used to keep their helpers in a module called ``conftest`` and import them with
``from conftest import ...``, which resolves through ordinary ``sys.path``
rather than through pytest's per-directory machinery -- so whichever suite
loaded first won for both. Each passed alone and three failed when they ran
together, which is the worst way for a test to be wrong: the green run is the
one you look at.
"""

from admissible_fixtures import db_path,store  # noqa: F401 - re-exported as fixtures
