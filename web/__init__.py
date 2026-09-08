"""The Admissible web surface: a landing page and the record, over the real core.

Two files of Python and no build step. The pages are hand-authored HTML, CSS and
SVG served by FastAPI, and every number they show is computed by the
``admissible`` package at request time -- the gate, the trust policy, the FLAGGED
tier, the relations graph and the bi-temporal replay, unmodified.

Importing this package puts ``packages/admissible/src`` on the path, so the
surface runs from a checkout without an install step. ``pip install -e
packages/admissible`` works too and takes precedence.
"""

from __future__ import annotations

import sys
from pathlib import Path

WEB_ROOT = Path(__file__).resolve().parent
REPO_ROOT = WEB_ROOT.parent
STATIC = WEB_ROOT / "static"
FIXTURES = WEB_ROOT / "fixtures"
DATA = WEB_ROOT / ".data"
DEFAULT_DB = DATA / "admissible-web.db"

_SRC = REPO_ROOT / "packages" / "admissible" / "src"


def bootstrap() -> None:
    """Make ``admissible`` importable from a bare checkout."""
    for path in (REPO_ROOT, _SRC):
        text = str(path)
        if path.exists() and text not in sys.path:
            sys.path.append(text)


bootstrap()

__all__ = [
    "DATA",
    "DEFAULT_DB",
    "FIXTURES",
    "REPO_ROOT",
    "STATIC",
    "WEB_ROOT",
    "bootstrap",
]
