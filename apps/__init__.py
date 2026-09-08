"""Runnable agents built on the ``admissible`` package.

Three processes that share one memory store and disagree about the truth:

``agent``         the buyer -- a LangGraph graph that hires and pays other agents
``counterparty``  an honest seller whose outcomes become memories
``poisoner``      the adversary, writing into the same store the buyer reads

The package is deliberately thin. Every rule that decides whether money moves
lives in ``packages/admissible``; these modules only wire it to a graph, a
counterparty and an attacker, so a reviewer auditing the security boundary
never has to read this directory.

The hackathon checkout does not install ``admissible``, so the source tree is
put on the path here rather than in every entrypoint -- same approach as
``bench/run.py``, and it means ``python scripts/demo.py`` works from a fresh
clone with no install step.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_ADMISSIBLE_SRC = _REPO_ROOT / "packages" / "admissible" / "src"

if _ADMISSIBLE_SRC.is_dir() and str(_ADMISSIBLE_SRC) not in sys.path:
    sys.path.insert(0, str(_ADMISSIBLE_SRC))

#: Repository root, so entrypoints can locate fixtures and the demo database
#: without caring where they were invoked from.
REPO_ROOT = _REPO_ROOT

__all__ = ["REPO_ROOT"]
