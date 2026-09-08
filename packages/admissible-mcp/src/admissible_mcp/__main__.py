"""Entry point: the ``admissible-mcp`` console script, and ``python -m admissible_mcp``."""

from __future__ import annotations

from .server import run_stdio


def main() -> None:
    run_stdio()


if __name__ == "__main__":
    main()
