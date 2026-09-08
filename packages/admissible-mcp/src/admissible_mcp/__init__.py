"""admissible-mcp: provenance-gated memory for any MCP client.

The same Sibyl Memory database every other tool reads, with the admission gate
in front of it. A client that speaks MCP -- Cursor, Continue, Codex CLI, a
Virtuals agent -- gets memory whose every read carries a verdict, without
adopting the Admissible runtime.

Usage (any MCP client, via its server config):

    {"mcpServers": {"admissible": {"command": "admissible-mcp"}}}

See :mod:`admissible_mcp.server` for the design rule the whole surface is built
around, and ``README.md`` for the environment variables and a worked refusal.
"""

from .server import TOOLS, build_server, run_stdio
from .session import Session, Settings

__all__ = ["Session", "Settings", "TOOLS", "build_server", "run_stdio", "__version__"]

__version__ = "0.1.0"
