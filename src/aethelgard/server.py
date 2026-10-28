"""FastMCP Server Entrypoint for Project Aethelgard."""

import sys
from .mcp import create_mcp_server, main, mcp, run_stdio

__all__ = ["create_mcp_server", "mcp", "run_stdio", "main"]

if __name__ == "__main__":
    sys.exit(main())
