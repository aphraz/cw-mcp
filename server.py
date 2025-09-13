#!/usr/bin/env python3
"""
FastMCP server instance
"""

from fastmcp import FastMCP

# Create a single FastMCP instance
# This is shared across all workers and requests
mcp = FastMCP("cloudways-mcp")
