#!/usr/bin/env python3
"""
FastMCP server instance - shared across all modules
"""

from fastmcp import FastMCP

# Create the FastMCP server instance that can be imported by tool modules
mcp = FastMCP("cloudways-mcp")