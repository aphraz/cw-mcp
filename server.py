#!/usr/bin/env python3
"""
FastMCP server instance with OAuth 2.1 authentication
"""

from fastmcp import FastMCP
from auth.oauth_provider import CloudwaysOAuthProvider

# Create OAuth provider (will lazy-load Redis from resources)
oauth_provider = CloudwaysOAuthProvider(redis_client=None)

# Create FastMCP server with OAuth authentication
mcp = FastMCP("cloudways-mcp", auth=oauth_provider)
