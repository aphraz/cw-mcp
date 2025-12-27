#!/usr/bin/env python3
"""
FastMCP server instance with dual authentication (OAuth + header-based)
"""

from fastmcp import FastMCP
from auth.oauth_provider import CloudwaysOAuthProvider

# Create OAuth provider (will lazy-load Redis from resources)
# Used for OAuth endpoints (/authorize, /token, etc.) but NOT for MCP tool auth
oauth_provider = CloudwaysOAuthProvider(redis_client=None)

# Create FastMCP server WITHOUT auth parameter
# Authentication is handled by OAuthMiddleware in main.py which supports both:
# - OAuth bearer tokens
# - Header-based auth (x-cloudways-email + x-cloudways-api-key)
mcp = FastMCP("cloudways-mcp")
