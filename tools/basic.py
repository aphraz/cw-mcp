#!/usr/bin/env python3
"""
Basic tools for Cloudways MCP Server with OAuth browser authentication
"""

from typing import Dict, Any
from fastmcp import Context
from pydantic import BaseModel

from server import mcp
from auth.customer import get_customer
from auth.rate_limit import get_rate_limit_status
from auth.oauth_error import OAuthErrorResponse
from utils.api_client import make_api_request

# Shared components (will be injected by main.py)
redis_client = None
http_client = None
token_manager = None
session_manager = None
browser_authenticator = None

class ServerIdParam(BaseModel):
    server_id: int

class AppParams(BaseModel):
    server_id: int
    app_id: int

@mcp.tool
async def ping(ctx: Context) -> Dict[str, Any]:
    """Test connectivity and authentication"""
    try:
        customer = await get_customer(ctx, session_manager, browser_authenticator, redis_client)
        if customer:
            return {"status": "success", "message": f"Pong! Authenticated as {customer.cloudways_email}"}
        else:
            return {"status": "success", "message": "Pong! No authentication provided."}
    except OAuthErrorResponse as e:
        # Return OAuth error dictionary - MCP client will interpret this
        return e.oauth_error.to_dict()

@mcp.tool
async def customer_info(ctx: Context) -> Dict[str, Any]:
    """Get current customer information"""
    try:
        customer = await get_customer(ctx, session_manager, browser_authenticator, redis_client)
        if not customer:
            return {"status": "error", "message": "Authentication required"}

        return {
            "status": "success",
            "customer_id": customer.customer_id,
            "email": customer.email,
            "cloudways_email": customer.cloudways_email,
            "session_id": customer.session_id,
            "created_at": customer.created_at.isoformat(),
            "last_seen": customer.last_seen.isoformat()
        }
    except OAuthErrorResponse as e:
        return e.oauth_error.to_dict()

@mcp.tool
async def rate_limit_status(ctx: Context) -> Dict[str, Any]:
    """Get current rate limit status"""
    try:
        customer = await get_customer(ctx, session_manager, browser_authenticator, redis_client)
        if not customer:
            return {"status": "error", "message": "Authentication required"}

        return await get_rate_limit_status(customer.customer_id, redis_client)
    except OAuthErrorResponse as e:
        return e.oauth_error.to_dict()

@mcp.tool
async def list_servers(ctx: Context) -> Dict[str, Any]:
    """
    Get list of servers in your Cloudways account.
    
    Returns:
        Dictionary containing:
            - status: Success/error status
            - servers: Array of server objects with details like id, label, status, apps, etc.
            - Or error message if the operation fails
    """
    return await make_api_request(ctx, "/server", None, redis_client, http_client, token_manager, session_manager, browser_authenticator)

@mcp.tool
async def get_server_details(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """
    Get details of a specific server including its applications.
    
    Args:
        server: ServerIdParam object containing server_id
    
    Returns:
        Dictionary containing:
            - status: Success/error status
            - bandwidth: Bandwidth usage data with timestamps
            - disk: Disk usage data per application
            - Or error message if operation fails
    """
    bw = await make_api_request(ctx, "/server/monitor/summary", {"server_id": server.server_id, "type": "bw"}, 
                               redis_client, http_client, token_manager, session_manager, browser_authenticator)
    db = await make_api_request(ctx, "/server/monitor/summary", {"server_id": server.server_id, "type": "db"}, 
                               redis_client, http_client, token_manager, session_manager, browser_authenticator)
    return {"status": "success", "bandwidth": bw, "disk": db}


@mcp.tool
async def get_app_credentials(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Get application credentials.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing app credentials
    """
    return await make_api_request(ctx, "/app/creds", {"server_id": app.server_id, "app_id": app.app_id}, 
                                 redis_client, http_client, token_manager, session_manager, browser_authenticator)


@mcp.tool
async def get_app_monitoring_summary(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Get application monitoring summary including bandwidth and disk usage.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing bandwidth and disk usage data
    """
    bw = await make_api_request(ctx, "/app/monitor/summary", {"server_id": app.server_id, "app_id": app.app_id, "type": "bw"}, 
                               redis_client, http_client, token_manager, session_manager, browser_authenticator)
    db = await make_api_request(ctx, "/app/monitor/summary", {"server_id": app.server_id, "app_id": app.app_id, "type": "db"}, 
                               redis_client, http_client, token_manager, session_manager, browser_authenticator)
    return {"status": "success", "bandwidth": bw, "disk": db}

@mcp.tool
async def list_projects(ctx: Context) -> Dict[str, Any]:
    """Get list of projects."""
    return await make_api_request(ctx, "/project", None, redis_client, http_client, token_manager, session_manager, browser_authenticator)

@mcp.tool
async def list_team_members(ctx: Context) -> Dict[str, Any]:
    """Get list of team members."""
    return await make_api_request(ctx, "/member", None, redis_client, http_client, token_manager, session_manager, browser_authenticator)

@mcp.tool
async def get_alerts(ctx: Context) -> Dict[str, Any]:
    """Get list of all alerts."""
    return await make_api_request(ctx, "/alerts/", None, redis_client, http_client, token_manager, session_manager, browser_authenticator)

@mcp.tool
async def get_ssh_keys(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """Get SSH keys for a server."""
    server_result = await make_api_request(ctx, "/server", None, redis_client, http_client, token_manager, session_manager, browser_authenticator)
    try:
        if "servers" in server_result:
            for srv in server_result["servers"]:
                if srv["id"] == str(server.server_id):
                    return {"status": "success", "ssh_keys": srv.get("ssh_keys", [])}
        return {"status": "error", "message": "Server not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@mcp.tool
async def get_available_providers(ctx: Context) -> Dict[str, Any]:
    """Get list of available cloud providers."""
    return await make_api_request(ctx, "/providers", None, redis_client, http_client, token_manager, session_manager, browser_authenticator)

@mcp.tool
async def get_available_regions(ctx: Context) -> Dict[str, Any]:
    """Get list of available regions for each cloud provider."""
    return await make_api_request(ctx, "/regions", None, redis_client, http_client, token_manager, session_manager, browser_authenticator)

@mcp.tool
async def get_available_server_sizes(ctx: Context) -> Dict[str, Any]:
    """Get list of available server sizes for each cloud provider."""
    return await make_api_request(ctx, "/server_sizes", None, redis_client, http_client, token_manager, session_manager, browser_authenticator)

@mcp.tool
async def get_available_apps(ctx: Context) -> Dict[str, Any]:
    """Get list of available applications that can be installed."""
    return await make_api_request(ctx, "/apps", None, redis_client, http_client, token_manager, session_manager, browser_authenticator)

@mcp.tool
async def get_available_packages(ctx: Context) -> Dict[str, Any]:
    """Get list of available packages and their versions."""
    return await make_api_request(ctx, "/packages", None, redis_client, http_client, token_manager, session_manager, browser_authenticator)