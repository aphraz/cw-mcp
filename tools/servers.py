#!/usr/bin/env python3
"""
Server management tools for Cloudways MCP Server
"""

from typing import Dict, Any
from fastmcp import Context
from pydantic import BaseModel, Field, field_validator

from server import mcp
from utils.api_client import make_api_request, make_api_request_post
# Shared components (will be injected by main.py)
redis_client = None
http_client = None  
token_manager = None

class ServerIdParam(BaseModel):
    server_id: int = Field(gt=0, le=999999999, description="Valid server ID")

class ServerOperationParam(BaseModel):
    server_id: int = Field(gt=0, le=999999999, description="Valid server ID")

@mcp.tool
async def start_server(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """
    Start a stopped server.
    
    Args:
        server: ServerIdParam object containing server_id
    
    Returns:
        Dictionary containing operation status and details
    """
    return await make_api_request_post(ctx, "/server/start", {"server_id": server.server_id}, 
                                     redis_client, http_client, token_manager)

@mcp.tool
async def stop_server(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """
    Stop a running server.
    
    Args:
        server: ServerIdParam object containing server_id
    
    Returns:
        Dictionary containing operation status and details
    """
    return await make_api_request_post(ctx, "/server/stop", {"server_id": server.server_id}, 
                                     redis_client, http_client, token_manager)

@mcp.tool
async def restart_server(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """
    Restart a server.
    
    Args:
        server: ServerIdParam object containing server_id
    
    Returns:
        Dictionary containing operation status and details
    """
    return await make_api_request_post(ctx, "/server/restart", {"server_id": server.server_id}, 
                                     redis_client, http_client, token_manager)

@mcp.tool
async def backup_server(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """
    Start server backup operation.
    
    Args:
        server: ServerIdParam object containing server_id
    
    Returns:
        Dictionary containing backup operation status
    """
    return await make_api_request_post(ctx, "/server/manage/backup", {"server_id": server.server_id}, 
                                     redis_client, http_client, token_manager)

@mcp.tool
async def get_server_settings(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """
    Get server settings and installed package versions.
    
    Args:
        server: ServerIdParam object containing server_id
    
    Returns:
        Dictionary containing server settings and package information
    """
    return await make_api_request(ctx, "/server/manage/settings", {"server_id": server.server_id}, 
                                redis_client, http_client, token_manager)

@mcp.tool
async def get_server_disk_usage(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """
    Get server disk usage information.
    
    Args:
        server: ServerIdParam object containing server_id
    
    Returns:
        Dictionary containing disk usage details
    """
    return await make_api_request(ctx, f"/server/{server.server_id}/diskUsage", None, 
                                redis_client, http_client, token_manager)

@mcp.tool
async def optimize_server_disk(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """
    Optimize server disk space.
    
    Args:
        server: ServerIdParam object containing server_id
    
    Returns:
        Dictionary containing optimization operation status
    """
    return await make_api_request_post(ctx, "/server/disk/cleanup", {"server_id": server.server_id}, 
                                     redis_client, http_client, token_manager)

@mcp.tool
async def get_server_services_status(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """
    Get status of all services on a server.
    
    Args:
        server: ServerIdParam object containing server_id
    
    Returns:
        Dictionary containing service status information
    """
    return await make_api_request(ctx, "/service", {"server_id": server.server_id}, 
                                redis_client, http_client, token_manager)

class ServiceStateParam(BaseModel):
    server_id: int = Field(gt=0, le=999999999, description="Valid server ID")
    service: str
    state: str  # start, stop, restart

@mcp.tool
async def change_service_state(ctx: Context, params: ServiceStateParam) -> Dict[str, Any]:
    """
    Start, stop, or restart a service on a server.
    
    Args:
        params: ServiceStateParam object containing:
            - server_id: Numeric ID of the server
            - service: Service name (mysql, apache, nginx, etc.)
            - state: Action to perform (start, stop, restart)
    
    Returns:
        Dictionary containing service operation status
    """
    return await make_api_request_post(ctx, "/service/state", {
        "server_id": params.server_id,
        "service": params.service,
        "state": params.state
    }, redis_client, http_client, token_manager)

class VarnishStateParam(BaseModel):
    server_id: int = Field(gt=0, le=999999999, description="Valid server ID")
    state: str  # enable, disable, purge

@mcp.tool
async def manage_server_varnish(ctx: Context, params: VarnishStateParam) -> Dict[str, Any]:
    """
    Enable, disable, or purge Varnish on server level.
    
    Args:
        params: VarnishStateParam object containing:
            - server_id: Numeric ID of the server
            - state: Action to perform (enable, disable, purge)
    
    Returns:
        Dictionary containing varnish operation status
    """
    return await make_api_request_post(ctx, "/service/varnish", {
        "server_id": params.server_id,
        "state": params.state
    }, redis_client, http_client, token_manager)

@mcp.tool
async def get_server_monitoring_detail(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """
    Get detailed server monitoring graph data.
    
    Args:
        server: ServerIdParam object containing server_id
    
    Returns:
        Dictionary containing detailed monitoring data
    """
    return await make_api_request(ctx, "/server/monitor/detail", {"server_id": server.server_id}, 
                                redis_client, http_client, token_manager)

@mcp.tool
async def get_server_analytics(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """
    Get server usage analytics.
    
    Args:
        server: ServerIdParam object containing server_id
    
    Returns:
        Dictionary containing server usage analytics
    """
    return await make_api_request(ctx, "/server/analytics/serverUsage", {"server_id": server.server_id}, 
                                redis_client, http_client, token_manager)