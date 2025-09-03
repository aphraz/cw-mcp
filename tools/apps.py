#!/usr/bin/env python3
"""
Application management tools for Cloudways MCP Server
"""

from typing import Dict, Any
from fastmcp import Context
from pydantic import BaseModel

from ..server import mcp
from ..utils.api_client import make_api_request, make_api_request_post

# Shared components (will be injected by main.py)
redis_client = None
http_client = None  
token_manager = None

class AppParams(BaseModel):
    server_id: int
    app_id: int

@mcp.tool
async def clone_app(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Clone application to the same server.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing clone operation status
    """
    return await make_api_request_post(ctx, "/app/clone", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)

@mcp.tool
async def backup_app(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Start application backup operation.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing backup operation status
    """
    return await make_api_request_post(ctx, "/app/manage/takeBackup", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)

@mcp.tool
async def clear_app_cache(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Clear all cache for an application.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing cache clear operation status
    """
    return await make_api_request_post(ctx, "/app/cache/purge", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)

@mcp.tool
async def get_app_backup_status(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Get application backup status.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing backup status information
    """
    return await make_api_request(ctx, "/app/manage/backup", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)

class RestoreAppParam(BaseModel):
    server_id: int
    app_id: int
    backup_id: str

@mcp.tool
async def restore_app(ctx: Context, params: RestoreAppParam) -> Dict[str, Any]:
    """
    Restore application from backup.
    
    Args:
        params: RestoreAppParam object containing server_id, app_id, and backup_id
    
    Returns:
        Dictionary containing restore operation status
    """
    return await make_api_request_post(ctx, "/app/manage/restore", {
        "server_id": params.server_id,
        "app_id": params.app_id,
        "backup_id": params.backup_id
    }, redis_client, http_client, token_manager)

@mcp.tool
async def rollback_app_restore(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Rollback last restore action.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing rollback operation status
    """
    return await make_api_request_post(ctx, "/app/manage/rollback", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)

class AppCnameParam(BaseModel):
    server_id: int
    app_id: int
    cname: str

@mcp.tool
async def update_app_cname(ctx: Context, params: AppCnameParam) -> Dict[str, Any]:
    """
    Update application custom domain (CNAME).
    
    Args:
        params: AppCnameParam object containing server_id, app_id, and cname
    
    Returns:
        Dictionary containing CNAME update operation status
    """
    return await make_api_request_post(ctx, "/app/manage/cname", {
        "server_id": params.server_id,
        "app_id": params.app_id,
        "cname": params.cname
    }, redis_client, http_client, token_manager)

@mcp.tool
async def delete_app_cname(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Delete application custom domain (CNAME).
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing CNAME deletion operation status
    """
    # Note: Using make_api_request with DELETE method would require extending api_client
    return await make_api_request_post(ctx, "/app/manage/cname", {
        "server_id": app.server_id,
        "app_id": app.app_id,
        "_method": "DELETE"
    }, redis_client, http_client, token_manager)

@mcp.tool
async def reset_app_file_permissions(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Reset file permissions for an application.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing permission reset operation status
    """
    return await make_api_request_post(ctx, "/app/manage/reset_permissions", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)

@mcp.tool
async def enforce_app_https(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Enforce HTTPS redirection for an application.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing HTTPS enforcement operation status
    """
    return await make_api_request_post(ctx, "/app/manage/enforce_https", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)

@mcp.tool
async def get_app_fpm_settings(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Get PHP-FPM configurations for an application.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing PHP-FPM settings
    """
    return await make_api_request(ctx, "/app/manage/fpm_setting", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)

@mcp.tool
async def get_app_varnish_settings(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Get Varnish configurations for an application.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing Varnish settings
    """
    return await make_api_request(ctx, "/app/manage/varnish_setting", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)

@mcp.tool
async def get_app_varnish_status(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Get application-level Varnish service status.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing Varnish status
    """
    return await make_api_request(ctx, "/service/appVarnish", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)

class AppVarnishParam(BaseModel):
    server_id: int
    app_id: int
    state: str  # enable, disable

@mcp.tool
async def manage_app_varnish(ctx: Context, params: AppVarnishParam) -> Dict[str, Any]:
    """
    Enable or disable Varnish for an application.
    
    Args:
        params: AppVarnishParam object containing server_id, app_id, and state
    
    Returns:
        Dictionary containing Varnish operation status
    """
    return await make_api_request_post(ctx, "/service/appVarnish", {
        "server_id": params.server_id,
        "app_id": params.app_id,
        "state": params.state
    }, redis_client, http_client, token_manager)

@mcp.tool
async def get_app_analytics_traffic(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Get application traffic analytics.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing traffic analytics data
    """
    return await make_api_request(ctx, "/app/analytics/traffic", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)

@mcp.tool
async def get_app_analytics_php(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Get application PHP analytics.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing PHP analytics data
    """
    return await make_api_request(ctx, "/app/analytics/php", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)

@mcp.tool
async def get_app_analytics_mysql(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Get application MySQL analytics.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing MySQL analytics data
    """
    return await make_api_request(ctx, "/app/analytics/mysql", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)