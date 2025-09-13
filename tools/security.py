#!/usr/bin/env python3
"""
Security management tools for Cloudways MCP Server
"""

from typing import Dict, Any, List
from fastmcp import Context
from pydantic import BaseModel

from server import mcp
from utils.api_client import make_api_request, make_api_request_post

# Shared components (will be injected by main.py)
redis_client = None
http_client = None  
token_manager = None

class AppParams(BaseModel):
    server_id: int
    app_id: int

class ServerIdParam(BaseModel):
    server_id: int

class SSLCertParam(BaseModel):
    server_id: int
    app_id: int
    certificate: str
    private_key: str

@mcp.tool
async def install_ssl_certificate(ctx: Context, params: SSLCertParam) -> Dict[str, Any]:
    """
    Install custom SSL certificate for an application.
    
    Args:
        params: SSLCertParam object containing server_id, app_id, certificate, and private_key
    
    Returns:
        Dictionary containing SSL installation operation status
    """
    return await make_api_request_post(ctx, "/security/ownSSL", {
        "server_id": params.server_id,
        "app_id": params.app_id,
        "certificate": params.certificate,
        "private_key": params.private_key
    }, redis_client, http_client, token_manager)

@mcp.tool
async def remove_ssl_certificate(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Remove custom SSL certificate from an application.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing SSL removal operation status
    """
    return await make_api_request_post(ctx, "/security/removeCustomSSL", {
        "server_id": app.server_id,
        "app_id": app.app_id,
        "_method": "DELETE"
    }, redis_client, http_client, token_manager)

@mcp.tool
async def install_letsencrypt(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Install Let's Encrypt SSL certificate for an application.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing Let's Encrypt installation operation status
    """
    return await make_api_request_post(ctx, "/security/lets_encrypt_install", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)

@mcp.tool
async def renew_letsencrypt(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Manually renew Let's Encrypt SSL certificate.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing Let's Encrypt renewal operation status
    """
    return await make_api_request_post(ctx, "/security/lets_encrypt_manual_renew", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)

class AutoRenewalParam(BaseModel):
    server_id: int
    app_id: int
    auto_renewal: bool

@mcp.tool
async def set_letsencrypt_auto_renewal(ctx: Context, params: AutoRenewalParam) -> Dict[str, Any]:
    """
    Enable or disable Let's Encrypt auto-renewal.
    
    Args:
        params: AutoRenewalParam object containing server_id, app_id, and auto_renewal flag
    
    Returns:
        Dictionary containing auto-renewal setting operation status
    """
    return await make_api_request_post(ctx, "/security/lets_encrypt_auto", {
        "server_id": params.server_id,
        "app_id": params.app_id,
        "auto_renewal": 1 if params.auto_renewal else 0
    }, redis_client, http_client, token_manager)

@mcp.tool
async def revoke_letsencrypt(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Revoke Let's Encrypt SSL certificate.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing Let's Encrypt revocation operation status
    """
    return await make_api_request_post(ctx, "/security/lets_encrypt_revoke", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)

@mcp.tool
async def get_whitelisted_ips_ssh(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """
    Get list of whitelisted IPs for SSH/SFTP access.
    
    Args:
        server: ServerIdParam object containing server_id
    
    Returns:
        Dictionary containing whitelisted IPs for SSH/SFTP
    """
    return await make_api_request(ctx, "/security/whitelisted", {
        "server_id": server.server_id
    }, redis_client, http_client, token_manager)

@mcp.tool
async def get_whitelisted_ips_mysql(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """
    Get list of whitelisted IPs for MySQL connections.
    
    Args:
        server: ServerIdParam object containing server_id
    
    Returns:
        Dictionary containing whitelisted IPs for MySQL
    """
    return await make_api_request(ctx, "/security/whitelistedIpsMysql", {
        "server_id": server.server_id
    }, redis_client, http_client, token_manager)

class WhitelistIPParam(BaseModel):
    server_id: int
    ips: List[str]

@mcp.tool
async def update_whitelisted_ips(ctx: Context, params: WhitelistIPParam) -> Dict[str, Any]:
    """
    Update the list of whitelisted IPs for SSH/SFTP access.
    
    Args:
        params: WhitelistIPParam object containing server_id and list of IPs
    
    Returns:
        Dictionary containing whitelist update operation status
    """
    return await make_api_request_post(ctx, "/security/whitelisted", {
        "server_id": params.server_id,
        "ips": ",".join(params.ips)
    }, redis_client, http_client, token_manager)

class CheckBlacklistParam(BaseModel):
    server_id: int
    ip: str

@mcp.tool
async def check_ip_blacklisted(ctx: Context, params: CheckBlacklistParam) -> Dict[str, Any]:
    """
    Check if an IP is blacklisted on the server.
    
    Args:
        params: CheckBlacklistParam object containing server_id and ip
    
    Returns:
        Dictionary containing blacklist check result
    """
    return await make_api_request(ctx, "/security/isBlacklisted", {
        "server_id": params.server_id,
        "ip": params.ip
    }, redis_client, http_client, token_manager)

class AllowIPParam(BaseModel):
    server_id: int
    ip: str

@mcp.tool
async def allow_ip_siab(ctx: Context, params: AllowIPParam) -> Dict[str, Any]:
    """
    Allow IP access to Server Information and Bandwidth (SIAB).
    
    Args:
        params: AllowIPParam object containing server_id and ip
    
    Returns:
        Dictionary containing SIAB access operation status
    """
    return await make_api_request_post(ctx, "/security/siab", {
        "server_id": params.server_id,
        "ip": params.ip
    }, redis_client, http_client, token_manager)

@mcp.tool
async def allow_ip_adminer(ctx: Context, params: AllowIPParam) -> Dict[str, Any]:
    """
    Allow IP access to Adminer (database management tool).
    
    Args:
        params: AllowIPParam object containing server_id and ip
    
    Returns:
        Dictionary containing Adminer access operation status
    """
    return await make_api_request_post(ctx, "/security/adminer", {
        "server_id": params.server_id,
        "ip": params.ip
    }, redis_client, http_client, token_manager)

# Git SSH Key Management
@mcp.tool
async def generate_git_ssh_key(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Generate SSH key for Git deployment.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing SSH key generation operation status
    """
    return await make_api_request_post(ctx, "/git/generateKey", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)

@mcp.tool
async def get_git_ssh_key(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Get the public SSH key for Git deployment.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing public SSH key content
    """
    return await make_api_request(ctx, "/git/key", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)

class GitCloneParam(BaseModel):
    server_id: int
    app_id: int
    repo_url: str
    branch: str

@mcp.tool
async def git_clone(ctx: Context, params: GitCloneParam) -> Dict[str, Any]:
    """
    Clone Git repository and deploy.
    
    Args:
        params: GitCloneParam object containing server_id, app_id, repo_url, and branch
    
    Returns:
        Dictionary containing Git clone operation status
    """
    return await make_api_request_post(ctx, "/git/clone", {
        "server_id": params.server_id,
        "app_id": params.app_id,
        "repo_url": params.repo_url,
        "branch": params.branch
    }, redis_client, http_client, token_manager)

@mcp.tool
async def git_pull(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Pull latest changes from Git repository and deploy.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing Git pull operation status
    """
    return await make_api_request_post(ctx, "/git/pull", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)

@mcp.tool
async def get_git_deployment_history(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Get Git deployment history.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing deployment history
    """
    return await make_api_request(ctx, "/git/history", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)

@mcp.tool
async def get_git_branch_names(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Get available Git branch names.
    
    Args:
        app: AppParams object containing server_id and app_id
    
    Returns:
        Dictionary containing available branch names
    """
    return await make_api_request(ctx, "/git/branchNames", {
        "server_id": app.server_id,
        "app_id": app.app_id
    }, redis_client, http_client, token_manager)