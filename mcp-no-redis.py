#!/usr/bin/env python3
"""
Cloudways MCP Server with SSE & Dynamic Authentication (Full Version)
This server allows clients to connect with their own Cloudways credentials.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import httpx
from fastmcp import FastMCP, Context
from pydantic import BaseModel, Field
from fastmcp.server.dependencies import get_http_request
from uvicorn import workers

# ===== DEBUG FLAGS - REMOVE AFTER TESTING =====
DEBUG_REQUESTS = True
# ==============================================

mcp = FastMCP("cloudways-mcp")

CLOUDWAYS_API_BASE = "https://api.cloudways.com/api/v1"
TOKEN_URL = f"{CLOUDWAYS_API_BASE}/oauth/access_token"
_clients: Dict[str, Dict[str, Any]] = {}

class ServerIdParam(BaseModel):
    server_id: int

class AppParams(BaseModel):
    server_id: int
    app_id: int

async def ensure_authenticated(ctx: Context) -> str:
    """Ensure we have a valid authentication token per client."""
    client_id = ctx.client_id
    now = datetime.utcnow()
    client_cache = _clients.setdefault(client_id, {})

    token = client_cache.get("token")
    expiry = client_cache.get("expires_at")
    if token and expiry and now < expiry:
        return token

    try:
        http_request = get_http_request()
        email = http_request.headers.get("x-cloudways-email")
        api_key = http_request.headers.get("x-cloudways-api-key")

        if not email or not api_key:
            raise ValueError("Missing x-cloudways-email or x-cloudways-api-key headers.")

        async with httpx.AsyncClient() as client:
            resp = await client.post(TOKEN_URL, data={"email": email, "api_key": api_key})
            resp.raise_for_status()
            data = resp.json()

        token = data.get("access_token")
        if not token:
            raise ValueError("No access_token returned from Cloudways API.")

        client_cache["token"] = token
        client_cache["expires_at"] = now + timedelta(seconds=data.get("expires_in", 3600) - 60)
        return token

    except Exception as e:
        raise RuntimeError(f"Authentication failed: {str(e)}")

async def auth_headers(ctx: Context) -> Dict[str, str]:
    token = await ensure_authenticated(ctx)
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }

async def make_api_request(ctx: Context, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Make a safe API request with error handling."""
    # ===== DEBUG LOGGING START - REMOVE AFTER TESTING =====
    if DEBUG_REQUESTS:
        print(f"\n=== DEBUG REQUEST INFO ===")
        print(f"Endpoint: {endpoint}")
        print(f"Params: {params}")
        print(f"Full URL base: {CLOUDWAYS_API_BASE}{endpoint}")
    # ===== DEBUG LOGGING END =====
    
    try:
        headers = await auth_headers(ctx)
        
        # ===== DEBUG LOGGING START - REMOVE AFTER TESTING =====
        if DEBUG_REQUESTS:
            print(f"Headers: {dict(headers)}")
        # ===== DEBUG LOGGING END =====
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(f"{CLOUDWAYS_API_BASE}{endpoint}", headers=headers, params=params)
            
            # ===== DEBUG LOGGING START - REMOVE AFTER TESTING =====
            if DEBUG_REQUESTS:
                print(f"Actual URL called: {resp.request.url}")
                print(f"Response status: {resp.status_code}")
                print(f"Response headers: {dict(resp.headers)}")
                if resp.status_code != 200:
                    print(f"Response text: {resp.text}")
                print(f"=== END DEBUG INFO ===\n")
            # ===== DEBUG LOGGING END =====
            
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPStatusError as e:
        # ===== DEBUG LOGGING START - REMOVE AFTER TESTING =====
        if DEBUG_REQUESTS:
            print(f"HTTPStatusError: {e}")
            print(f"Response status: {e.response.status_code}")
            print(f"Response text: {e.response.text}")
        # ===== DEBUG LOGGING END =====
        return {"status": "error", "message": f"HTTP error: {e.response.status_code} - {e.response.text}"}
    except httpx.RequestError as e:
        # ===== DEBUG LOGGING START - REMOVE AFTER TESTING =====
        if DEBUG_REQUESTS:
            print(f"RequestError: {e}")
            print(f"Error type: {type(e).__name__}")
            print(f"Error args: {getattr(e, 'args', [])}")
            print(f"Error details: {str(e)}")
        # ===== DEBUG LOGGING END =====
        return {
            "status": "error", 
            "message": f"Request error: {str(e)}",
            "error_type": type(e).__name__,
            "error_args": str(getattr(e, 'args', []))
        }
    except Exception as e:
        # ===== DEBUG LOGGING START - REMOVE AFTER TESTING =====
        if DEBUG_REQUESTS:
            print(f"Unexpected error: {e}")
            print(f"Error type: {type(e).__name__}")
        # ===== DEBUG LOGGING END =====
        return {"status": "error", "message": f"Unexpected error: {str(e)}", "error_type": type(e).__name__}

@mcp.tool()
async def list_servers(ctx: Context) -> Dict[str, Any]:
    """
    Get list of servers in your Cloudways account.
    
    Returns:
        Dictionary containing:
            - status: Success/error status
            - servers: Array of server objects with details like id, label, status, apps, etc.
            - Or error message if the operation fails
    """
    return await make_api_request(ctx, "/server")

@mcp.tool()
async def get_server_details(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """
    Get details of a specific server including its applications.
    
    Args:
        server: ServerIdParam object containing:
            - server_id: Numeric ID of the server
    
    Returns:
        Dictionary containing:
            - status: Success/error status
            - server: Complete server object with all details including apps, SSH keys, settings
            - Or error message if server not found or operation fails
    """
    try:
        response = await make_api_request(ctx, "/server")
        for srv in response.get("servers", []):
            if srv["id"] == str(server.server_id):
                return {"status": "success", "server": srv}
        return {"status": "error", "message": "Server not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@mcp.tool()
async def get_services_status(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """
    Get current status of services running on a server.
    
    Args:
        server: ServerIdParam object containing:
            - server_id: Numeric ID of the server
    
    Returns:
        Dictionary containing service statuses:
            - services.status: Object with service names as keys and their status as values
                - apache2: running/stopped
                - elasticsearch: running/stopped
                - memcached: running/stopped
                - mysql: running/stopped
                - nginx: running/stopped
                - redis-server: running/stopped
                - varnish: running/stopped
                - php8-fpm: running/stopped
            - Or error message if operation fails
    """
    return await make_api_request(ctx, "/service", {"server_id": server.server_id})

@mcp.tool()
async def get_server_settings(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """
    Get server settings and installed package versions.
    
    Args:
        server: ServerIdParam object containing:
            - server_id: Numeric ID of the server
    
    Returns:
        Dictionary containing:
            - status: Success/error status
            - settings: Object with various server settings including:
                - character_set_server: Database character set
                - date.timezone: Server timezone
                - display_errors: PHP error display setting
                - error_reporting: PHP error reporting level
                - execution_limit: Max execution time
                - memory_limit: PHP memory limit
                - package_versions: Installed packages (php, mysql, etc.)
                - upload_size: Max upload size
                - And many more server configuration options
            - Or error message if operation fails
    """
    return await make_api_request(ctx, "/server/manage/settings", {"server_id": server.server_id})

@mcp.tool()
async def get_server_monitoring_summary(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """
    Get server monitoring summary including bandwidth and disk usage.
    
    Args:
        server: ServerIdParam object containing:
            - server_id: Numeric ID of the server
    
    Returns:
        Dictionary containing:
            - status: Success/error status
            - bandwidth: Bandwidth usage data with timestamps
            - disk: Disk usage data per application
            - Or error message if operation fails
    """
    bw = await make_api_request(ctx, "/server/monitor/summary", {"server_id": server.server_id, "type": "bw"})
    db = await make_api_request(ctx, "/server/monitor/summary", {"server_id": server.server_id, "type": "db"})
    return {"status": "success", "bandwidth": bw, "disk": db}

@mcp.tool()
async def get_app_details(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Get details of a specific application.
    
    Args:
        app: AppParams object containing:
            - server_id: Numeric ID of the server
            - app_id: Numeric ID of the application
    
    Returns:
        Dictionary containing:
            - status: Success/error status
            - app: Application object with details like:
                - id: Application ID
                - label: Application name
                - application: App type (wordpress, magento, etc.)
                - app_version: Version of the application
                - app_fqdn: Application URL
                - app_user: Application username
                - cname: Custom domain if set
                - webroot: Web root directory
                - created_at: Creation timestamp
            - Or error message if application not found or operation fails
    """
    server_result = await make_api_request(ctx, "/server")
    try:
        if "servers" in server_result:
            for srv in server_result["servers"]:
                if srv["id"] == str(app.server_id):
                    if "apps" in srv:
                        for application in srv["apps"]:
                            if application["id"] == str(app.app_id):
                                return {"status": "success", "app": application}
        
        return {"status": "error", "message": "Application not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@mcp.tool()
async def get_app_credentials(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Get application credentials.
    
    Args:
        app: AppParams object containing:
            - server_id: Numeric ID of the server
            - app_id: Numeric ID of the application
    
    Returns:
        Dictionary containing:
            - app_creds: Array of credential objects, each containing:
                - id: Credential ID
                - sys_user: System username
                - sys_password: System password
                - ssh_keys: Array of SSH keys with label and ssh_key_id
            - Or error message if operation fails
    """
    return await make_api_request(ctx, "/app/creds", {"server_id": app.server_id, "app_id": app.app_id})

@mcp.tool()
async def get_app_settings(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Get application settings.
    
    Args:
        app: AppParams object containing:
            - server_id: Numeric ID of the server
            - app_id: Numeric ID of the application
    
    Returns:
        Dictionary containing various application settings:
            - status: Success/error status
            - application_id: Application process ID
            - from_address: Email from address
            - cors_header: CORS header setting (0/1)
            - enforce_https: HTTPS enforcement (0/1)
            - geo_ip_setting: GeoIP setting (0/1)
            - xml_rpc_setting: XML-RPC setting (0/1)
            - php_direct_execution: PHP direct execution (0/1)
            - webp: WebP redirection (0/1)
            - wp_cron_setting: WordPress cron setting (0/1)
            - And other application-specific settings
            - Or error message if operation fails
    """
    return await make_api_request(ctx, "/app/get_settings_value", {"server_id": app.server_id, "app_id": app.app_id})

@mcp.tool()
async def get_app_monitoring_summary(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """
    Get application monitoring summary including bandwidth and disk usage.
    
    Args:
        app: AppParams object containing:
            - server_id: Numeric ID of the server
            - app_id: Numeric ID of the application
    
    Returns:
        Dictionary containing:
            - status: Success/error status
            - bandwidth: Application bandwidth usage data
            - disk: Application disk usage breakdown:
                - app_home: Home directory size
                - app_mysql: MySQL database size
                - total: Total disk usage
            - Or error message if operation fails
    """
    bw = await make_api_request(ctx, "/app/monitor/summary", {"server_id": app.server_id, "app_id": app.app_id, "type": "bw"})
    db = await make_api_request(ctx, "/app/monitor/summary", {"server_id": app.server_id, "app_id": app.app_id, "type": "db"})
    return {"status": "success", "bandwidth": bw, "disk": db}

@mcp.tool()
async def list_projects(ctx: Context) -> Dict[str, Any]:
    """
    Get list of projects.
    
    Returns:
        Dictionary containing:
            - projects: Array of project objects, each containing:
                - id: Project ID
                - name: Project name
                - created_at: Creation timestamp
                - image: Project image URL
            - Or error message if operation fails
    """
    return await make_api_request(ctx, "/project")

@mcp.tool()
async def list_team_members(ctx: Context) -> Dict[str, Any]:
    """
    Get list of team members.
    
    Returns:
        Dictionary containing:
            - members: Object with member IDs as keys, each containing:
                - id: Member ID
                - member_mapping_id: Mapping ID
                - name: Member name
                - email: Member email
                - status: Member status
                - image: Profile image URL
                - added_on: Date when member was added
                - role: Member role (e.g., "Project Manager")
                - account_disabled: Account status (0/1)
                - permissions: Object with is_full and sections array
            - Or error message if operation fails
    """
    return await make_api_request(ctx, "/member")

@mcp.tool()
async def get_alerts(ctx: Context) -> Dict[str, Any]:
    """
    Get list of all alerts.
    
    Returns:
        Dictionary containing:
            - alerts: Array of alert objects, each containing:
                - id: Alert ID
                - server_id: Associated server ID
                - app_id: Associated app ID (can be null)
                - details: Object with:
                    - subject: Alert subject
                    - desc: Alert description
                    - template_slug: Template identifier
                    - values: Additional values like SERVER_LABEL
                - created_at: Alert creation timestamp
                - is_read: Read status (0/1)
            - Or error message if operation fails
    """
    return await make_api_request(ctx, "/alerts/")

@mcp.tool()
async def get_ssh_keys(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """
    Get SSH keys for a server.
    
    Args:
        server: ServerIdParam object containing:
            - server_id: Numeric ID of the server
    
    Returns:
        Dictionary containing:
            - status: Success/error status
            - ssh_keys: Array of SSH key objects, each containing:
                - id: SSH key ID
                - label: SSH key label/name
            - Or error message if server not found or operation fails
    """
    server_result = await make_api_request(ctx, "/server")
    try:
        if "servers" in server_result:
            for srv in server_result["servers"]:
                if srv["id"] == str(server.server_id):
                    return {
                        "status": "success",
                        "ssh_keys": srv.get("ssh_keys", [])
                    }
        
        return {"status": "error", "message": "Server not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@mcp.tool()
async def get_available_providers(ctx: Context) -> Dict[str, Any]:
    """
    Get list of available cloud providers.
    
    Returns:
        Dictionary containing:
            - providers: Array of provider objects, each containing:
                - id: Provider ID (do, vultr, amazon, gce, linode)
                - name: Provider display name
            - Or error message if operation fails
    """
    return await make_api_request(ctx, "/providers")

@mcp.tool()
async def get_available_regions(ctx: Context) -> Dict[str, Any]:
    """
    Get list of available regions for each cloud provider.
    
    Returns:
        Dictionary containing:
            - regions: Object with provider names as keys, each containing array of:
                - id: Region ID
                - name: Region display name
            
    Example structure:
        {
            "regions": {
                "amazon": [
                    {"id": "us-east-1", "name": "US N.Virginia"},
                    {"id": "us-west-1", "name": "California"}
                ],
                "do": [
                    {"id": "lon1", "name": "London"},
                    {"id": "sfo1", "name": "San Francisco"}
                ]
            }
        }
    """
    return await make_api_request(ctx, "/regions")

@mcp.tool()
async def get_available_server_sizes(ctx: Context) -> Dict[str, Any]:
    """
    Get list of available server sizes for each cloud provider.
    
    Returns:
        Dictionary containing:
            - sizes: Object with provider names as keys, each containing array of size strings
            
    Example structure:
        {
            "sizes": {
                "amazon": ["Small", "Medium", "Large", "XL", "2XL"],
                "do": ["512MB", "1GB", "2GB", "4GB", "8GB", "16GB"],
                "gce": ["small", "n1-std-1", "n1-std-2", "n1-std-4"]
            }
        }
    """
    return await make_api_request(ctx, "/server_sizes")

@mcp.tool()
async def get_available_apps(ctx: Context) -> Dict[str, Any]:
    """
    Get list of available applications that can be installed.
    
    Returns:
        Dictionary containing:
            - apps: Object with application types as keys, each containing:
                - label: Display name
                - versions: Array of version objects with:
                    - app_version: Version number
                    - application: Application identifier
                    
    Available applications include:
        - WordPress
        - PHP Stack
        - WooCommerce
        - WordPress Multisite
        - Magento
        - Drupal
        - Laravel
        - OpenCart
        - PrestaShop
        - Joomla
        - Moodle
        - MediaWiki
        - And more...
    """
    return await make_api_request(ctx, "/apps")

@mcp.tool()
async def get_available_packages(ctx: Context) -> Dict[str, Any]:
    """
    Get list of available packages and their versions.
    
    Returns:
        Dictionary containing:
            - packages: Object with package types as keys:
                - php: PHP versions by OS (debian10, debian11)
                - mysql: MySQL/MariaDB versions by OS
                - redis: Redis installation options
                - supervisor: Supervisor installation options
                - elasticsearch: Elasticsearch versions
                - And configuration mappings for version compatibility
                
    Example structure:
        {
            "packages": {
                "php": {
                    "debian10": {
                        "7.0": "PHP 7.0",
                        "7.4": "PHP 7.4",
                        "8.0": "PHP 8.0"
                    }
                },
                "mysql": {
                    "debian10": {
                        "mysql,5.7": "MySQL 5.7",
                        "mariadb,10.3": "MariaDB 10.3"
                    }
                }
            }
        }
    """
    return await make_api_request(ctx, "/packages")

async def main():
    await mcp.run_streamable_http_async(
        host="127.0.0.1",
        port=7000,
        log_level="debug",
        path="/mcp",
        uvicorn_config={
            "loop":"uvloop",
            "workers":20,
        }
    )

if __name__ == "__main__":
   asyncio.run(main())
