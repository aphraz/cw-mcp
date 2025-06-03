#!/usr/bin/env python3
"""
Cloudways MCP Server
Features:
- Redis for session/token storage
- Customer isolation with encryption
- Rate limiting

"""

import asyncio
import json
import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import httpx
import redis.asyncio as redis
from cryptography.fernet import Fernet
from fastmcp import FastMCP, Context
from pydantic import BaseModel, Field
import structlog
import os
import time
from fastmcp.server.dependencies import get_http_request

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.UnicodeDecoder(),
        structlog.dev.ConsoleRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

# Production Configuration
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", Fernet.generate_key().decode())
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_POOL_SIZE = int(os.getenv("REDIS_POOL_SIZE", "200"))  # Connection pool size for scaling
HTTP_POOL_SIZE = int(os.getenv("HTTP_POOL_SIZE", "100"))  # HTTP connection pool size
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "90"))  # Cloudways API allows 100, we use 90
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # 1 minute

# Initialize encryption
fernet = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)

# Global Redis connection and HTTP client
redis_client: Optional[redis.Redis] = None
http_client: Optional[httpx.AsyncClient] = None

mcp = FastMCP("cloudways-mcp")

CLOUDWAYS_API_BASE = "https://api.cloudways.com/api/v1"
TOKEN_URL = f"{CLOUDWAYS_API_BASE}/oauth/access_token"

class ServerIdParam(BaseModel):
    server_id: int

class AppParams(BaseModel):
    server_id: int
    app_id: int

class Customer:
    """Customer entity for isolation"""
    def __init__(self, customer_id: str, email: str, cloudways_email: str, 
                 cloudways_api_key: str, created_at: datetime):
        self.customer_id = customer_id
        self.email = email
        self.cloudways_email = cloudways_email
        self.cloudways_api_key = cloudways_api_key
        self.created_at = created_at
        self.last_seen = datetime.utcnow()

async def init_redis():
    """Initialize Redis connection with connection pooling"""
    global redis_client
    try:
        redis_client = redis.from_url(
            REDIS_URL,
            decode_responses=True,
            max_connections=REDIS_POOL_SIZE,
            retry_on_timeout=True,
            socket_keepalive=True,
            socket_keepalive_options={},
            health_check_interval=30
        )
        await redis_client.ping()
        logger.info("Redis connected successfully", 
                   url=REDIS_URL, 
                   pool_size=REDIS_POOL_SIZE)
    except Exception as e:
        logger.error("Redis connection failed", error=str(e))
        redis_client = None


async def init_http_client():
    """Initialize HTTP client with connection pooling"""
    global http_client
    try:
        # Configure connection limits for high concurrency
        limits = httpx.Limits(
            max_connections=HTTP_POOL_SIZE,
            max_keepalive_connections=20,
            keepalive_expiry=5.0
        )
        
        # Configure timeouts
        timeout = httpx.Timeout(
            connect=10.0,
            read=30.0,
            write=10.0,
            pool=5.0
        )
        
        http_client = httpx.AsyncClient(
            limits=limits,
            timeout=timeout,
            follow_redirects=True,
            verify=True
        )
        
        logger.info("HTTP client initialized", 
                   max_connections=HTTP_POOL_SIZE,
                   keepalive_connections=20)
    except Exception as e:
        logger.error("HTTP client initialization failed", error=str(e))
        http_client = None


async def close_http_client():
    """Close HTTP client gracefully"""
    global http_client
    if http_client:
        await http_client.aclose()
        http_client = None
        logger.info("HTTP client closed")

async def get_customer_from_headers(ctx: Context) -> Optional[Customer]:
    """Extract customer from headers and create/get customer with encryption"""
    try:
        http_request = get_http_request()
        email = http_request.headers.get("x-cloudways-email")
        api_key = http_request.headers.get("x-cloudways-api-key")

        if not email or not api_key:
            raise ValueError("Missing x-cloudways-email or x-cloudways-api-key headers.")
        
        # Create customer ID from credentials hash (deterministic)
        customer_hash = hashlib.sha256(f"{email}:{api_key}".encode()).hexdigest()
        customer_id = f"customer_{customer_hash[:16]}"
        
        # Check Redis cache first
        if redis_client:
            try:
                cached_data = await redis_client.get(f"customer:{customer_id}")
                if cached_data:
                    data = json.loads(cached_data)
                    # Decrypt API key
                    decrypted_key = fernet.decrypt(data["encrypted_api_key"].encode()).decode()
                    
                    customer = Customer(
                        customer_id=customer_id,
                        email=data["email"],
                        cloudways_email=data["cloudways_email"],
                        cloudways_api_key=decrypted_key,
                        created_at=datetime.fromisoformat(data["created_at"])
                    )
                    
                    # Update last seen
                    customer.last_seen = datetime.utcnow()
                    await _cache_customer(customer)
                    
                    logger.debug("Customer loaded from cache", customer_id=customer_id)
                    return customer
            except Exception as e:
                logger.warning("Failed to load customer from cache", error=str(e))
        
        # Create new customer
        customer = Customer(
            customer_id=customer_id,
            email=email,
            cloudways_email=email,
            cloudways_api_key=api_key,
            created_at=datetime.utcnow()
        )
        
        # Cache customer with encryption
        await _cache_customer(customer)
        
        logger.info("New customer created", customer_id=customer_id, email=email)
        return customer
        
    except Exception as e:
        logger.error("Failed to get customer from headers", error=str(e))
        return None

async def _cache_customer(customer: Customer):
    """Cache customer data with encrypted API key"""
    if not redis_client:
        return
    
    try:
        # Encrypt sensitive data
        encrypted_api_key = fernet.encrypt(customer.cloudways_api_key.encode()).decode()
        
        customer_data = {
            "customer_id": customer.customer_id,
            "email": customer.email,
            "cloudways_email": customer.cloudways_email,
            "encrypted_api_key": encrypted_api_key,
            "created_at": customer.created_at.isoformat(),
            "last_seen": customer.last_seen.isoformat()
        }
        
        # Cache for 1 hour
        await redis_client.setex(
            f"customer:{customer.customer_id}",
            3600,
            json.dumps(customer_data)
        )
        
    except Exception as e:
        logger.error("Failed to cache customer", error=str(e))

async def check_rate_limit(customer_id: str, endpoint: str) -> bool:
    """Check rate limits using token bucket algorithm"""
    if not redis_client:
        return True  # Fail open if Redis unavailable
    
    try:
        key = f"rate_limit:{customer_id}:{endpoint}"
        now = time.time()
        
        # Token bucket algorithm
        bucket_data = await redis_client.get(key)
        if bucket_data:
            bucket = json.loads(bucket_data)
            tokens = bucket["tokens"]
            last_refill = bucket["last_refill"]
        else:
            tokens = RATE_LIMIT_REQUESTS
            last_refill = now
        
        # Refill tokens
        time_passed = now - last_refill
        tokens_to_add = time_passed * (RATE_LIMIT_REQUESTS / RATE_LIMIT_WINDOW)
        tokens = min(RATE_LIMIT_REQUESTS, tokens + tokens_to_add)
        
        if tokens >= 1:
            # Allow request
            tokens -= 1
            bucket_data = {
                "tokens": tokens,
                "last_refill": now
            }
            await redis_client.setex(key, RATE_LIMIT_WINDOW * 2, json.dumps(bucket_data))
            return True
        else:
            # Rate limit exceeded
            logger.warning("Rate limit exceeded", customer_id=customer_id, endpoint=endpoint)
            return False
            
    except Exception as e:
        logger.error("Rate limit check failed", error=str(e))
        return True  # Fail open

async def get_cloudways_token(customer: Customer) -> str:
    """Get/refresh Cloudways token with customer isolation using pooled HTTP client"""
    try:
        # Check cached token first
        if redis_client:
            token_key = f"token:{customer.customer_id}"
            cached_token = await redis_client.get(token_key)
            if cached_token:
                logger.debug("Using cached token", customer_id=customer.customer_id)
                return cached_token
        
        # Get new token using pooled HTTP client
        if http_client:
            resp = await http_client.post(TOKEN_URL, data={
                "email": customer.cloudways_email,
                "api_key": customer.cloudways_api_key
            })
        else:
            # Fallback to creating a new client if pooled client unavailable
            async with httpx.AsyncClient() as client:
                resp = await client.post(TOKEN_URL, data={
                    "email": customer.cloudways_email,
                    "api_key": customer.cloudways_api_key
                })
        
        resp.raise_for_status()
        data = resp.json()
        
        token = data.get("access_token")
        if not token:
            raise ValueError("No access_token returned from Cloudways API")
        
        # Cache token
        if redis_client:
            expires_in = data.get("expires_in", 3600)
            await redis_client.setex(f"token:{customer.customer_id}", expires_in - 60, token)
        
        logger.info("New Cloudways token obtained", customer_id=customer.customer_id)
        return token
        
    except Exception as e:
        logger.error("Failed to get Cloudways token", customer_id=customer.customer_id, error=str(e))
        raise RuntimeError(f"Authentication failed: {str(e)}")

async def make_api_request(ctx: Context, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Make API request with customer isolation and rate limiting using pooled HTTP client"""
    try:
        # Get customer
        customer = await get_customer_from_headers(ctx)
        if not customer:
            return {"status": "error", "message": "Authentication required"}
        
        # Check rate limits
        if not await check_rate_limit(customer.customer_id, endpoint):
            return {
                "status": "error",
                "message": "Rate limit exceeded. Please try again later.",
                "retry_after": 60
            }
        
        # Get token
        token = await get_cloudways_token(customer)
        
        # Make request using pooled HTTP client
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"
        }
        
        if http_client:
            resp = await http_client.get(f"{CLOUDWAYS_API_BASE}{endpoint}", headers=headers, params=params)
        else:
            # Fallback to creating a new client if pooled client unavailable
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(f"{CLOUDWAYS_API_BASE}{endpoint}", headers=headers, params=params)
        
        resp.raise_for_status()
        result = resp.json()
        
        logger.info("API request successful", 
                   customer_id=customer.customer_id,
                   endpoint=endpoint,
                   status_code=resp.status_code)
        
        return result
        
    except httpx.HTTPStatusError as e:
        logger.error("API request failed", endpoint=endpoint, status_code=e.response.status_code)
        return {"status": "error", "message": f"HTTP error: {e.response.status_code}"}
    except Exception as e:
        logger.error("API request failed", endpoint=endpoint, error=str(e))
        return {"status": "error", "message": f"Request failed: {str(e)}"}

# All your original tools - unchanged except using the new make_api_request
@mcp.tool()
async def ping(ctx: Context) -> str:
    """Test connectivity and authentication"""
    customer = await get_customer_from_headers(ctx)
    if customer:
        return f"Pong! Authenticated as {customer.cloudways_email} (Customer: {customer.customer_id})"
    else:
        return "Pong! No authentication provided."

@mcp.tool()
async def customer_info(ctx: Context) -> Dict[str, Any]:
    """Get current customer information"""
    customer = await get_customer_from_headers(ctx)
    if not customer:
        return {"status": "error", "message": "Authentication required"}
    
    return {
        "customer_id": customer.customer_id,
        "email": customer.email,
        "cloudways_email": customer.cloudways_email,
        "created_at": customer.created_at.isoformat(),
        "last_seen": customer.last_seen.isoformat(),
        "namespace": f"customer:{customer.customer_id}"
    }

@mcp.tool()
async def rate_limit_status(ctx: Context) -> Dict[str, Any]:
    """Get current rate limit status"""
    customer = await get_customer_from_headers(ctx)
    if not customer or not redis_client:
        return {"status": "error", "message": "Rate limiting not available"}
    
    try:
        key = f"rate_limit:{customer.customer_id}:*"
        # Get all rate limit keys for this customer
        keys = await redis_client.keys(key)
        
        stats = {}
        for key in keys:
            endpoint = key.split(":")[-1]
            bucket_data = await redis_client.get(key)
            if bucket_data:
                bucket = json.loads(bucket_data)
                stats[endpoint] = {
                    "tokens_remaining": int(bucket["tokens"]),
                    "max_tokens": RATE_LIMIT_REQUESTS,
                    "last_refill": bucket["last_refill"]
                }
        
        return {
            "customer_id": customer.customer_id,
            "rate_limits": stats,
            "window_seconds": RATE_LIMIT_WINDOW,
            "requests_per_minute": RATE_LIMIT_REQUESTS
        }
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

# All original Cloudways tools - using the enhanced make_api_request
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
                    return {"status": "success", "ssh_keys": srv.get("ssh_keys", [])}
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

async def startup():
    """Initialize Redis and HTTP client on startup"""
    await init_redis()
    await init_http_client()

if __name__ == "__main__":
    print("=" * 90)
    print("🚀 Cloudways MCP Server")
    print("=" * 90)

    # Initialize and run
    asyncio.run(startup())
    
    asyncio.run(mcp.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=7000,
        path="/mcp",
        )
    )