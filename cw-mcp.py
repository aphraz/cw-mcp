#!/usr/bin/env python3
"""
Cloudways MCP Server
Features:
- Enhanced token management with proactive renewal
- Customer isolation with encryption
- Rate limiting
- Basic logging for administrators (no customer-facing tools)

"""

import asyncio
import json
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any
import httpx
import redis.asyncio as redis
from cryptography.fernet import Fernet
from fastmcp import FastMCP, Context
from pydantic import BaseModel
import structlog
import os
import time
from fastmcp.server.dependencies import get_http_request

# Configure simple logging
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

# Configuration
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", Fernet.generate_key().decode())
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_POOL_SIZE = int(os.getenv("REDIS_POOL_SIZE", "200"))
HTTP_POOL_SIZE = int(os.getenv("HTTP_POOL_SIZE", "100"))
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "90"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))

# Initialize encryption
fernet = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)

# Global components
redis_client: Optional[redis.Redis] = None
http_client: Optional[httpx.AsyncClient] = None
token_manager: Optional['TokenManager'] = None

mcp = FastMCP("cloudways-mcp")

CLOUDWAYS_API_BASE = "https://api.cloudways.com/api/v1"
TOKEN_URL = f"{CLOUDWAYS_API_BASE}/oauth/access_token"

class TokenManager:
    """Enhanced token manager with proactive renewal and race condition protection"""
    
    def __init__(self, redis_client: redis.Redis, http_client: httpx.AsyncClient):
        self.redis_client = redis_client
        self.http_client = http_client
        self.refresh_threshold = 300  # Refresh when 5 minutes remaining
        self.min_refresh_threshold = 60  # Minimum 1 minute before expiry
        
    async def get_token(self, customer: 'Customer') -> str:
        """Get token with proactive renewal and race condition protection"""
        token_key = f"token:{customer.customer_id}"
        meta_key = f"token_meta:{customer.customer_id}"
        lock_key = f"token_lock:{customer.customer_id}"
        
        try:
            # Check if we have a valid cached token
            cached_token = await self.redis_client.get(token_key)
            token_meta = await self.redis_client.get(meta_key)
            
            if cached_token and token_meta:
                meta = json.loads(token_meta)
                expires_at = meta.get("expires_at", 0)
                current_time = time.time()
                time_until_expiry = expires_at - current_time
                
                if time_until_expiry > self.refresh_threshold:
                    logger.debug("Using fresh cached token", customer_id=customer.customer_id)
                    return cached_token
                    
                elif time_until_expiry > self.min_refresh_threshold:
                    # Background refresh
                    asyncio.create_task(self._refresh_token_background(customer))
                    logger.debug("Using cached token with background refresh", customer_id=customer.customer_id)
                    return cached_token
                
                logger.info("Token near expiry, refreshing immediately", customer_id=customer.customer_id)
            
            # Need immediate refresh with lock protection
            lock_acquired = await self._acquire_refresh_lock(lock_key)
            
            if not lock_acquired:
                await asyncio.sleep(0.1)
                refreshed_token = await self.redis_client.get(token_key)
                if refreshed_token:
                    logger.debug("Using token refreshed by another process", customer_id=customer.customer_id)
                    return refreshed_token
            
            try:
                token_data = await self._fetch_new_token(customer)
                await self._cache_token_with_metadata(customer, token_data)
                logger.info("Successfully refreshed token", customer_id=customer.customer_id)
                return token_data["access_token"]
            finally:
                await self._release_refresh_lock(lock_key)
                
        except Exception as e:
            logger.error("Token management failed", customer_id=customer.customer_id, error=str(e))
            raise RuntimeError(f"Authentication failed: {str(e)}")
    
    async def _acquire_refresh_lock(self, lock_key: str) -> bool:
        try:
            result = await self.redis_client.set(lock_key, "locked", ex=30, nx=True)
            return result is True
        except Exception:
            return False
    
    async def _release_refresh_lock(self, lock_key: str):
        try:
            await self.redis_client.delete(lock_key)
        except Exception as e:
            logger.warning("Failed to release refresh lock", error=str(e))
    
    async def _refresh_token_background(self, customer: 'Customer'):
        try:
            lock_key = f"token_lock:{customer.customer_id}"
            if await self._acquire_refresh_lock(lock_key):
                try:
                    token_data = await self._fetch_new_token(customer)
                    await self._cache_token_with_metadata(customer, token_data)
                    logger.info("Background token refresh successful", customer_id=customer.customer_id)
                finally:
                    await self._release_refresh_lock(lock_key)
        except Exception as e:
            logger.warning("Background token refresh failed", customer_id=customer.customer_id, error=str(e))
    
    async def _fetch_new_token(self, customer: 'Customer') -> Dict[str, Any]:
        resp = await self.http_client.post(TOKEN_URL, data={
            "email": customer.cloudways_email,
            "api_key": customer.cloudways_api_key
        }, timeout=30.0)
        
        resp.raise_for_status()
        data = resp.json()
        
        if not data.get("access_token"):
            raise ValueError("No access_token returned from Cloudways API")
        
        return data
    
    async def _cache_token_with_metadata(self, customer: 'Customer', token_data: Dict[str, Any]):
        token = token_data.get("access_token")
        expires_in = token_data.get("expires_in", 3600)
        current_time = time.time()
        
        # Store token
        token_ttl = max(expires_in - self.min_refresh_threshold, 300)
        await self.redis_client.setex(f"token:{customer.customer_id}", token_ttl, token)
        
        # Store metadata
        metadata = {
            "expires_at": current_time + expires_in,
            "expires_in": expires_in,
            "created_at": current_time,
            "refresh_threshold": self.refresh_threshold
        }
        await self.redis_client.setex(f"token_meta:{customer.customer_id}", expires_in, json.dumps(metadata))

class ServerIdParam(BaseModel):
    server_id: int

class AppParams(BaseModel):
    server_id: int
    app_id: int

class Customer:
    def __init__(self, customer_id: str, email: str, cloudways_email: str, 
                 cloudways_api_key: str, created_at: datetime):
        self.customer_id = customer_id
        self.email = email
        self.cloudways_email = cloudways_email
        self.cloudways_api_key = cloudways_api_key
        self.created_at = created_at
        self.last_seen = datetime.utcnow()

async def init_redis():
    global redis_client
    try:
        redis_client = redis.from_url(REDIS_URL, decode_responses=True, max_connections=REDIS_POOL_SIZE)
        await redis_client.ping()
        logger.info("Redis connected successfully", url=REDIS_URL)
    except Exception as e:
        logger.error("Redis connection failed", error=str(e))
        redis_client = None

async def init_http_client():
    global http_client
    try:
        http_client = httpx.AsyncClient(
            limits=httpx.Limits(max_connections=HTTP_POOL_SIZE, max_keepalive_connections=20),
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0)
        )
        logger.info("HTTP client initialized")
    except Exception as e:
        logger.error("HTTP client initialization failed", error=str(e))
        http_client = None

async def get_customer_from_headers(ctx: Context) -> Optional[Customer]:
    try:
        http_request = get_http_request()
        email = http_request.headers.get("x-cloudways-email")
        api_key = http_request.headers.get("x-cloudways-api-key")

        if not email or not api_key:
            raise ValueError("Missing authentication headers")
        
        customer_hash = hashlib.sha256(f"{email}:{api_key}".encode()).hexdigest()
        customer_id = f"customer_{customer_hash[:16]}"
        
        # Check cache
        if redis_client:
            try:
                cached_data = await redis_client.get(f"customer:{customer_id}")
                if cached_data:
                    data = json.loads(cached_data)
                    decrypted_key = fernet.decrypt(data["encrypted_api_key"].encode()).decode()
                    
                    customer = Customer(
                        customer_id=customer_id,
                        email=data["email"],
                        cloudways_email=data["cloudways_email"],
                        cloudways_api_key=decrypted_key,
                        created_at=datetime.fromisoformat(data["created_at"])
                    )
                    logger.debug("Customer loaded from cache", customer_id=customer_id)
                    return customer
            except Exception as e:
                logger.warning("Failed to load customer from cache", error=str(e))
        
        # Create new customer
        customer = Customer(customer_id, email, email, api_key, datetime.utcnow())
        await _cache_customer(customer)
        logger.info("New customer created", customer_id=customer_id)
        return customer
        
    except Exception as e:
        logger.error("Failed to get customer from headers", error=str(e))
        return None

async def _cache_customer(customer: Customer):
    if not redis_client:
        return
    
    try:
        encrypted_api_key = fernet.encrypt(customer.cloudways_api_key.encode()).decode()
        customer_data = {
            "customer_id": customer.customer_id,
            "email": customer.email,
            "cloudways_email": customer.cloudways_email,
            "encrypted_api_key": encrypted_api_key,
            "created_at": customer.created_at.isoformat(),
            "last_seen": customer.last_seen.isoformat()
        }
        await redis_client.setex(f"customer:{customer.customer_id}", 3600, json.dumps(customer_data))
    except Exception as e:
        logger.error("Failed to cache customer", error=str(e))

async def check_rate_limit(customer_id: str, endpoint: str) -> bool:
    if not redis_client:
        return True
    
    try:
        key = f"rate_limit:{customer_id}:{endpoint}"
        now = time.time()
        
        bucket_data = await redis_client.get(key)
        if bucket_data:
            bucket = json.loads(bucket_data)
            tokens = bucket["tokens"]
            last_refill = bucket["last_refill"]
        else:
            tokens = RATE_LIMIT_REQUESTS
            last_refill = now
        
        # Token bucket refill
        time_passed = now - last_refill
        tokens_to_add = time_passed * (RATE_LIMIT_REQUESTS / RATE_LIMIT_WINDOW)
        tokens = min(RATE_LIMIT_REQUESTS, tokens + tokens_to_add)
        
        if tokens >= 1:
            tokens -= 1
            await redis_client.setex(key, RATE_LIMIT_WINDOW * 2, json.dumps({
                "tokens": tokens,
                "last_refill": now
            }))
            return True
        else:
            logger.warning("Rate limit exceeded", customer_id=customer_id, endpoint=endpoint)
            return False
            
    except Exception as e:
        logger.error("Rate limit check failed", error=str(e))
        return True

async def get_cloudways_token(customer: Customer) -> str:
    global token_manager
    
    if not token_manager and redis_client and http_client:
        token_manager = TokenManager(redis_client, http_client)
    
    if token_manager:
        return await token_manager.get_token(customer)
    
    # Fallback method
    if redis_client:
        cached_token = await redis_client.get(f"token:{customer.customer_id}")
        if cached_token:
            return cached_token
    
    resp = await http_client.post(TOKEN_URL, data={
        "email": customer.cloudways_email,
        "api_key": customer.cloudways_api_key
    })
    resp.raise_for_status()
    data = resp.json()
    token = data.get("access_token")
    
    if not token:
        raise ValueError("No access_token returned")
    
    if redis_client:
        await redis_client.setex(f"token:{customer.customer_id}", 3540, token)
    
    return token

async def make_api_request(ctx: Context, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    try:
        customer = await get_customer_from_headers(ctx)
        if not customer:
            return {"status": "error", "message": "Authentication required"}
        
        if not await check_rate_limit(customer.customer_id, endpoint):
            return {"status": "error", "message": "Rate limit exceeded", "retry_after": 60}
        
        token = await get_cloudways_token(customer)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        
        resp = await http_client.get(f"{CLOUDWAYS_API_BASE}{endpoint}", headers=headers, params=params)
        resp.raise_for_status()
        result = resp.json()
        
        logger.info("API request successful", customer_id=customer.customer_id, endpoint=endpoint)
        return result
        
    except httpx.HTTPStatusError as e:
        logger.error("API request failed", endpoint=endpoint, status_code=e.response.status_code)
        return {"status": "error", "message": f"HTTP error: {e.response.status_code}"}
    except Exception as e:
        logger.error("API request failed", endpoint=endpoint, error=str(e))
        return {"status": "error", "message": f"Request failed: {str(e)}"}

# Customer-facing tools (no admin/monitoring tools)
@mcp.tool()
async def ping(ctx: Context) -> str:
    """Test connectivity and authentication"""
    customer = await get_customer_from_headers(ctx)
    if customer:
        return f"Pong! Authenticated as {customer.cloudways_email}"
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
        "last_seen": customer.last_seen.isoformat()
    }

@mcp.tool()
async def rate_limit_status(ctx: Context) -> Dict[str, Any]:
    """Get current rate limit status"""
    customer = await get_customer_from_headers(ctx)
    if not customer or not redis_client:
        return {"status": "error", "message": "Rate limiting not available"}
    
    try:
        keys = await redis_client.keys(f"rate_limit:{customer.customer_id}:*")
        stats = {}
        
        for key in keys:
            endpoint = key.split(":")[-1]
            bucket_data = await redis_client.get(key)
            if bucket_data:
                bucket = json.loads(bucket_data)
                stats[endpoint] = {
                    "tokens_remaining": int(bucket["tokens"]),
                    "max_tokens": RATE_LIMIT_REQUESTS
                }
        
        return {
            "customer_id": customer.customer_id,
            "rate_limits": stats,
            "requests_per_minute": RATE_LIMIT_REQUESTS
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

# Cloudways API tools
@mcp.tool()
async def list_servers(ctx: Context) -> Dict[str, Any]:
    """Get list of servers in your Cloudways account"""
    return await make_api_request(ctx, "/server")

@mcp.tool()
async def get_server_details(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """Get details of a specific server including monitoring data"""
    bw = await make_api_request(ctx, "/server/monitor/summary", {"server_id": server.server_id, "type": "bw"})
    db = await make_api_request(ctx, "/server/monitor/summary", {"server_id": server.server_id, "type": "db"})
    return {"status": "success", "bandwidth": bw, "disk": db}

@mcp.tool()
async def get_app_details(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """Get details of a specific application"""
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
    """Get application credentials"""
    return await make_api_request(ctx, "/app/creds", {"server_id": app.server_id, "app_id": app.app_id})

@mcp.tool()
async def get_app_settings(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """Get application settings"""
    return await make_api_request(ctx, "/app/get_settings_value", {"server_id": app.server_id, "app_id": app.app_id})

@mcp.tool()
async def get_app_monitoring_summary(ctx: Context, app: AppParams) -> Dict[str, Any]:
    """Get application monitoring summary"""
    bw = await make_api_request(ctx, "/app/monitor/summary", {"server_id": app.server_id, "app_id": app.app_id, "type": "bw"})
    db = await make_api_request(ctx, "/app/monitor/summary", {"server_id": app.server_id, "app_id": app.app_id, "type": "db"})
    return {"status": "success", "bandwidth": bw, "disk": db}

@mcp.tool()
async def list_projects(ctx: Context) -> Dict[str, Any]:
    """Get list of projects"""
    return await make_api_request(ctx, "/project")

@mcp.tool()
async def list_team_members(ctx: Context) -> Dict[str, Any]:
    """Get list of team members"""
    return await make_api_request(ctx, "/member")

@mcp.tool()
async def get_alerts(ctx: Context) -> Dict[str, Any]:
    """Get list of all alerts"""
    return await make_api_request(ctx, "/alerts/")

@mcp.tool()
async def get_ssh_keys(ctx: Context, server: ServerIdParam) -> Dict[str, Any]:
    """Get SSH keys for a server"""
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
    """Get list of available cloud providers"""
    return await make_api_request(ctx, "/providers")

@mcp.tool()
async def get_available_regions(ctx: Context) -> Dict[str, Any]:
    """Get list of available regions for each cloud provider"""
    return await make_api_request(ctx, "/regions")

@mcp.tool()
async def get_available_server_sizes(ctx: Context) -> Dict[str, Any]:
    """Get list of available server sizes for each cloud provider"""
    return await make_api_request(ctx, "/server_sizes")

@mcp.tool()
async def get_available_apps(ctx: Context) -> Dict[str, Any]:
    """Get list of available applications that can be installed"""
    return await make_api_request(ctx, "/apps")

@mcp.tool()
async def get_available_packages(ctx: Context) -> Dict[str, Any]:
    """Get list of available packages and their versions"""
    return await make_api_request(ctx, "/packages")

async def startup():
    """Initialize components"""
    global token_manager
    
    logger.info("Starting Cloudways MCP Server")
    await init_redis()
    await init_http_client()
    
    if redis_client and http_client:
        token_manager = TokenManager(redis_client, http_client)
        logger.info("Token manager initialized with proactive renewal")
    else:
        logger.warning("Token manager not initialized - Redis or HTTP client unavailable")

if __name__ == "__main__":
    print("=" * 50)
    print("🚀 Cloudways MCP Server")
    print("=" * 50)

    asyncio.run(startup())
    
    try:
        asyncio.run(mcp.run(
            transport="streamable-http",
            host="127.0.0.1",
            port=7000,
            path="/mcp",
        ))
    except KeyboardInterrupt:
        logger.info("Server shutting down gracefully")
    except Exception as e:
        logger.error("Server crashed", error=str(e))
        raise
