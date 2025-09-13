#!/usr/bin/env python3
"""
Stdio-based MCP server for Claude Desktop and other MCP clients
This version uses stdio transport instead of HTTP
"""

import asyncio
import httpx
import redis.asyncio as redis
import structlog
from server import mcp
from config import REDIS_URL, REDIS_POOL_SIZE, HTTP_POOL_SIZE, configure_logging
from auth.tokens import TokenManager

# Configure logging from config
configure_logging()

logger = structlog.get_logger(__name__)

# Global components
redis_client = None
http_client = None
token_manager = None

async def init_redis():
    """Initialize Redis connection"""
    global redis_client
    try:
        redis_client = redis.from_url(REDIS_URL, decode_responses=True, max_connections=REDIS_POOL_SIZE)
        await redis_client.ping()
        logger.info("Redis connected successfully", url=REDIS_URL)
        return True
    except Exception as e:
        logger.error("Redis connection failed", error=str(e))
        redis_client = None
        return False

async def init_http_client():
    """Initialize HTTP client"""
    global http_client
    try:
        http_client = httpx.AsyncClient(
            limits=httpx.Limits(max_connections=HTTP_POOL_SIZE, max_keepalive_connections=100),
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0)
        )
        logger.info("HTTP client initialized")
        return True
    except Exception as e:
        logger.error("HTTP client initialization failed", error=str(e))
        http_client = None
        return False

def inject_dependencies():
    """Inject shared components into tool modules"""
    global redis_client, http_client, token_manager
    
    # Import all tool modules to trigger @mcp.tool decorator registration
    from tools import basic, servers, apps, security
    
    # Inject dependencies into all tool modules
    basic.redis_client = redis_client
    basic.http_client = http_client
    basic.token_manager = token_manager
    
    servers.redis_client = redis_client
    servers.http_client = http_client
    servers.token_manager = token_manager
    
    apps.redis_client = redis_client
    apps.http_client = http_client
    apps.token_manager = token_manager
    
    security.redis_client = redis_client
    security.http_client = http_client
    security.token_manager = token_manager
    
    logger.info("Dependencies injected into tool modules")

async def initialize_server():
    """Initialize all server components"""
    global token_manager
    
    logger.info("Initializing Cloudways MCP Server (stdio mode)")
    
    # Initialize components
    redis_ok = await init_redis()
    http_ok = await init_http_client()
    
    if redis_ok and http_ok:
        token_manager = TokenManager(redis_client, http_client)
        logger.info("Token manager initialized with proactive renewal")
    else:
        logger.warning("Some components failed to initialize")
    
    # Inject dependencies regardless (tools will handle missing dependencies)
    inject_dependencies()
    
    logger.info("MCP server initialization complete")

async def cleanup():
    """Clean up resources on shutdown"""
    global http_client, redis_client
    
    if http_client:
        await http_client.aclose()
        logger.info("HTTP client shut down")
    
    if redis_client:
        await redis_client.close()
        logger.info("Redis client shut down")

async def main():
    """Main entry point for stdio-based MCP server"""
    # Initialize server components first
    await initialize_server()
    
    try:
        # Run the stdio server
        logger.info("Starting MCP stdio server")
        await mcp.run()
    finally:
        await cleanup()

if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())
