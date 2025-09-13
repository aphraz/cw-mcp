#!/usr/bin/env python3
"""
Production-grade FastMCP HTTP Server for Cloudways API
"""

import asyncio
import httpx
import redis.asyncio as redis
import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI
import uvicorn

from server import mcp
from config import REDIS_URL, REDIS_POOL_SIZE, HTTP_POOL_SIZE, configure_logging
from auth.tokens import TokenManager

# Configure logging
configure_logging()
logger = structlog.get_logger(__name__)

# Global resource pool - initialized once at startup
class Resources:
    """Singleton resource container"""
    redis_client: redis.Redis = None
    http_client: httpx.AsyncClient = None
    token_manager: TokenManager = None
    initialized: bool = False

resources = Resources()

async def init_resources():
    """Initialize all resources once at startup"""
    if resources.initialized:
        return

    logger.info("Initializing server resources")

    # Initialize Redis connection pool
    try:
        resources.redis_client = redis.from_url(
            REDIS_URL,
            decode_responses=True,
            max_connections=REDIS_POOL_SIZE
        )
        await resources.redis_client.ping()
        logger.info("Redis connected", pool_size=REDIS_POOL_SIZE)
    except Exception as e:
        logger.warning("Redis unavailable, running without cache", error=str(e))

    # Initialize HTTP client pool
    resources.http_client = httpx.AsyncClient(
        limits=httpx.Limits(
            max_connections=HTTP_POOL_SIZE,
            max_keepalive_connections=100
        ),
        timeout=httpx.Timeout(30.0, connect=10.0)
    )
    logger.info("HTTP client initialized", pool_size=HTTP_POOL_SIZE)

    # Initialize token manager if Redis is available
    if resources.redis_client:
        resources.token_manager = TokenManager(
            resources.redis_client,
            resources.http_client
        )
        logger.info("Token manager initialized")

    # Import and inject dependencies into tool modules
    # This happens ONCE at startup, not per request
    from tools import basic, servers, apps, security

    for module in [basic, servers, apps, security]:
        module.redis_client = resources.redis_client
        module.http_client = resources.http_client
        module.token_manager = resources.token_manager

    resources.initialized = True
    logger.info("Server initialization complete")

async def cleanup_resources():
    """Cleanup resources on shutdown"""
    if resources.http_client:
        await resources.http_client.aclose()
    if resources.redis_client:
        await resources.redis_client.close()
    logger.info("Resources cleaned up")

@asynccontextmanager
async def app_lifespan(app: FastAPI):
    await init_resources()
    print("Starting up the app...")
    # Initialize database, cache, etc.
    yield
    await cleanup_resources()
    print("Shutting down the app...")

# Create the MCP HTTP app FIRST
mcp_app = mcp.http_app()

@asynccontextmanager
async def combined_lifespan(app: FastAPI):
    """Combined lifespan for both FastAPI and FastMCP"""
    # Initialize our resources
    #await init_resources()

    # Run the MCP app's lifespan
    async with app_lifespan(app):
        async with mcp_app.lifespan(app):
            yield

    # Cleanup our resources
    #await cleanup_resources()

# Create FastAPI app with the COMBINED lifespan
app = FastAPI(
    title="Cloudways MCP Server",
    version="1.0.0",
    lifespan=combined_lifespan  # Use combined lifespan
)

# Mount the MCP app
app.mount("/mcp", mcp_app)

@app.get("/health")
async def health():
    """Health check endpoint for load balancers"""
    return {
        "status": "healthy",
        "redis": resources.redis_client is not None,
        "initialized": resources.initialized
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Cloudways MCP Server",
        "version": "1.0.0",
        "endpoints": {
            "mcp": "/mcp",
            "health": "/health"
        }
    }

def main():
    """Production server entry point"""
    import os

    # Production configuration
    workers = int(os.getenv("WORKERS", "1"))  # Single worker for MCP compatibility

    print("=" * 50)
    print("🚀 Cloudways MCP Server (Production)")
    print(f"Workers: {workers}")
    print(f"Port: 7000")
    print("=" * 50)

    # For MCP: use single worker to maintain session state
    # Scale horizontally with multiple instances behind a load balancer instead
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=7000,
        workers=workers,
        loop="uvloop" if workers == 1 else "asyncio",  # uvloop for single worker
        log_level="info",
        access_log=False,  # Disable in production for performance
        reload=False
    )

if __name__ == "__main__":
    # For development: single worker with reload
    import sys
    if "--dev" in sys.argv:
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=7000,
            reload=True,
            log_level="debug"
        )
    else:
        main()
