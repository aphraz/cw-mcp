#!/usr/bin/env python3
"""
Production-grade FastMCP HTTP Server for Cloudways API
"""

import asyncio
import httpx
import redis.asyncio as redis
import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, EmailStr, ValidationError
import uvicorn

from server import mcp
from config import (
    REDIS_URL, REDIS_POOL_SIZE, HTTP_POOL_SIZE, configure_logging,
    AUTH_BASE_URL, CLOUDWAYS_API_BASE, TOKEN_URL,
    MAX_AUTH_ATTEMPTS_PER_SESSION, MAX_AUTH_ATTEMPTS_PER_IP, AUTH_LOCKOUT_DURATION
)
from auth.tokens import TokenManager
from auth.session import SessionManager, AuthStatus, start_session_cleanup_task
from auth.browser_flow import BrowserAuthenticator
from auth.exceptions import (
    SessionNotFoundError, CloudwaysAPIError, RateLimitError,
    InvalidCredentialsError
)

# Initialize Jinja2 templates
templates = Jinja2Templates(directory="templates")

# Configure logging
configure_logging()
logger = structlog.get_logger(__name__)

# Global resource pool - initialized once at startup
class Resources:
    """Singleton resource container"""
    redis_client: redis.Redis = None
    http_client: httpx.AsyncClient = None
    token_manager: TokenManager = None
    session_manager: SessionManager = None
    browser_authenticator: BrowserAuthenticator = None
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

        # Initialize session manager for OAuth authentication
        resources.session_manager = SessionManager(resources.redis_client)
        logger.info("Session manager initialized")

        # Start session cleanup background task
        asyncio.create_task(start_session_cleanup_task(resources.session_manager))
        logger.info("Session cleanup task started")

    # Initialize browser authenticator
    resources.browser_authenticator = BrowserAuthenticator()
    logger.info("Browser authenticator initialized")

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
            "health": "/health",
            "auth": "/auth"
        }
    }


# ==================== OAuth Authentication Endpoints ====================

@app.get("/auth", response_class=HTMLResponse)
async def auth_page(request: Request, session_id: str, reason: str = None):
    """
    Render authentication form.

    Args:
        session_id: Session identifier
        reason: Optional reason for authentication (e.g., "expired")

    Returns:
        HTML authentication form
    """
    logger.info("Authentication page requested", session_id=session_id, reason=reason)

    return templates.TemplateResponse(
        "auth_form.html",
        {
            "request": request,
            "session_id": session_id,
            "reason": reason
        }
    )


async def check_auth_rate_limit(session_id: str, ip: str) -> bool:
    """
    Check authentication rate limits.

    Args:
        session_id: Session identifier
        ip: Client IP address

    Returns:
        True if within limits, raises RateLimitError otherwise
    """
    if not resources.redis_client:
        return True  # Skip rate limiting if Redis unavailable

    session_key = f"auth_attempts:{session_id}"
    ip_key = f"auth_attempts:ip:{ip}"

    # Check session-based rate limit
    session_attempts = await resources.redis_client.incr(session_key)
    if session_attempts == 1:
        await resources.redis_client.expire(session_key, AUTH_LOCKOUT_DURATION)

    if session_attempts > MAX_AUTH_ATTEMPTS_PER_SESSION:
        logger.warning(
            "Session rate limit exceeded",
            session_id=session_id,
            attempts=session_attempts
        )
        raise RateLimitError(
            f"Too many authentication attempts for this session. Try again in {AUTH_LOCKOUT_DURATION} seconds.",
            retry_after=AUTH_LOCKOUT_DURATION,
            attempt_count=session_attempts
        )

    # Check IP-based rate limit
    ip_attempts = await resources.redis_client.incr(ip_key)
    if ip_attempts == 1:
        await resources.redis_client.expire(ip_key, AUTH_LOCKOUT_DURATION)

    if ip_attempts > MAX_AUTH_ATTEMPTS_PER_IP:
        logger.warning(
            "IP rate limit exceeded",
            ip=ip,
            attempts=ip_attempts
        )
        raise RateLimitError(
            f"Too many authentication attempts from this IP. Try again in {AUTH_LOCKOUT_DURATION} seconds.",
            retry_after=AUTH_LOCKOUT_DURATION,
            attempt_count=ip_attempts
        )

    return True


@app.post("/auth/submit")
async def submit_credentials(
    request: Request,
    session_id: str = Form(...),
    email: str = Form(...),
    api_key: str = Form(...)
):
    """
    Process credential submission and exchange for access token.

    Args:
        session_id: Session identifier
        email: Cloudways email
        api_key: Cloudways API key

    Returns:
        JSON response with success/error status
    """
    client_ip = request.client.host if request.client else "unknown"

    logger.info(
        "Credential submission",
        session_id=session_id,
        email=email,
        ip=client_ip
    )

    try:
        # Validate email format
        try:
            EmailStr._validate(email)
        except:
            raise InvalidCredentialsError("email", "Invalid email format")

        # Validate API key length
        if len(api_key) < 20 or len(api_key) > 200:
            raise InvalidCredentialsError("api_key", "API key must be between 20-200 characters")

        # Check rate limits
        await check_auth_rate_limit(session_id, client_ip)

        # Verify session exists
        session = await resources.session_manager.get_session(session_id)
        if not session:
            raise SessionNotFoundError(session_id)

        # Exchange credentials for access token
        logger.info("Exchanging credentials for token", session_id=session_id)

        response = await resources.http_client.post(
            TOKEN_URL,
            data={"email": email, "api_key": api_key},
            timeout=30.0
        )

        if response.status_code != 200:
            logger.error(
                "Cloudways API rejected credentials",
                session_id=session_id,
                status_code=response.status_code
            )
            raise CloudwaysAPIError(
                "Invalid credentials or Cloudways API error",
                status_code=response.status_code
            )

        token_data = response.json()

        if not token_data.get("access_token"):
            raise CloudwaysAPIError("No access_token in response")

        # Store token with session
        access_token = token_data["access_token"]
        expires_in = token_data.get("expires_in", 3600)
        token_expires_at = asyncio.get_event_loop().time() + expires_in

        # Encrypt and store token
        from config import fernet
        encrypted_token = fernet.encrypt(access_token.encode()).decode()

        token_key = f"session:{session_id}:token"
        token_meta_key = f"session:{session_id}:token_meta"

        await resources.redis_client.setex(token_key, expires_in, encrypted_token)
        await resources.redis_client.setex(
            token_meta_key,
            expires_in,
            f'{{"expires_at": {token_expires_at}, "expires_in": {expires_in}}}'
        )

        # Generate customer ID
        import hashlib
        customer_hash = hashlib.sha256(f"{email}:{session_id}".encode()).hexdigest()
        customer_id = f"customer_{customer_hash[:16]}"

        # Update session status
        await resources.session_manager.update_session_status(
            session_id=session_id,
            status=AuthStatus.AUTHENTICATED,
            customer_id=customer_id,
            customer_email=email,
            token_expires_at=token_expires_at
        )

        logger.info(
            "Authentication successful",
            session_id=session_id,
            customer_id=customer_id
        )

        return JSONResponse({
            "status": "success",
            "message": "Authentication successful",
            "session_id": session_id
        })

    except (InvalidCredentialsError, SessionNotFoundError, CloudwaysAPIError, RateLimitError) as e:
        logger.error(
            "Authentication failed",
            session_id=session_id,
            error=str(e),
            error_type=type(e).__name__
        )
        return JSONResponse(
            status_code=400,
            content={
                "status": "error",
                "message": e.message if hasattr(e, 'message') else str(e),
                "error_type": type(e).__name__
            }
        )

    except Exception as e:
        logger.error(
            "Unexpected error during authentication",
            session_id=session_id,
            error=str(e)
        )
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "Internal server error"
            }
        )


@app.get("/auth/status/{session_id}")
async def check_auth_status(session_id: str):
    """
    Check authentication status for polling.

    Args:
        session_id: Session identifier

    Returns:
        JSON with session status
    """
    if not resources.session_manager:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "message": "Session manager not initialized"}
        )

    session = await resources.session_manager.get_session(session_id)

    if not session:
        return JSONResponse({
            "status": "not_found",
            "authenticated": False
        })

    return JSONResponse({
        "status": session.auth_status.value,
        "authenticated": session.is_authenticated()
    })


@app.get("/auth/success", response_class=HTMLResponse)
async def auth_success(request: Request):
    """Success page after authentication."""
    return templates.TemplateResponse("auth_success.html", {"request": request})


@app.get("/auth/error", response_class=HTMLResponse)
async def auth_error(request: Request, error_message: str = None, retry_url: str = None):
    """Error page for authentication failures."""
    return templates.TemplateResponse(
        "auth_error.html",
        {
            "request": request,
            "error_message": error_message or "Authentication failed",
            "retry_url": retry_url
        }
    )


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
