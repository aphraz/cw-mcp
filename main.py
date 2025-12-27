#!/usr/bin/env python3
"""
Production-grade FastMCP HTTP Server for Cloudways API
"""

import asyncio
import secrets
import time
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
from auth.oauth_token import OAuthTokenManager
from auth.bearer_auth import BearerTokenAuth
from auth.middleware import OAuthMiddleware
from auth.oauth_provider import CloudwaysOAuthProvider
from auth.exceptions import (
    SessionNotFoundError, CloudwaysAPIError, RateLimitError,
    InvalidCredentialsError
)

# Initialize Jinja2 templates
templates = Jinja2Templates(directory="templates")

# Configure logging
configure_logging()
logger = structlog.get_logger(__name__)

# Startup event to initialize middleware (backup if lifespan doesn't run)
async def init_middleware():
    """Initialize middleware with oauth_token_manager after resources are created"""
    if hasattr(resources, 'oauth_token_manager') and resources.oauth_token_manager:
        for middleware in app.user_middleware:
            if middleware.cls == OAuthMiddleware:
                middleware.kwargs["oauth_token_manager"] = resources.oauth_token_manager
                logger.info("Injected oauth_token_manager into middleware (startup event)")
                return
    logger.warning("Could not inject oauth_token_manager - resources not initialized")

# Global resource pool - initialized once at startup
class Resources:
    """Singleton resource container"""
    redis_client: redis.Redis = None
    http_client: httpx.AsyncClient = None
    token_manager: TokenManager = None
    session_manager: SessionManager = None
    browser_authenticator: BrowserAuthenticator = None
    oauth_token_manager: OAuthTokenManager = None
    bearer_auth: BearerTokenAuth = None
    oauth_provider: CloudwaysOAuthProvider = None
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

    # Initialize OAuth token manager
    if resources.redis_client:
        resources.oauth_token_manager = OAuthTokenManager(resources.redis_client)
        resources.bearer_auth = BearerTokenAuth(resources.oauth_token_manager)
        logger.info("OAuth token manager initialized")

        # Inject oauth_token_manager into middleware via global variable
        import auth.middleware
        auth.middleware._global_oauth_token_manager = resources.oauth_token_manager
        logger.info("Injected oauth_token_manager into middleware (global)")

        # Initialize FastMCP OAuth provider
        resources.oauth_provider = CloudwaysOAuthProvider(resources.redis_client)
        logger.info("FastMCP OAuth provider initialized")

        # Inject oauth_provider into customer.py via global variable
        import auth.customer
        auth.customer._global_oauth_provider = resources.oauth_provider
        logger.info("Injected oauth_provider into customer.py (global)")

        # Inject Redis client into server.py oauth_provider (used by FastMCP routes)
        from server import oauth_provider as server_oauth_provider
        server_oauth_provider._redis_client = resources.redis_client
        logger.info("Injected Redis client into server OAuth provider")

    # Import and inject dependencies into tool modules
    # This happens ONCE at startup, not per request
    from tools import basic, servers, apps, security

    for module in [basic, servers, apps, security]:
        module.redis_client = resources.redis_client
        module.http_client = resources.http_client
        module.token_manager = resources.token_manager
        module.session_manager = resources.session_manager
        module.browser_authenticator = resources.browser_authenticator
        module.oauth_token_manager = resources.oauth_token_manager
        module.bearer_auth = resources.bearer_auth

    resources.initialized = True
    logger.info("Server initialization complete")

async def cleanup_resources():
    """Cleanup resources on shutdown"""
    if resources.http_client:
        await resources.http_client.aclose()
    if resources.redis_client:
        await resources.redis_client.close()
    logger.info("Resources cleaned up")

# Create the MCP HTTP app FIRST
mcp_app = mcp.http_app()

# Application lifespan for resource initialization
@asynccontextmanager
async def app_lifespan(app: FastAPI):
    await init_resources()
    print("Starting up the app...")
    yield
    await cleanup_resources()
    print("Shutting down the app...")

# Combine both lifespans (FastAPI and MCP)
@asynccontextmanager
async def combined_lifespan(app: FastAPI):
    print("DEBUG: combined_lifespan starting")
    async with app_lifespan(app):
        print("DEBUG: app_lifespan completed, entering mcp_app.lifespan")
        async with mcp_app.lifespan(app):
            print("DEBUG: mcp_app.lifespan completed, yielding")
            yield
    print("DEBUG: combined_lifespan shutting down")

# Create FastAPI app with combined lifespan
app = FastAPI(
    title="Cloudways MCP Server",
    version="1.0.0",
    lifespan=combined_lifespan
)

# Add OAuth middleware for bearer token authentication on /mcp/* routes
# This must be added BEFORE routes are registered
# Note: Middleware will be fully initialized after resources are created
app.add_middleware(
    OAuthMiddleware,
    oauth_token_manager=None  # Will be set after startup
)

# Get OAuth provider from server.py and add its routes to root app
# OAuth endpoints (/authorize, /token, /register, etc.) must be at root level
from server import oauth_provider as server_oauth_provider
oauth_routes = server_oauth_provider.get_routes()
if oauth_routes:
    # Filter out routes that conflict with our custom implementations
    filtered_routes = [
        route for route in oauth_routes
        if not (
            hasattr(route, 'path') and (
                '/.well-known/oauth-authorization-server' in str(route.path)
                or str(route.path) == '/authorize'
                or str(route.path) == '/token'
            )
        )
    ]
    for route in filtered_routes:
        app.router.routes.append(route)
    logger.info(f"Added {len(filtered_routes)} OAuth routes from provider (filtered {len(oauth_routes) - len(filtered_routes)})")
else:
    logger.warning(f"get_routes() returned: {type(oauth_routes)}")

# Mount the MCP app (MCP protocol endpoint at /mcp/mcp)
app.mount("/mcp", mcp_app)

# Manually add /register endpoint (FastMCP doesn't create it automatically)
@app.post("/register")
async def register_client(request: Request):
    """Dynamic Client Registration (RFC 7591)"""
    body = await request.json()
    client_id = secrets.token_urlsafe(16)

    from auth.oauth_provider import CloudwaysOAuthClient
    client = CloudwaysOAuthClient(
        client_id=client_id,
        client_name=body.get("client_name", "MCP Client"),
        redirect_uris=body.get("redirect_uris", []),
        grant_types=body.get("grant_types", ["authorization_code"]),
        response_types=body.get("response_types", ["code"]),
        token_endpoint_auth_method=body.get("token_endpoint_auth_method", "none")
    )

    if resources.oauth_provider:
        await resources.oauth_provider.register_client(client)

    logger.info("Client registered", client_id=client_id)

    return {
        "client_id": client_id,
        "client_name": client.client_name,
        "redirect_uris": client.redirect_uris,
        "grant_types": client.grant_types,
        "response_types": client.response_types,
        "token_endpoint_auth_method": client.token_endpoint_auth_method
    }

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

        # Store Cloudways token encrypted
        cloudways_token = token_data["access_token"]
        expires_in = token_data.get("expires_in", 3600)

        # Encrypt and store Cloudways token
        from config import fernet
        encrypted_token = fernet.encrypt(cloudways_token.encode()).decode()
        cloudways_token_key = f"session:{session_id}:cloudways_token"
        await resources.redis_client.setex(cloudways_token_key, expires_in, encrypted_token)

        # Generate customer ID
        import hashlib
        customer_hash = hashlib.sha256(f"{email}:{session_id}".encode()).hexdigest()
        customer_id = f"customer_{customer_hash[:16]}"

        # Update session status
        import time
        token_expires_at = time.time() + expires_in
        await resources.session_manager.update_session_status(
            session_id=session_id,
            status=AuthStatus.AUTHENTICATED,
            customer_id=customer_id,
            customer_email=email,
            token_expires_at=token_expires_at
        )

        # Check if this is an OAuth authorization flow
        import json
        oauth_params_key = f"session:{session_id}:oauth_params"
        oauth_params_json = await resources.redis_client.get(oauth_params_key)

        # Generate OAuth authorization code
        auth_code = resources.oauth_token_manager.generate_authorization_code(session_id)

        # Store authorization code with session reference and OAuth metadata
        code_data = {
            "session_id": session_id,
            "customer_id": customer_id,
            "customer_email": email
        }

        # If OAuth flow, include full OAuth params so FastMCP token handler passes validation
        if oauth_params_json:
            oauth_params = json.loads(oauth_params_json)
            # PKCE metadata
            if oauth_params.get("code_challenge"):
                code_data["code_challenge"] = oauth_params["code_challenge"]
                code_data["code_challenge_method"] = oauth_params.get("code_challenge_method", "S256")
            # Required OAuth fields for token exchange
            code_data["client_id"] = oauth_params.get("client_id")
            code_data["redirect_uri"] = oauth_params.get("redirect_uri", "")
            code_data["redirect_uri_provided_explicitly"] = bool(oauth_params.get("redirect_uri"))
            # Scopes string -> list for our CloudwaysAuthorizationCode dataclass
            scope_val = oauth_params.get("scope") or "cloudways:api"
            code_data["scopes"] = scope_val.split() if isinstance(scope_val, str) else scope_val

        # Store with 10 minute TTL
        code_key = f"oauth:authcode:{auth_code}"
        await resources.redis_client.setex(code_key, 600, json.dumps(code_data))

        logger.info(
            "Authentication successful - Authorization code issued",
            session_id=session_id,
            customer_id=customer_id,
            code_prefix=auth_code[:8],
            has_oauth_params=bool(oauth_params_json)
        )

        # If OAuth flow with redirect_uri, redirect back to client
        if oauth_params_json:
            oauth_params = json.loads(oauth_params_json)
            redirect_uri = oauth_params.get("redirect_uri")
            state = oauth_params.get("state")

            if redirect_uri:
                # Build redirect URL with code and state
                from urllib.parse import urlencode
                params = {"code": auth_code}
                if state:
                    params["state"] = state

                redirect_url = f"{redirect_uri}?{urlencode(params)}"

                logger.info(
                    "Redirecting to client callback",
                    redirect_uri=redirect_uri,
                    has_state=bool(state)
                )

                from fastapi.responses import RedirectResponse
                return RedirectResponse(url=redirect_url, status_code=302)

        # Fallback: Return authorization code in JSON (for manual testing)
        return JSONResponse({
            "status": "success",
            "message": "Authentication successful",
            "session_id": session_id,
            "code": auth_code,
            "redirect_hint": "Exchange this code at POST /token with grant_type=authorization_code"
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


# ==================== OAuth 2.1 Authorization Code Flow ====================

@app.get("/authorize")
async def authorize_endpoint(
    request: Request,
    client_id: str = None,
    redirect_uri: str = None,
    response_type: str = None,
    state: str = None,
    code_challenge: str = None,
    code_challenge_method: str = None,
    scope: str = None
):
    """
    OAuth 2.1 Authorization Endpoint (RFC 6749 Section 3.1)

    Handles authorization requests from OAuth clients.
    Redirects user to authentication page, then back to client's redirect_uri.
    """
    logger.info(
        "Authorization endpoint called",
        client_id=client_id,
        redirect_uri=redirect_uri,
        response_type=response_type,
        code_challenge_method=code_challenge_method
    )

    # Validate required parameters
    if not response_type or response_type != "code":
        return JSONResponse(
            status_code=400,
            content={
                "error": "unsupported_response_type",
                "error_description": "Only 'code' response_type is supported"
            }
        )

    if not redirect_uri:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": "redirect_uri is required"
            }
        )

    # Generate session for this authorization request
    session = await resources.session_manager.create_session()
    session_id = session.session_id

    # Store OAuth parameters with session for later use
    import json
    oauth_params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method or "S256",
        "scope": scope
    }

    # Store OAuth params in Redis
    oauth_params_key = f"session:{session_id}:oauth_params"
    await resources.redis_client.setex(
        oauth_params_key,
        600,  # 10 minutes
        json.dumps(oauth_params)
    )

    # Redirect to our authentication page with session_id
    auth_url = f"{AUTH_BASE_URL}/auth?session_id={session_id}"

    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=auth_url, status_code=302)


# ==================== OAuth 2.1 Token Exchange ====================

@app.post("/token")
async def token_endpoint(
    grant_type: str = Form(...),
    code: str = Form(...),
    code_verifier: str = Form(None),
    redirect_uri: str = Form(None),
    client_id: str = Form(None)
):
    """
    OAuth 2.1 Token Endpoint (RFC 6749 + PKCE RFC 7636)

    Exchanges authorization code for access token.
    """
    logger.info("Token endpoint called", grant_type=grant_type, client_id=client_id)

    # Validate grant type
    if grant_type != "authorization_code":
        return JSONResponse(
            status_code=400,
            content={
                "error": "unsupported_grant_type",
                "error_description": "Only authorization_code grant type is supported"
            }
        )

    # Validate required parameters
    if not code:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": "Missing required parameter: code"
            }
        )

    # Retrieve authorization code data from Redis
    code_key = f"oauth:authcode:{code}"
    code_data_json = await resources.redis_client.get(code_key)

    if not code_data_json:
        logger.warning("Invalid or expired authorization code", code_prefix=code[:8])
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_grant",
                "error_description": "Authorization code is invalid or expired"
            }
        )

    # Parse code data
    import json
    code_data = json.loads(code_data_json)

    # Validate PKCE code_verifier if code_challenge was used
    if code_data.get("code_challenge"):
        if not code_verifier:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request",
                    "error_description": "code_verifier required for PKCE"
                }
            )

        # Verify code challenge
        import hashlib
        import base64

        computed_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip('=')

        if computed_challenge != code_data["code_challenge"]:
            logger.warning("PKCE verification failed")
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_grant",
                    "error_description": "Code verifier does not match code challenge"
                }
            )

    # Delete authorization code (one-time use)
    await resources.redis_client.delete(code_key)

    # Get session and customer data
    session_id = code_data["session_id"]
    session = await resources.session_manager.get_session(session_id)

    if not session or not session.is_authenticated():
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_grant",
                "error_description": "Session not authenticated"
            }
        )

    # Get Cloudways token
    cloudways_token_key = f"session:{session_id}:cloudways_token"
    encrypted_cloudways_token = await resources.redis_client.get(cloudways_token_key)

    if not encrypted_cloudways_token:
        return JSONResponse(
            status_code=500,
            content={
                "error": "server_error",
                "error_description": "Failed to retrieve Cloudways token"
            }
        )

    from config import fernet
    cloudways_token = fernet.decrypt(encrypted_cloudways_token.encode()).decode()

    # Create OAuth access token
    oauth_token = await resources.oauth_token_manager.create_access_token(
        customer_id=session.customer_id,
        customer_email=session.customer_email,
        cloudways_token=cloudways_token
    )

    # Also store token in the FastMCP provider format so bearer auth works consistently
    try:
        from auth.oauth_provider import CloudwaysAccessToken
        provider_token = CloudwaysAccessToken(
            access_token=oauth_token.access_token,
            client_id=client_id or "unknown_client",
            user_id=session.customer_id,
            scope="cloudways:api",
            customer_id=session.customer_id,
            customer_email=session.customer_email,
            cloudways_token=cloudways_token,
            expires_at=time.time() + oauth_token.expires_in
        )
        await resources.oauth_provider._store_access_token(provider_token)
    except Exception as e:
        logger.warning("Failed to mirror token into provider store", error=str(e))

    logger.info(
        "Access token issued",
        customer_id=session.customer_id,
        session_id=session_id
    )

    # Return token response (RFC 6749 Section 5.1)
    return JSONResponse({
        "access_token": oauth_token.access_token,
        "token_type": "Bearer",
        "expires_in": oauth_token.expires_in,
        "scope": "cloudways:api"
    })


# ==================== OAuth 2.0 Discovery Endpoints ====================

@app.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server(request: Request):
    """OAuth 2.0 Authorization Server Metadata (RFC 8414)"""
    # Use AUTH_BASE_URL from config instead of request.base_url
    # This ensures we return the correct public URL (e.g., ngrok) rather than localhost
    base_url = AUTH_BASE_URL.rstrip('/')

    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/token",
        "registration_endpoint": f"{base_url}/register",  # REQUIRED for Claude Desktop!
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"]
    }


@app.get("/.well-known/oauth-protected-resource")
@app.get("/.well-known/oauth-protected-resource/{path:path}")
async def oauth_protected_resource(request: Request, path: str = None):
    """
    OAuth 2.0 Protected Resource Metadata

    Supports both:
    - /.well-known/oauth-protected-resource (base)
    - /.well-known/oauth-protected-resource/mcp/mcp (path-specific)
    """
    # Use AUTH_BASE_URL from config instead of request.base_url
    # This ensures we return the correct public URL (e.g., ngrok) rather than localhost
    base_url = AUTH_BASE_URL.rstrip('/')

    # Return metadata for the specific resource or base
    resource_url = f"{base_url}/{path}" if path else base_url

    return {
        "resource": resource_url,
        "authorization_servers": [base_url],
        "scopes_supported": ["cloudways:api"],
        "bearer_methods_supported": ["header"]
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

    # Resources will be initialized lazily on first request
    # (Can't initialize async resources here due to event loop issues)

    # For MCP: use single worker to maintain session state
    # Scale horizontally with multiple instances behind a load balancer instead
    # Simple uvicorn config for lifespan compatibility
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=7000,
        log_level="info"
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
