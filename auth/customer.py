#!/usr/bin/env python3
"""
Customer management for Cloudways MCP Server with OAuth browser authentication.
"""

import json
import hashlib
from datetime import datetime, timezone
from typing import Optional
import redis.asyncio as redis
from fastmcp import Context
from fastmcp.server.dependencies import get_http_request
import structlog

from config import fernet, AUTH_BASE_URL
from auth.exceptions import TokenExpiredError, SessionNotFoundError
from auth.session import SessionManager, AuthStatus
from auth.browser_flow import BrowserAuthenticator, initiate_browser_auth, initiate_re_authentication
from auth.oauth_error import (
    OAuthErrorResponse,
    create_authorization_required_error,
    create_token_expired_error,
    create_authentication_pending_error
)

logger = structlog.get_logger(__name__)

# Module-level global for oauth_provider (set during initialization)
_global_oauth_provider = None

class Customer:
    def __init__(self, customer_id: str, email: str, cloudways_email: str,
                 created_at: datetime,
                 auth_method: str,
                 session_id: Optional[str] = None,
                 cloudways_api_key: Optional[str] = None,
                 cloudways_oauth_token: Optional[str] = None):
        self.customer_id = customer_id
        self.email = email
        self.cloudways_email = cloudways_email
        self.auth_method = auth_method  # "headers", "bearer", or "oauth"
        self.session_id = session_id  # For OAuth session-based authentication
        self.cloudways_api_key = cloudways_api_key  # Permanent API key (header-based only)
        self.cloudways_oauth_token = cloudways_oauth_token  # OAuth access token (bearer/session)
        self.created_at = created_at
        self.last_seen = datetime.now(timezone.utc)

async def get_customer_from_headers(ctx: Context, redis_client: Optional[redis.Redis] = None) -> Optional[Customer]:
    """Extract customer information from request headers"""
    try:
        http_request = get_http_request()
        email = http_request.headers.get("x-cloudways-email")
        api_key = http_request.headers.get("x-cloudways-api-key")

        if not email or not api_key:
            # Log authentication failure
            try:
                from ..utils.logging import log_authentication_event
                log_authentication_event("auth_failed", "unknown", False, {
                    "reason": "missing_credentials",
                    "email_provided": bool(email),
                    "api_key_provided": bool(api_key)
                })
            except:
                pass
            raise ValueError("Missing authentication headers")
        
        # Get session identifier from MCP context or headers
        session_id = getattr(ctx, 'session_id', None) or http_request.headers.get('x-mcp-session-id')
        
        if not session_id:
            # Generate unique session ID for this connection
            import secrets
            session_id = secrets.token_urlsafe(32)
        
        # Include session in customer ID to ensure session isolation
        customer_hash = hashlib.sha256(f"{email}:{api_key}:{session_id}".encode()).hexdigest()
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
                        created_at=datetime.fromisoformat(data["created_at"]),
                        auth_method="headers",
                        cloudways_api_key=decrypted_key
                    )
                    logger.debug("Customer loaded from cache", customer_id=customer_id, customer_email=customer.email)
                    return customer
            except Exception as e:
                logger.warning("Failed to load customer from cache", error=str(e))
        
        # Create new customer
        customer = Customer(
            customer_id=customer_id,
            email=email,
            cloudways_email=email,
            created_at=datetime.now(timezone.utc),
            auth_method="headers",
            cloudways_api_key=api_key
        )
        await _cache_customer(customer, redis_client)
        logger.info("New customer created", customer_id=customer_id, customer_email=customer.email)
        
        # Log security event
        try:
            from ..utils.logging import log_authentication_event
            log_authentication_event("new_customer", customer_id, True, {
                "email": email,
                "ip_address": getattr(http_request.client, 'host', 'unknown') if http_request.client else 'unknown'
            })
        except:
            pass  # Don't fail customer creation if logging fails
        
        return customer
        
    except Exception as e:
        logger.error("Failed to get customer from headers", error=str(e))
        return None

async def get_customer_from_session(
    ctx: Context,
    session_manager: SessionManager,
    browser_authenticator: BrowserAuthenticator,
    redis_client: Optional[redis.Redis] = None
) -> Optional[Customer]:
    """
    Get customer from OAuth session-based authentication.

    Flow:
    1. Extract/generate session_id from MCP context
    2. Check if session exists and is authenticated
    3. If not authenticated: trigger browser auth flow
    4. If token expired: trigger re-authentication
    5. If authenticated: create Customer from session data

    Args:
        ctx: MCP Context
        session_manager: SessionManager instance
        browser_authenticator: BrowserAuthenticator instance
        redis_client: Redis client (optional)

    Returns:
        Customer object with session_id

    Raises:
        SessionNotFoundError: If session creation/retrieval fails
        TokenExpiredError: If token expired and re-auth failed
    """
    try:
        # Extract session_id from cookie, context, or headers (in priority order)
        try:
            http_request = get_http_request()
        except Exception as e:
            logger.warning(f"get_http_request() failed: {e}")
            http_request = None


        # Short-circuit: if a valid Bearer token is present, trust it and avoid browser re-auth
        auth_header = http_request.headers.get("Authorization") if http_request else None
        if auth_header and auth_header.lower().startswith("bearer "):
            bearer_token = auth_header.split()[1]

            # Try global provider first, then fall back to resources
            global _global_oauth_provider
            provider = _global_oauth_provider
            if not provider:
                try:
                    from main import resources
                    provider = getattr(resources, "oauth_provider", None)
                except Exception as e:
                    logger.error(f"Failed to get OAuth provider: {e}")
                    provider = None

            if provider:
                token_obj = await provider.load_access_token(bearer_token)
                if token_obj:
                    # Construct customer from bearer token claims
                    customer_id = token_obj.customer_id or token_obj.user_id or "unknown"
                    customer_email = token_obj.customer_email or "unknown"

                    # Get Cloudways API token from bearer token
                    cloudways_token = getattr(token_obj, 'cloudways_token', None)
                    if not cloudways_token:
                        logger.warning("Bearer token missing cloudways_token", customer_id=customer_id)
                        cloudways_token = "<token-missing>"

                    customer = Customer(
                        customer_id=customer_id,
                        email=customer_email,
                        cloudways_email=customer_email,
                        created_at=datetime.now(timezone.utc),
                        auth_method="bearer",
                        session_id=None,
                        cloudways_oauth_token=cloudways_token
                    )
                    logger.debug("Authenticated via bearer token", customer_id=customer_id)
                    return customer

        # Priority 1: HTTP cookie (persists across MCP-over-HTTP requests)
        session_id = http_request.cookies.get('cloudways_mcp_session')

        # Priority 2: MCP context or headers (for first-time connections)
        if not session_id:
            session_id = (
                getattr(ctx, 'session_id', None) or
                http_request.headers.get('x-mcp-session-id') or
                http_request.headers.get('x-session-id')
            )

        if not session_id:
            # No session_id from MCP - generate a new one
            logger.info("No session_id found, creating new session")
            session = await session_manager.create_session()  # Will generate new session_id
            session_id = session.session_id

            # Try to open browser (will only work for local connections)
            auth_url = f"{AUTH_BASE_URL}/auth?session_id={session_id}"
            browser_authenticator.open_browser(auth_url)

            # Raise OAuth error that triggers browser authentication
            logger.info("Authentication required", session_id=session_id, auth_url=auth_url)
            oauth_error = create_authorization_required_error(session_id, AUTH_BASE_URL)
            raise OAuthErrorResponse(oauth_error)

        # Get session from storage
        session = await session_manager.get_session(session_id)

        if not session:
            # Session doesn't exist - create new session using MCP's session_id
            logger.warning("Session not found, creating new session", session_id=session_id)
            session = await session_manager.create_session(session_id=session_id)  # Use MCP session_id!

            # Try to open browser
            auth_url = f"{AUTH_BASE_URL}/auth?session_id={session_id}"
            browser_authenticator.open_browser(auth_url)

            # Raise OAuth error
            oauth_error = create_authorization_required_error(session_id, AUTH_BASE_URL)
            raise OAuthErrorResponse(oauth_error)

        # Check session status
        if session.auth_status == AuthStatus.PENDING:
            # Authentication still pending
            logger.info("Authentication pending", session_id=session_id)

            # Try to open browser again (in case it didn't open before)
            auth_url = f"{AUTH_BASE_URL}/auth?session_id={session_id}"
            browser_authenticator.open_browser(auth_url)

            # Raise OAuth error
            oauth_error = create_authentication_pending_error(session_id, AUTH_BASE_URL)
            raise OAuthErrorResponse(oauth_error)

        elif session.auth_status == AuthStatus.EXPIRED or session.is_expired():
            # Token expired - user must re-authenticate
            logger.info("Session/token expired", session_id=session_id)

            # Try to open browser for re-authentication
            auth_url = f"{AUTH_BASE_URL}/auth?session_id={session_id}&reason=expired"
            browser_authenticator.open_browser(auth_url)

            # Raise OAuth error for token expiration
            oauth_error = create_token_expired_error(session_id, AUTH_BASE_URL)
            raise OAuthErrorResponse(oauth_error)

        elif session.auth_status == AuthStatus.AUTHENTICATED:
            # Session is authenticated and valid
            logger.debug(
                "Session authenticated",
                session_id=session_id,
                customer_id=session.customer_id
            )

        else:
            logger.error("Unknown session status", session_id=session_id, status=session.auth_status)
            raise SessionNotFoundError(session_id)

        # Create Customer object from session
        customer = Customer(
            customer_id=session.customer_id,
            email=session.customer_email,
            cloudways_email=session.customer_email,
            created_at=session.created_at,
            auth_method="oauth",
            session_id=session_id
        )

        logger.debug(
            "Customer created from session",
            customer_id=customer.customer_id,
            session_id=session_id
        )

        return customer

    except (SessionNotFoundError, TokenExpiredError, OAuthErrorResponse):
        raise
    except Exception as e:
        logger.error("Failed to get customer from session", error=str(e), exc_info=True)
        return None


async def _cache_customer(customer: Customer, redis_client: Optional[redis.Redis] = None):
    """Cache customer data in Redis"""
    if not redis_client:
        return

    try:
        # Only cache API key for header-based auth
        if customer.cloudways_api_key:
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


async def get_customer(
    ctx: Context,
    session_manager: Optional[SessionManager] = None,
    browser_authenticator: Optional[BrowserAuthenticator] = None,
    redis_client: Optional[redis.Redis] = None
) -> Optional[Customer]:
    """
    Unified customer getter that routes based on authentication method.

    Checks request.state.auth_method set by middleware and calls:
    - "headers": get_customer_from_headers()
    - "bearer" or "oauth": get_customer_from_session()

    Args:
        ctx: MCP context
        session_manager: Session manager (for OAuth)
        browser_authenticator: Browser authenticator (for OAuth)
        redis_client: Redis client

    Returns:
        Customer object or None
    """
    try:
        http_request = get_http_request()
        auth_method = getattr(http_request.state, 'auth_method', None)

        if auth_method == "headers":
            # Header-based authentication
            logger.info("Using header-based auth customer getter")
            return await get_customer_from_headers(ctx, redis_client)
        else:
            # OAuth or bearer token authentication (both use session-based)
            logger.info("Using session-based auth customer getter", auth_method=auth_method)
            return await get_customer_from_session(ctx, session_manager, browser_authenticator, redis_client)

    except Exception as e:
        logger.error("Failed to get customer", error=str(e))
        return None
