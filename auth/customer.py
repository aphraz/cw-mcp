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

logger = structlog.get_logger(__name__)

class Customer:
    def __init__(self, customer_id: str, email: str, cloudways_email: str,
                 cloudways_api_key: str, created_at: datetime, session_id: Optional[str] = None):
        self.customer_id = customer_id
        self.email = email
        self.cloudways_email = cloudways_email
        self.cloudways_api_key = cloudways_api_key
        self.session_id = session_id  # For OAuth session-based authentication
        self.created_at = datetime.now(timezone.utc)
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
                        cloudways_api_key=decrypted_key,
                        created_at=datetime.fromisoformat(data["created_at"])
                    )
                    logger.debug("Customer loaded from cache", customer_id=customer_id, customer_email=customer.email)
                    return customer
            except Exception as e:
                logger.warning("Failed to load customer from cache", error=str(e))
        
        # Create new customer
        customer = Customer(customer_id, email, email, api_key, datetime.now(timezone.utc))
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
        # Extract session_id from context or generate new one
        http_request = get_http_request()
        session_id = (
            getattr(ctx, 'session_id', None) or
            http_request.headers.get('x-mcp-session-id') or
            http_request.headers.get('x-session-id')
        )

        if not session_id:
            # Create new session for first-time authentication
            logger.info("No session_id found, creating new session")
            session = await session_manager.create_session()
            session_id = session.session_id

            # Store session_id in context for subsequent requests
            ctx.session_id = session_id

            # Trigger browser authentication
            logger.info("Initiating browser authentication", session_id=session_id)

            auth_result = await initiate_browser_auth(
                session_id=session_id,
                auth_base_url=AUTH_BASE_URL,
                session_manager=session_manager,
                browser_authenticator=browser_authenticator,
                timeout=300
            )

            if not auth_result.success:
                logger.error(
                    "Browser authentication failed",
                    session_id=session_id,
                    message=auth_result.message
                )
                raise SessionNotFoundError(session_id)

        # Get session from storage
        session = await session_manager.get_session(session_id)

        if not session:
            logger.warning("Session not found", session_id=session_id)
            raise SessionNotFoundError(session_id)

        # Check session status
        if session.auth_status == AuthStatus.PENDING:
            # Authentication still pending
            logger.info("Authentication pending", session_id=session_id)
            raise SessionNotFoundError(session_id)

        elif session.auth_status == AuthStatus.EXPIRED or session.is_expired():
            # Token expired - trigger re-authentication
            logger.info("Session/token expired, initiating re-authentication", session_id=session_id)

            auth_result = await initiate_re_authentication(
                session_id=session_id,
                auth_base_url=AUTH_BASE_URL,
                session_manager=session_manager,
                browser_authenticator=browser_authenticator,
                reason="expired"
            )

            if not auth_result.success:
                logger.error(
                    "Re-authentication failed",
                    session_id=session_id,
                    message=auth_result.message
                )
                raise TokenExpiredError(session_id, session.token_expires_at)

            # Reload session after re-authentication
            session = await session_manager.get_session(session_id)
            if not session or not session.is_authenticated():
                raise SessionNotFoundError(session_id)

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
            cloudways_api_key="<token-based>",  # Not stored in OAuth flow
            created_at=session.created_at,
            session_id=session_id
        )

        logger.debug(
            "Customer created from session",
            customer_id=customer.customer_id,
            session_id=session_id
        )

        return customer

    except (SessionNotFoundError, TokenExpiredError):
        raise
    except Exception as e:
        logger.error("Failed to get customer from session", error=str(e), exc_info=True)
        return None


async def _cache_customer(customer: Customer, redis_client: Optional[redis.Redis] = None):
    """Cache customer data in Redis"""
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