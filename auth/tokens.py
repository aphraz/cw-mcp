#!/usr/bin/env python3
"""
Token management for Cloudways MCP Server with session-based authentication.

This module handles token retrieval and validation for OAuth browser authentication.
Tokens are stored by session ID (not customer ID) and are NOT auto-refreshed.
When tokens expire, users must re-authenticate in browser.
"""

import asyncio
import json
import time
from typing import Dict, Any, Optional
import httpx
import redis.asyncio as redis
import structlog

from config import TOKEN_URL
from auth.customer import Customer
from auth.exceptions import TokenExpiredError, SessionNotFoundError

logger = structlog.get_logger(__name__)

class TokenManager:
    """
    Session-based token manager for OAuth browser authentication.

    Key differences from credential-based approach:
    - Tokens stored by session_id (not customer_id)
    - NO auto-refresh (no credentials stored)
    - Token expiry triggers re-authentication in browser
    - Retrieves tokens from session storage (set by /auth/submit endpoint)
    """

    def __init__(self, redis_client: redis.Redis, http_client: httpx.AsyncClient):
        self.redis_client = redis_client
        self.http_client = http_client
        
    async def get_token_from_session(self, session_id: str) -> str:
        """
        Get access token from session storage.

        Args:
            session_id: Session identifier

        Returns:
            Decrypted access token

        Raises:
            SessionNotFoundError: Session or token not found
            TokenExpiredError: Token has expired
        """
        token_key = f"session:{session_id}:token"
        meta_key = f"session:{session_id}:token_meta"

        try:
            # Retrieve encrypted token
            encrypted_token = await self.redis_client.get(token_key)
            token_meta = await self.redis_client.get(meta_key)

            if not encrypted_token:
                logger.warning("Token not found for session", session_id=session_id)
                raise SessionNotFoundError(session_id)

            # Decrypt token
            from config import fernet
            try:
                decrypted_token = fernet.decrypt(encrypted_token.encode()).decode()
            except Exception as e:
                logger.error(
                    "Failed to decrypt token",
                    session_id=session_id,
                    error=str(e)
                )
                raise SessionNotFoundError(session_id)

            # Check token expiry
            if token_meta:
                try:
                    meta = json.loads(token_meta)
                    expires_at = meta.get("expires_at", 0)
                    current_time = time.time()

                    if current_time >= expires_at:
                        logger.info(
                            "Token expired",
                            session_id=session_id,
                            expired_at=expires_at
                        )
                        raise TokenExpiredError(session_id, expired_at)

                    logger.debug(
                        "Token valid",
                        session_id=session_id,
                        time_until_expiry=round(expires_at - current_time, 2)
                    )
                except (json.JSONDecodeError, KeyError) as e:
                    logger.warning(
                        "Invalid token metadata, assuming valid",
                        session_id=session_id,
                        error=str(e)
                    )

            return decrypted_token

        except (SessionNotFoundError, TokenExpiredError):
            raise
        except Exception as e:
            logger.error(
                "Unexpected error retrieving token",
                session_id=session_id,
                error=str(e)
            )
            raise SessionNotFoundError(session_id)

    async def get_token(self, customer: Customer) -> str:
        """
        LEGACY: Get token using Customer object (for backward compatibility).

        This method is deprecated and maintained only for compatibility
        with existing code during migration. New code should use
        get_token_from_session() directly.

        Args:
            customer: Customer object (contains session info)

        Returns:
            Decrypted access token

        Raises:
            ValueError: If customer doesn't have session_id
            SessionNotFoundError: Session or token not found
            TokenExpiredError: Token has expired
        """
        # Extract session_id from customer
        # Assuming customer will have a session_id attribute after Phase 4 migration
        if not hasattr(customer, 'session_id') or not customer.session_id:
            raise ValueError("Customer object missing session_id for OAuth authentication")

        return await self.get_token_from_session(customer.session_id)

async def get_cloudways_token(
    customer: Customer,
    token_manager: Optional[TokenManager] = None,
    redis_client: Optional[redis.Redis] = None,
    http_client: Optional[httpx.AsyncClient] = None
) -> str:
    """
    DEPRECATED: Get Cloudways API token for customer.

    This function is maintained for backward compatibility during migration
    to session-based OAuth authentication. It will be removed in a future version.

    For OAuth authentication, tokens are stored by session_id and retrieved
    via TokenManager.get_token_from_session().

    Args:
        customer: Customer object (must have session_id for OAuth)
        token_manager: TokenManager instance
        redis_client: Redis client (deprecated)
        http_client: HTTP client (deprecated)

    Returns:
        Access token string

    Raises:
        ValueError: If customer lacks session_id for OAuth
        SessionNotFoundError: If session/token not found
        TokenExpiredError: If token has expired
    """
    logger.warning(
        "DEPRECATED: get_cloudways_token() called - migrate to session-based auth",
        customer_id=customer.customer_id if hasattr(customer, 'customer_id') else 'unknown'
    )

    if token_manager:
        # Use session-based authentication
        return await token_manager.get_token(customer)

    # Fallback: Direct session token retrieval
    if hasattr(customer, 'session_id') and customer.session_id:
        if not redis_client:
            raise ValueError("Redis client required for token retrieval")

        token_key = f"session:{customer.session_id}:token"
        cached_token = await redis_client.get(token_key)

        if cached_token:
            try:
                from config import fernet
                decrypted_token = fernet.decrypt(cached_token.encode()).decode()
                logger.debug(
                    "Retrieved token from session",
                    session_id=customer.session_id
                )
                return decrypted_token
            except Exception as e:
                logger.error(
                    "Failed to decrypt session token",
                    session_id=customer.session_id,
                    error=str(e)
                )
                raise SessionNotFoundError(customer.session_id)

    raise ValueError(
        "Customer object missing session_id - OAuth authentication required"
    )