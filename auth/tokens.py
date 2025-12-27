#!/usr/bin/env python3
"""
Token management for Cloudways MCP Server with dual authentication modes.

This module handles token retrieval and validation for both:
1. OAuth browser authentication (session-based, no auto-refresh)
2. Header-based authentication (credential-based, WITH auto-refresh)

OAuth mode:
- Tokens stored by session_id
- No auto-refresh (no credentials stored)
- Token expiry triggers re-authentication in browser

Header-based mode:
- Exchanges email+api_key for Cloudways OAuth tokens
- Tokens cached by customer_id with auto-renewal
- Proactive refresh when tokens near expiry (5 min)
- Background refresh to avoid blocking requests (1-5 min remaining)
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
    Dual-mode token manager for both OAuth and header-based authentication.

    OAuth mode (session-based):
    - Tokens stored by session_id (not customer_id)
    - NO auto-refresh (no credentials stored)
    - Token expiry triggers re-authentication in browser
    - Retrieves tokens from session storage (set by /auth/submit endpoint)

    Header-based mode (credential-based):
    - Tokens stored by customer_id with auto-refresh
    - Exchanges email+api_key for Cloudways OAuth tokens
    - Proactive renewal when tokens near expiry
    - Background refresh to avoid blocking requests
    """

    def __init__(self, redis_client: redis.Redis, http_client: httpx.AsyncClient):
        self.redis_client = redis_client
        self.http_client = http_client
        # Auto-renewal settings for header-based auth
        self.refresh_threshold = 300  # Refresh when 5 minutes remaining
        self.min_refresh_threshold = 60  # Minimum 1 minute before expiry
        
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
        Get token using Customer object - supports all authentication modes.

        Routes to appropriate handler based on customer.auth_method:
        - "headers": Exchange permanent API key for OAuth token with auto-renewal
        - "bearer": Return OAuth token directly from customer object
        - "oauth": Retrieve token from session storage (no auto-renewal)

        Args:
            customer: Customer object with auth_method set

        Returns:
            Cloudways OAuth access token

        Raises:
            ValueError: If customer lacks required attributes
            SessionNotFoundError: Session or token not found
            TokenExpiredError: Token has expired
            RuntimeError: If token exchange/renewal fails
        """
        auth_method = getattr(customer, 'auth_method', None)

        if auth_method == "headers":
            # Header-based: exchange permanent API key for OAuth token with auto-renewal
            if not customer.cloudways_api_key:
                raise ValueError("Header-based auth requires cloudways_api_key")
            return await self._get_token_with_renewal(customer)

        elif auth_method == "bearer":
            # Bearer token: OAuth token already in customer object
            if customer.cloudways_oauth_token and customer.cloudways_oauth_token not in ["<token-missing>"]:
                logger.debug("Using OAuth token from bearer token auth",
                           customer_id=customer.customer_id)
                return customer.cloudways_oauth_token
            raise ValueError("Bearer token auth missing cloudways_oauth_token")

        elif auth_method == "oauth":
            # OAuth session: retrieve token from session storage (no auto-renewal)
            if not customer.session_id:
                raise ValueError("OAuth session auth requires session_id")
            return await self.get_token_from_session(customer.session_id)

        else:
            raise ValueError(f"Unknown auth_method: {auth_method}")

    async def _get_token_with_renewal(self, customer: Customer) -> str:
        """
        Get token with proactive renewal for header-based auth.

        This implements the auto-renewal logic:
        - Checks cache for valid token
        - Returns cached token if > 5 min remaining
        - Triggers background refresh if 1-5 min remaining
        - Refreshes immediately if < 1 min remaining
        """
        token_key = f"token:{customer.customer_id}"
        meta_key = f"token_meta:{customer.customer_id}"
        lock_key = f"token_lock:{customer.customer_id}"

        try:
            # Check if we have a valid cached token
            cached_token = await self.redis_client.get(token_key)
            token_meta = await self.redis_client.get(meta_key)

            if cached_token and token_meta:
                # Decrypt token
                from config import fernet
                try:
                    decrypted_token = fernet.decrypt(cached_token.encode()).decode()
                except Exception as e:
                    logger.warning("Failed to decrypt cached token, forcing refresh",
                                 customer_id=customer.customer_id,
                                 customer_email=customer.email,
                                 error=str(e))
                    decrypted_token = None

                if decrypted_token:
                    meta = json.loads(token_meta)
                    expires_at = meta.get("expires_at", 0)
                    current_time = time.time()
                    time_until_expiry = expires_at - current_time

                    if time_until_expiry > self.refresh_threshold:
                        logger.debug("Using fresh cached token",
                                   customer_id=customer.customer_id,
                                   customer_email=customer.email)
                        return decrypted_token

                    elif time_until_expiry > self.min_refresh_threshold:
                        # Background refresh with error handling
                        task = asyncio.create_task(self._refresh_token_background(customer))
                        task.add_done_callback(lambda t: self._handle_refresh_error(t, customer))
                        logger.debug("Using cached token with background refresh",
                                   customer_id=customer.customer_id,
                                   customer_email=customer.email)
                        return decrypted_token

                logger.info("Token near expiry, refreshing immediately",
                          customer_id=customer.customer_id,
                          customer_email=customer.email)

            # Need immediate refresh with lock protection
            lock_acquired = await self._acquire_refresh_lock(lock_key)

            if not lock_acquired:
                await asyncio.sleep(0.1)
                refreshed_token = await self.redis_client.get(token_key)
                if refreshed_token:
                    # Decrypt token
                    try:
                        from config import fernet
                        decrypted_token = fernet.decrypt(refreshed_token.encode()).decode()
                        logger.debug("Using token refreshed by another process",
                                   customer_id=customer.customer_id,
                                   customer_email=customer.email)
                        return decrypted_token
                    except Exception as e:
                        logger.warning("Failed to decrypt token refreshed by another process",
                                     customer_id=customer.customer_id,
                                     customer_email=customer.email,
                                     error=str(e))

            try:
                token_data = await self._fetch_new_token(customer)
                await self._cache_token_with_metadata(customer, token_data)
                logger.info("Successfully refreshed token",
                          customer_id=customer.customer_id,
                          customer_email=customer.email)
                return token_data["access_token"]
            finally:
                await self._release_refresh_lock(lock_key)

        except Exception as e:
            logger.error("Token management failed",
                       customer_id=customer.customer_id,
                       customer_email=customer.email,
                       error=str(e))
            raise RuntimeError(f"Authentication failed: {str(e)}")

    async def _fetch_new_token(self, customer: Customer) -> Dict[str, Any]:
        """Exchange email + API key for Cloudways OAuth token."""
        resp = await self.http_client.post(TOKEN_URL, data={
            "email": customer.cloudways_email,
            "api_key": customer.cloudways_api_key
        }, timeout=30.0)

        resp.raise_for_status()
        data = resp.json()

        if not data.get("access_token"):
            raise ValueError("No access_token returned from Cloudways API")

        return data

    async def _cache_token_with_metadata(self, customer: Customer, token_data: Dict[str, Any]):
        """Cache token with expiry metadata."""
        token = token_data.get("access_token")
        expires_in = token_data.get("expires_in", 3600)
        current_time = time.time()

        # Import fernet for token encryption
        from config import fernet

        # Encrypt token before storing
        encrypted_token = fernet.encrypt(token.encode()).decode()

        # Store encrypted token
        token_ttl = max(expires_in - self.min_refresh_threshold, 300)
        await self.redis_client.setex(f"token:{customer.customer_id}", token_ttl, encrypted_token)

        # Store metadata
        metadata = {
            "expires_at": current_time + expires_in,
            "expires_in": expires_in,
            "created_at": current_time,
            "refresh_threshold": self.refresh_threshold
        }
        await self.redis_client.setex(
            f"token_meta:{customer.customer_id}",
            expires_in,
            json.dumps(metadata)
        )

    async def _acquire_refresh_lock(self, lock_key: str) -> bool:
        """Acquire lock for token refresh to prevent concurrent refreshes."""
        try:
            result = await self.redis_client.set(lock_key, "locked", ex=30, nx=True)
            return result is True
        except Exception:
            return False

    async def _release_refresh_lock(self, lock_key: str):
        """Release token refresh lock."""
        try:
            await self.redis_client.delete(lock_key)
        except Exception:
            pass

    async def _refresh_token_background(self, customer: Customer):
        """Background task to refresh token without blocking."""
        try:
            lock_key = f"token_lock:{customer.customer_id}"
            if await self._acquire_refresh_lock(lock_key):
                try:
                    token_data = await self._fetch_new_token(customer)
                    await self._cache_token_with_metadata(customer, token_data)
                    logger.info("Background token refresh successful",
                              customer_id=customer.customer_id,
                              customer_email=customer.email)
                finally:
                    await self._release_refresh_lock(lock_key)
        except Exception as e:
            logger.error("Background token refresh failed",
                       customer_id=customer.customer_id,
                       customer_email=customer.email,
                       error=str(e))

    def _handle_refresh_error(self, task: asyncio.Task, customer: Customer):
        """Handle errors from background refresh task."""
        try:
            task.result()
        except Exception as e:
            logger.error("Background refresh task failed",
                       customer_id=customer.customer_id,
                       customer_email=customer.email,
                       error=str(e))

async def get_cloudways_token(
    customer: Customer,
    token_manager: Optional[TokenManager] = None,
    redis_client: Optional[redis.Redis] = None,
    http_client: Optional[httpx.AsyncClient] = None
) -> str:
    """
    Get Cloudways OAuth access token for customer.

    Supports all authentication modes via customer.auth_method:
    - "headers": Exchanges permanent API key for OAuth token with auto-renewal
    - "bearer": Returns OAuth token from customer object
    - "oauth": Retrieves token from session storage

    Args:
        customer: Customer object with auth_method set
        token_manager: TokenManager instance
        redis_client: Redis client (deprecated - use token_manager)
        http_client: HTTP client (deprecated - use token_manager)

    Returns:
        Cloudways OAuth access token string

    Raises:
        ValueError: If customer lacks required attributes or token_manager is missing
        SessionNotFoundError: If session/token not found
        TokenExpiredError: If token has expired
        RuntimeError: If token exchange/renewal fails
    """
    if token_manager:
        # TokenManager routes to appropriate handler based on customer.auth_method
        return await token_manager.get_token(customer)

    # Fallback: Direct session token retrieval (OAuth mode only) - deprecated
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
                    "Retrieved token from session (fallback)",
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

    raise ValueError("TokenManager required for token retrieval")