#!/usr/bin/env python3
"""
OAuth 2.1 Token Management for MCP

Implements proper OAuth 2.1 token generation, validation, and storage
following the MCP specification.
"""

import secrets
import hashlib
import time
import json
from typing import Optional, Dict, Any, Tuple
import redis.asyncio as redis
import structlog
from dataclasses import dataclass

from config import fernet

logger = structlog.get_logger(__name__)


@dataclass
class AccessToken:
    """Represents an OAuth 2.1 access token"""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600  # 1 hour
    scope: Optional[str] = None
    customer_id: Optional[str] = None
    customer_email: Optional[str] = None
    created_at: float = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = time.time()

    def is_expired(self) -> bool:
        """Check if token has expired"""
        return time.time() >= (self.created_at + self.expires_in)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to OAuth 2.1 token response format"""
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
        }


class OAuthTokenManager:
    """
    Manages OAuth 2.1 access tokens for MCP authentication.

    Follows the MCP specification for OAuth 2.1 implementation:
    - Token generation and validation
    - Authorization code exchange
    - Bearer token verification
    """

    def __init__(self, redis_client: redis.Redis):
        self.redis_client = redis_client

    def generate_authorization_code(self, session_id: str) -> str:
        """
        Generate a secure authorization code for OAuth flow.

        Args:
            session_id: Session identifier

        Returns:
            Authorization code (base64url encoded)
        """
        # Generate cryptographically secure random code
        code = secrets.token_urlsafe(32)

        logger.debug("Authorization code generated", session_id=session_id)
        return code

    def generate_access_token(self) -> str:
        """
        Generate a cryptographically secure access token.

        Returns:
            Access token (base64url encoded, 43 characters)
        """
        # OAuth 2.1 recommends at least 128 bits of entropy
        return secrets.token_urlsafe(32)

    async def store_authorization_code(
        self,
        code: str,
        session_id: str,
        ttl: int = 600  # 10 minutes
    ) -> None:
        """
        Store authorization code with session mapping.

        Args:
            code: Authorization code
            session_id: Associated session ID
            ttl: Time-to-live in seconds (default 10 minutes)
        """
        key = f"oauth:authcode:{code}"
        await self.redis_client.setex(key, ttl, session_id)

        logger.info(
            "Authorization code stored",
            code_prefix=code[:8],
            session_id=session_id,
            ttl=ttl
        )

    async def exchange_authorization_code(
        self,
        code: str,
        customer_id: str,
        customer_email: str
    ) -> Optional[AccessToken]:
        """
        Exchange authorization code for access token.

        Args:
            code: Authorization code from /auth callback
            customer_id: Customer identifier
            customer_email: Customer email

        Returns:
            AccessToken if code is valid, None otherwise
        """
        # Verify code exists
        key = f"oauth:authcode:{code}"
        session_id = await self.redis_client.get(key)

        if not session_id:
            logger.warning("Invalid or expired authorization code", code_prefix=code[:8])
            return None

        # Delete code (one-time use only)
        await self.redis_client.delete(key)

        # Generate access token
        access_token = self.generate_access_token()

        token = AccessToken(
            access_token=access_token,
            customer_id=customer_id,
            customer_email=customer_email,
            expires_in=3600  # 1 hour
        )

        # Store token metadata
        await self._store_token(token)

        logger.info(
            "Authorization code exchanged for access token",
            customer_id=customer_id,
            session_id=session_id
        )

        return token

    async def create_access_token(
        self,
        customer_id: str,
        customer_email: str,
        cloudways_token: str
    ) -> AccessToken:
        """
        Create a new access token directly (for browser auth flow).

        Args:
            customer_id: Customer identifier
            customer_email: Customer email
            cloudways_token: Cloudways API access token

        Returns:
            New AccessToken
        """
        access_token = self.generate_access_token()

        token = AccessToken(
            access_token=access_token,
            customer_id=customer_id,
            customer_email=customer_email,
            expires_in=3600
        )

        # Store token metadata and Cloudways token
        await self._store_token(token, cloudways_token)

        logger.info("Access token created", customer_id=customer_id)

        return token

    async def _store_token(self, token: AccessToken, cloudways_token: str = None) -> None:
        """Store access token metadata in Redis"""
        token_key = f"oauth:token:{token.access_token}"

        token_data = {
            "customer_id": token.customer_id,
            "customer_email": token.customer_email,
            "created_at": token.created_at,
            "expires_in": token.expires_in
        }

        # Optionally store encrypted Cloudways token
        if cloudways_token:
            encrypted = fernet.encrypt(cloudways_token.encode()).decode()
            token_data["cloudways_token"] = encrypted

        await self.redis_client.setex(
            token_key,
            token.expires_in,
            json.dumps(token_data)
        )

    async def validate_bearer_token(self, bearer_token: str) -> Optional[Dict[str, Any]]:
        """
        Validate Bearer token from Authorization header.

        Args:
            bearer_token: Access token from Authorization: Bearer <token>

        Returns:
            Token data dict if valid, None if invalid/expired
        """
        token_key = f"oauth:token:{bearer_token}"
        token_json = await self.redis_client.get(token_key)

        if not token_json:
            logger.warning("Invalid or expired bearer token", token_prefix=bearer_token[:8])
            return None

        token_data = json.loads(token_json)

        # Check expiration - handle both schemas
        if "expires_at" in token_data:
            # CloudwaysOAuthProvider schema (absolute timestamp)
            expires_at = token_data["expires_at"]
            if time.time() >= expires_at:
                logger.warning("Expired bearer token (expires_at)", customer_id=token_data.get("customer_id"))
                await self.redis_client.delete(token_key)
                return None
        else:
            # OAuthTokenManager schema (relative expiry)
            created_at = token_data.get("created_at", time.time())
            expires_in = token_data.get("expires_in", 3600)
            if time.time() >= (created_at + expires_in):
                logger.warning("Expired bearer token (created_at+expires_in)", customer_id=token_data.get("customer_id"))
                await self.redis_client.delete(token_key)
                return None

        logger.debug("Bearer token validated", customer_id=token_data.get("customer_id"))
        return token_data

    async def get_cloudways_token(self, bearer_token: str) -> Optional[str]:
        """
        Get Cloudways API token associated with bearer token.

        Args:
            bearer_token: OAuth access token

        Returns:
            Decrypted Cloudways token if exists, None otherwise
        """
        token_key = f"oauth:token:{bearer_token}"
        token_json = await self.redis_client.get(token_key)

        if not token_json:
            return None

        token_data = json.loads(token_json)
        encrypted_token = token_data.get("cloudways_token")

        if not encrypted_token:
            return None

        try:
            return fernet.decrypt(encrypted_token.encode()).decode()
        except Exception as e:
            logger.error("Failed to decrypt Cloudways token", error=str(e))
            return None

    async def revoke_token(self, bearer_token: str) -> bool:
        """
        Revoke an access token.

        Args:
            bearer_token: Token to revoke

        Returns:
            True if revoked, False if not found
        """
        token_key = f"oauth:token:{bearer_token}"
        result = await self.redis_client.delete(token_key)

        if result:
            logger.info("Access token revoked", token_prefix=bearer_token[:8])

        return bool(result)
