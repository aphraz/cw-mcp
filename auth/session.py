"""
Session management for OAuth-like browser authentication.

This module handles the lifecycle of authentication sessions, including:
- Session creation with cryptographically secure IDs
- Session validation and status tracking
- Token storage and retrieval
- Session cleanup
"""

import asyncio
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, Any

import redis.asyncio as redis
import structlog

from .exceptions import SessionNotFoundError, TokenExpiredError

logger = structlog.get_logger()


class AuthStatus(str, Enum):
    """Authentication status states for a session."""
    PENDING = "pending"
    AUTHENTICATED = "authenticated"
    EXPIRED = "expired"


@dataclass
class AuthSession:
    """
    Represents an authentication session.

    Attributes:
        session_id: Unique session identifier (SHA256 hex, 64 chars)
        auth_status: Current authentication status
        created_at: When the session was created
        customer_id: Customer identifier (set after authentication)
        customer_email: Customer email (set after authentication)
        token_expires_at: When the access token expires (Unix timestamp)
    """
    session_id: str
    auth_status: AuthStatus
    created_at: datetime
    customer_id: Optional[str] = None
    customer_email: Optional[str] = None
    token_expires_at: Optional[float] = None
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_authenticated(self) -> bool:
        """Check if session is authenticated."""
        return self.auth_status == AuthStatus.AUTHENTICATED

    def is_expired(self) -> bool:
        """Check if session or token is expired."""
        if self.auth_status == AuthStatus.EXPIRED:
            return True
        if self.token_expires_at and time.time() >= self.token_expires_at:
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary for storage."""
        return {
            "session_id": self.session_id,
            "auth_status": self.auth_status.value,
            "created_at": self.created_at.isoformat(),
            "customer_id": self.customer_id,
            "customer_email": self.customer_email,
            "token_expires_at": self.token_expires_at,
            "last_activity": self.last_activity.isoformat()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthSession":
        """Create session from dictionary."""
        return cls(
            session_id=data["session_id"],
            auth_status=AuthStatus(data["auth_status"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            customer_id=data.get("customer_id"),
            customer_email=data.get("customer_email"),
            token_expires_at=data.get("token_expires_at"),
            last_activity=datetime.fromisoformat(data.get("last_activity", data["created_at"]))
        )


class SessionManager:
    """
    Manages authentication sessions with Redis storage.

    Redis key structure:
        session:{session_id}:data      - Session metadata (JSON)
        session:{session_id}:status    - Quick status lookup
        session:{session_id}:token     - Encrypted access token
        session:{session_id}:token_meta - Token metadata (expiry, etc.)
    """

    def __init__(self, redis_client: redis.Redis):
        """
        Initialize session manager.

        Args:
            redis_client: Async Redis client for session storage
        """
        self.redis_client = redis_client
        self.session_pending_ttl = 300  # 5 minutes for pending auth
        self.session_authenticated_ttl = 3600  # 1 hour (matches token expiry)

    def generate_session_id(self) -> str:
        """
        Generate a cryptographically secure session ID.

        Returns:
            64-character hex string (SHA256 of random bytes + timestamp)
        """
        random_bytes = secrets.token_bytes(32)
        timestamp = str(time.time()).encode()
        combined = random_bytes + timestamp
        return hashlib.sha256(combined).hexdigest()

    async def create_session(self, session_id: Optional[str] = None) -> AuthSession:
        """
        Create a new pending authentication session.

        Args:
            session_id: Optional session ID to use (e.g., from MCP transport).
                       If not provided, a new one will be generated.

        Returns:
            New AuthSession with PENDING status
        """
        if not session_id:
            session_id = self.generate_session_id()

        session = AuthSession(
            session_id=session_id,
            auth_status=AuthStatus.PENDING,
            created_at=datetime.now(timezone.utc)
        )

        # Store session data
        await self._store_session(session, ttl=self.session_pending_ttl)

        logger.info(
            "Session created",
            session_id=session_id,
            status=session.auth_status.value
        )

        return session

    async def get_session(self, session_id: str) -> Optional[AuthSession]:
        """
        Retrieve a session by ID.

        Args:
            session_id: Session identifier

        Returns:
            AuthSession if found, None otherwise
        """
        data_key = f"session:{session_id}:data"
        session_data = await self.redis_client.get(data_key)

        if not session_data:
            logger.debug("Session not found", session_id=session_id)
            return None

        try:
            data = json.loads(session_data)
            session = AuthSession.from_dict(data)

            # Update last activity
            session.last_activity = datetime.now(timezone.utc)
            await self._store_session(session)

            logger.debug(
                "Session retrieved",
                session_id=session_id,
                status=session.auth_status.value
            )

            return session

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.error(
                "Failed to deserialize session",
                session_id=session_id,
                error=str(e)
            )
            return None

    async def update_session_status(
        self,
        session_id: str,
        status: AuthStatus,
        customer_id: Optional[str] = None,
        customer_email: Optional[str] = None,
        token_expires_at: Optional[float] = None
    ) -> None:
        """
        Update session status and metadata.

        Args:
            session_id: Session identifier
            status: New authentication status
            customer_id: Customer identifier (for authenticated sessions)
            customer_email: Customer email (for authenticated sessions)
            token_expires_at: Token expiry timestamp (for authenticated sessions)
        """
        session = await self.get_session(session_id)
        if not session:
            raise SessionNotFoundError(session_id)

        session.auth_status = status
        if customer_id:
            session.customer_id = customer_id
        if customer_email:
            session.customer_email = customer_email
        if token_expires_at:
            session.token_expires_at = token_expires_at

        # Use longer TTL for authenticated sessions
        ttl = (
            self.session_authenticated_ttl
            if status == AuthStatus.AUTHENTICATED
            else self.session_pending_ttl
        )

        await self._store_session(session, ttl=ttl)

        logger.info(
            "Session status updated",
            session_id=session_id,
            status=status.value,
            customer_id=customer_id
        )

    async def validate_session(self, session_id: str) -> bool:
        """
        Validate that a session exists and is not expired.

        Args:
            session_id: Session identifier

        Returns:
            True if session is valid, False otherwise
        """
        session = await self.get_session(session_id)
        if not session:
            return False

        if session.is_expired():
            await self.mark_session_expired(session_id)
            return False

        return True

    async def mark_session_expired(self, session_id: str) -> None:
        """
        Mark a session as expired.

        Args:
            session_id: Session identifier
        """
        await self.update_session_status(session_id, AuthStatus.EXPIRED)

        logger.info("Session marked as expired", session_id=session_id)

    async def delete_session(self, session_id: str) -> None:
        """
        Delete a session and all associated data.

        Args:
            session_id: Session identifier
        """
        keys_to_delete = [
            f"session:{session_id}:data",
            f"session:{session_id}:status",
            f"session:{session_id}:token",
            f"session:{session_id}:token_meta"
        ]

        deleted = await self.redis_client.delete(*keys_to_delete)

        logger.info(
            "Session deleted",
            session_id=session_id,
            keys_deleted=deleted
        )

    async def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions (background task).

        Returns:
            Number of sessions cleaned up
        """
        # Get all session keys
        pattern = "session:*:data"
        cursor = 0
        cleaned = 0

        while True:
            cursor, keys = await self.redis_client.scan(
                cursor,
                match=pattern,
                count=100
            )

            for key in keys:
                session_id = key.split(":")[1]
                session = await self.get_session(session_id)

                if session and session.is_expired():
                    await self.delete_session(session_id)
                    cleaned += 1

            if cursor == 0:
                break

        if cleaned > 0:
            logger.info("Expired sessions cleaned up", count=cleaned)

        return cleaned

    async def _store_session(self, session: AuthSession, ttl: Optional[int] = None) -> None:
        """
        Store session data in Redis.

        Args:
            session: Session to store
            ttl: Time to live in seconds
        """
        data_key = f"session:{session.session_id}:data"
        status_key = f"session:{session.session_id}:status"

        session_data = json.dumps(session.to_dict())

        if ttl:
            await self.redis_client.setex(data_key, ttl, session_data)
            await self.redis_client.setex(status_key, ttl, session.auth_status.value)
        else:
            # Use default TTL based on status
            default_ttl = (
                self.session_authenticated_ttl
                if session.auth_status == AuthStatus.AUTHENTICATED
                else self.session_pending_ttl
            )
            await self.redis_client.setex(data_key, default_ttl, session_data)
            await self.redis_client.setex(status_key, default_ttl, session.auth_status.value)


async def start_session_cleanup_task(session_manager: SessionManager, interval: int = 600) -> None:
    """
    Background task to periodically clean up expired sessions.

    Args:
        session_manager: SessionManager instance
        interval: Cleanup interval in seconds (default: 10 minutes)
    """
    logger.info("Session cleanup task started", interval=interval)

    while True:
        try:
            await asyncio.sleep(interval)
            await session_manager.cleanup_expired_sessions()
        except Exception as e:
            logger.error("Session cleanup task error", error=str(e))
