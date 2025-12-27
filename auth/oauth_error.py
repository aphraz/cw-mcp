#!/usr/bin/env python3
"""
OAuth 2.0 error responses for MCP authentication
"""

from typing import Dict, Any, Optional
from dataclasses import dataclass
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class OAuthError:
    """
    OAuth 2.0 error response that triggers browser authentication.

    This follows RFC 6749 (OAuth 2.0) error response format.
    When returned by an MCP tool, this signals to the client that
    browser-based authentication is required.
    """
    error: str  # Error code: "authorization_required", "token_expired", etc.
    error_description: str  # Human-readable description
    authorization_uri: str  # URL to open in browser
    session_id: Optional[str] = None  # Session identifier
    state: Optional[str] = None  # OAuth state parameter

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for MCP response"""
        response = {
            "status": "error",
            "error": self.error,
            "error_description": self.error_description,
            "authorization_uri": self.authorization_uri,
        }

        if self.session_id:
            response["session_id"] = self.session_id

        if self.state:
            response["state"] = self.state

        return response


class OAuthErrorResponse(Exception):
    """
    Exception that carries OAuth error metadata.

    When raised in a tool, this should be caught and converted
    to a proper MCP error response with OAuth metadata.
    """
    def __init__(self, oauth_error: OAuthError):
        self.oauth_error = oauth_error
        super().__init__(oauth_error.error_description)


def create_authorization_required_error(session_id: str, auth_base_url: str) -> OAuthError:
    """
    Create an OAuth error for initial authentication.

    Args:
        session_id: Session identifier
        auth_base_url: Base URL for authentication (e.g., https://example.com)

    Returns:
        OAuthError with authorization_uri
    """
    authorization_uri = f"{auth_base_url}/auth?session_id={session_id}"

    return OAuthError(
        error="authorization_required",
        error_description=(
            "Authentication required. Please authenticate in your browser. "
            "A browser window should open automatically."
        ),
        authorization_uri=authorization_uri,
        session_id=session_id
    )


def create_token_expired_error(session_id: str, auth_base_url: str) -> OAuthError:
    """
    Create an OAuth error for token expiration.

    Args:
        session_id: Session identifier
        auth_base_url: Base URL for authentication

    Returns:
        OAuthError with authorization_uri and reason=expired
    """
    authorization_uri = f"{auth_base_url}/auth?session_id={session_id}&reason=expired"

    return OAuthError(
        error="token_expired",
        error_description=(
            "Your session expired. Tokens expire after 1 hour for security. "
            "Please re-authenticate in your browser."
        ),
        authorization_uri=authorization_uri,
        session_id=session_id
    )


def create_authentication_pending_error(session_id: str, auth_base_url: str) -> OAuthError:
    """
    Create an OAuth error for pending authentication.

    Args:
        session_id: Session identifier
        auth_base_url: Base URL for authentication

    Returns:
        OAuthError indicating authentication is pending
    """
    authorization_uri = f"{auth_base_url}/auth?session_id={session_id}"

    return OAuthError(
        error="authorization_pending",
        error_description=(
            "Authentication is pending. Please complete authentication in your browser. "
            "If the browser didn't open automatically, please open the URL manually."
        ),
        authorization_uri=authorization_uri,
        session_id=session_id
    )
