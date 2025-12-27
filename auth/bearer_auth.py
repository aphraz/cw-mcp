#!/usr/bin/env python3
"""
Bearer Token Authentication for MCP OAuth 2.1

Implements Authorization header validation following MCP specification.
"""

from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
import structlog

from config import AUTH_BASE_URL

logger = structlog.get_logger(__name__)


class BearerTokenAuth:
    """
    Bearer token authentication for MCP requests.

    Extracts and validates Authorization: Bearer <token> header.
    """

    def __init__(self, oauth_token_manager):
        self.oauth_token_manager = oauth_token_manager

    async def authenticate(self, request: Request) -> Optional[Dict[str, Any]]:
        """
        Authenticate request using Bearer token.

        Args:
            request: FastAPI request

        Returns:
            Token data if authenticated, None otherwise

        Raises:
            HTTPException: 401 if authentication required or invalid
        """
        # Extract Authorization header
        auth_header = request.headers.get("Authorization")

        if not auth_header:
            # No authorization header - return 401 with WWW-Authenticate
            logger.info("No Authorization header present", path=request.url.path)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization required",
                headers=self._www_authenticate_header()
            )

        # Parse Bearer token
        parts = auth_header.split()

        if len(parts) != 2 or parts[0].lower() != "bearer":
            logger.warning("Invalid Authorization header format", auth_header=auth_header[:20])
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization header format. Expected: Bearer <token>",
                headers=self._www_authenticate_header()
            )

        bearer_token = parts[1]

        # Validate token
        token_data = await self.oauth_token_manager.validate_bearer_token(bearer_token)

        if not token_data:
            logger.warning("Invalid or expired bearer token")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired access token",
                headers=self._www_authenticate_header(error="invalid_token")
            )

        logger.debug(
            "Request authenticated",
            customer_id=token_data.get("customer_id"),
            path=request.url.path
        )

        return token_data

    def _www_authenticate_header(self, error: Optional[str] = None) -> Dict[str, str]:
        """
        Generate WWW-Authenticate header for 401 responses.

        Following RFC 6750 (OAuth 2.0 Bearer Token Usage).

        Args:
            error: Optional error code (invalid_token, invalid_request, etc.)

        Returns:
            Headers dict
        """
        # Base WWW-Authenticate header
        auth_value = f'Bearer realm="{AUTH_BASE_URL}"'

        if error:
            auth_value += f', error="{error}"'

        # Add authorization endpoint for client discovery
        headers = {
            "WWW-Authenticate": auth_value,
            "Link": f'<{AUTH_BASE_URL}/.well-known/oauth-authorization-server>; rel="oauth-authorization-server"'
        }

        return headers


async def extract_bearer_token(request: Request) -> Optional[str]:
    """
    Extract bearer token from Authorization header.

    Args:
        request: FastAPI request

    Returns:
        Bearer token if present, None otherwise
    """
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split()

    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]

    return None


def create_401_response(auth_base_url: str, error: Optional[str] = None) -> JSONResponse:
    """
    Create a 401 Unauthorized response with proper OAuth headers.

    Args:
        auth_base_url: Base URL for authentication
        error: Optional OAuth error code

    Returns:
        JSONResponse with 401 status and WWW-Authenticate header
    """
    auth_value = f'Bearer realm="{auth_base_url}"'

    if error:
        auth_value += f', error="{error}"'

    headers = {
        "WWW-Authenticate": auth_value,
        "Link": f'<{auth_base_url}/.well-known/oauth-authorization-server>; rel="oauth-authorization-server"'
    }

    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "error": error or "unauthorized",
            "error_description": "Authorization required. Please authenticate using OAuth 2.1.",
            "authorization_uri": f"{auth_base_url}/auth"
        },
        headers=headers
    )
