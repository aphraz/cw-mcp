#!/usr/bin/env python3
"""
OAuth 2.1 Authentication Middleware for MCP requests

Validates Bearer tokens on all MCP endpoint requests.
"""

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_401_UNAUTHORIZED
import structlog

from config import AUTH_BASE_URL

logger = structlog.get_logger(__name__)

# Module-level variable for oauth_token_manager (set during initialization)
_global_oauth_token_manager = None

class OAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware that validates OAuth Bearer tokens for MCP requests.

    Following MCP OAuth 2.1 specification:
    - Returns 401 Unauthorized with WWW-Authenticate header if token missing/invalid
    - Stores authenticated user data in request.state for tools to access
    """

    def __init__(self, app, oauth_token_manager=None):
        super().__init__(app)
        self._oauth_token_manager = oauth_token_manager

    @property
    def oauth_token_manager(self):
        """Get oauth_token_manager from instance, global, or resources"""
        if self._oauth_token_manager is not None:
            return self._oauth_token_manager

        # Try module-level global first
        global _global_oauth_token_manager
        if _global_oauth_token_manager is not None:
            return _global_oauth_token_manager

        # Fallback: Import from main resources
        try:
            from main import resources
            if resources.oauth_token_manager is None:
                logger.error("resources.oauth_token_manager is None! Resources may not be initialized yet.")
            return resources.oauth_token_manager
        except Exception as e:
            logger.error(f"Failed to get oauth_token_manager from resources: {e}")
            return None

    async def dispatch(self, request: Request, call_next):
        # Only authenticate MCP endpoint requests
        if not request.url.path.startswith("/mcp"):
            return await call_next(request)

        # Skip authentication for MCP initialization/discovery
        if request.method == "GET":
            return await call_next(request)

        # Check for header-based authentication first (if enabled)
        from config import ENABLE_HEADER_AUTH, ENABLE_OAUTH_AUTH

        email = request.headers.get("x-cloudways-email")
        api_key = request.headers.get("x-cloudways-api-key")

        if email and api_key:
            if not ENABLE_HEADER_AUTH:
                logger.warning("Header-based auth disabled", email=email)
                return self._create_401_response(
                    "header_auth_disabled",
                    "Header-based authentication is disabled. Please use OAuth authentication."
                )
            # Header-based authentication - bypass OAuth for compatibility
            logger.debug("Using header-based authentication", email=email)
            request.state.authenticated = True
            request.state.auth_method = "headers"
            request.state.cloudways_email = email
            request.state.cloudways_api_key = api_key
            return await call_next(request)

        # Extract Authorization header for OAuth/bearer token auth
        auth_header = request.headers.get("Authorization", "")

        if not auth_header:
            logger.info("MCP request without Authorization header", path=request.url.path)
            return self._create_401_response("authorization_required")

        # Check if OAuth authentication is enabled
        if not ENABLE_OAUTH_AUTH:
            logger.warning("OAuth auth disabled")
            return self._create_401_response(
                "oauth_auth_disabled",
                "OAuth authentication is disabled. Please use header-based authentication."
            )

        # Parse Bearer token
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            logger.warning("Invalid Authorization header format")
            return self._create_401_response("invalid_request")

        bearer_token = parts[1]

        # Validate token
        token_data = await self.oauth_token_manager.validate_bearer_token(bearer_token)

        if not token_data:
            logger.warning("Invalid or expired bearer token")
            return self._create_401_response("invalid_token")

        # Store authenticated user data in request state
        request.state.authenticated = True
        request.state.customer_id = token_data.get("customer_id")
        request.state.customer_email = token_data.get("customer_email")
        request.state.bearer_token = bearer_token

        logger.debug(
            "MCP request authenticated",
            customer_id=token_data.get("customer_id"),
            path=request.url.path
        )

        # Proceed with request
        return await call_next(request)

    def _create_401_response(self, error: str) -> JSONResponse:
        """
        Create 401 Unauthorized response with OAuth headers.

        Args:
            error: OAuth error code (invalid_token, invalid_request, etc.)

        Returns:
            JSONResponse with 401 status
        """
        auth_value = f'Bearer realm="{AUTH_BASE_URL}", error="{error}"'

        if error == "authorization_required":
            error_description = "Authorization required. Please authenticate using OAuth 2.1."
        elif error == "invalid_token":
            error_description = "The access token is invalid or expired."
        elif error == "invalid_request":
            error_description = "Invalid authorization header format. Expected: Authorization: Bearer <token>"
        else:
            error_description = "Authentication failed."

        headers = {
            "WWW-Authenticate": auth_value,
            "Link": f'<{AUTH_BASE_URL}/.well-known/oauth-authorization-server>; rel="oauth-authorization-server"'
        }

        return JSONResponse(
            status_code=HTTP_401_UNAUTHORIZED,
            content={
                "error": error,
                "error_description": error_description,
                "authorization_endpoint": f"{AUTH_BASE_URL}/authorize",
                "token_endpoint": f"{AUTH_BASE_URL}/token"
            },
            headers=headers
        )
