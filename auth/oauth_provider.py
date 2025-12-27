#!/usr/bin/env python3
"""
FastMCP OAuth Provider Implementation for Cloudways MCP Server

Implements OAuth 2.1 Authorization Code flow with PKCE using FastMCP's OAuthProvider.
"""

from typing import Optional
import secrets
import hashlib
import json
import time
from dataclasses import dataclass, field

import structlog
from fastmcp.server.auth import OAuthProvider
from mcp.server.auth.provider import AuthorizationParams
from mcp.server.auth.settings import ClientRegistrationOptions
from authlib.oauth2.rfc7636 import create_s256_code_challenge

from config import AUTH_BASE_URL, fernet

logger = structlog.get_logger(__name__)


@dataclass
class CloudwaysOAuthClient:
    """OAuth client information"""
    client_id: str
    client_name: str = "Claude Desktop"
    client_secret: Optional[str] = None
    client_id_issued_at: Optional[int] = None
    client_secret_expires_at: Optional[int] = None
    redirect_uris: list[str] = field(default_factory=list)
    grant_types: list[str] = field(default_factory=lambda: ["authorization_code"])
    response_types: list[str] = field(default_factory=lambda: ["code"])
    token_endpoint_auth_method: str = "none"  # PKCE, no client secret needed

    def get_client_id(self) -> str:
        return self.client_id

    def check_redirect_uri(self, redirect_uri: str) -> bool:
        """Validate redirect URI"""
        # For PKCE clients (no client secret), allow any HTTPS redirect_uri
        # PKCE provides security even without exact redirect_uri matching
        if self.token_endpoint_auth_method == "none" and redirect_uri.startswith("https://"):
            return True
        if not self.redirect_uris:
            return True  # Allow any redirect URI if none configured
        return redirect_uri in self.redirect_uris

    def check_grant_type(self, grant_type: str) -> bool:
        return grant_type in self.grant_types

    def check_response_type(self, response_type: str) -> bool:
        return response_type in self.response_types

    def validate_redirect_uri(self, redirect_uri):
        """Validate redirect URI (required by MCP SDK) - returns URI if valid"""
        # Convert to string if it's a Pydantic URL object
        uri_str = str(redirect_uri) if redirect_uri else ""

        # Accept any HTTPS redirect_uri for PKCE security
        if uri_str.startswith("https://"):
            return uri_str

        # Fallback to strict validation
        if self.check_redirect_uri(uri_str):
            return uri_str

        raise ValueError(f"Invalid redirect_uri: {redirect_uri}")

    def validate_scope(self, scope: str) -> list[str]:
        """Validate and return scopes (required by MCP SDK)"""
        if not scope:
            return ["cloudways:api"]
        return scope.split() if isinstance(scope, str) else scope


@dataclass
class CloudwaysAuthorizationCode:
    """Authorization code for OAuth flow"""
    code: str
    client_id: str
    redirect_uri: str
    scopes: list[str]
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    redirect_uri_provided_explicitly: bool = False
    resource: Optional[str] = None
    user_id: str = None
    session_id: Optional[str] = None
    customer_id: Optional[str] = None
    customer_email: Optional[str] = None
    expires_at: float = field(default_factory=lambda: time.time() + 600)  # 10 min

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def get_redirect_uri(self) -> str:
        return self.redirect_uri

    def get_scope(self) -> str:
        return " ".join(self.scopes)


@dataclass
class CloudwaysAccessToken:
    """OAuth access token"""
    access_token: str
    client_id: str
    user_id: str
    scope: str
    scopes: Optional[list[str]] = None
    customer_id: Optional[str] = None
    customer_email: Optional[str] = None
    expires_at: float = field(default_factory=lambda: time.time() + 3600)  # 1 hour
    cloudways_token: Optional[str] = None
    claims: dict = field(default_factory=dict)

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def get_scope(self) -> str:
        return self.scope

    def get_expires_in(self) -> int:
        return int(self.expires_at - time.time())


@dataclass
class CloudwaysRefreshToken:
    """OAuth refresh token (not used currently)"""
    refresh_token: str
    client_id: str
    user_id: str
    scope: str
    expires_at: float = field(default_factory=lambda: time.time() + 86400)  # 24 hours

    def get_scope(self) -> str:
        return self.scope


class CloudwaysOAuthProvider(OAuthProvider):
    """
    OAuth 2.1 Provider for Cloudways MCP Server

    Implements FastMCP's OAuthProvider interface with Redis storage.
    """

    def __init__(self, redis_client=None, session_manager=None):
        self._redis_client = redis_client
        self._session_manager = session_manager

        super().__init__(
            base_url=AUTH_BASE_URL,
            issuer_url=AUTH_BASE_URL,
            service_documentation_url="https://github.com/afrazchelsea/cloudways-mcp",
            client_registration_options=ClientRegistrationOptions(),  # Enable dynamic client registration
            required_scopes=["cloudways:api"]
        )

        logger.info("CloudwaysOAuthProvider initialized", base_url=AUTH_BASE_URL)

    @property
    def redis_client(self):
        """Get Redis client from instance or resources"""
        if self._redis_client is not None:
            return self._redis_client

        # Import here to avoid circular dependency
        try:
            from main import resources
            if resources.redis_client is not None:
                return resources.redis_client
        except (ImportError, AttributeError):
            pass

        # Fallback: return None and let caller handle it
        return None

    @property
    def session_manager(self):
        """Get SessionManager from instance or resources"""
        if self._session_manager is not None:
            return self._session_manager

        # Import here to avoid circular dependency
        try:
            from main import resources
            if getattr(resources, "session_manager", None) is not None:
                return resources.session_manager
        except Exception:
            pass

        return None

    # ==================== Client Management ====================

    async def get_client(self, client_id: str):
        """
        Retrieve OAuth client by ID

        For Claude Desktop, we auto-register clients with dynamic client registration.
        """
        key = f"oauth:client:{client_id}"
        client_json = await self.redis_client.get(key)

        if client_json:
            data = json.loads(client_json)
            # Backfill optional fields expected by the FastMCP authenticator
            data.setdefault("client_secret", None)
            data.setdefault("client_id_issued_at", None)
            data.setdefault("client_secret_expires_at", None)
            return CloudwaysOAuthClient(**data)

        # Auto-register client for Claude Desktop (dynamic client registration)
        logger.info("Auto-registering OAuth client", client_id=client_id)
        client = CloudwaysOAuthClient(
            client_id=client_id,
            client_name="Claude Desktop",
            token_endpoint_auth_method="none"
        )

        await self.register_client(client)
        return client

    async def register_client(self, client_info):
        """Store OAuth client registration"""
        key = f"oauth:client:{client_info.client_id}"

        client_data = {
            "client_id": client_info.client_id,
            "client_name": client_info.client_name,
            "redirect_uris": client_info.redirect_uris,
            "grant_types": client_info.grant_types,
            "response_types": client_info.response_types,
            "token_endpoint_auth_method": client_info.token_endpoint_auth_method,
            # Optional fields for SDK compatibility (even if None)
            "client_secret": getattr(client_info, "client_secret", None),
            "client_id_issued_at": getattr(client_info, "client_id_issued_at", None),
            "client_secret_expires_at": getattr(client_info, "client_secret_expires_at", None),
        }

        await self.redis_client.setex(key, 86400, json.dumps(client_data))  # 24 hour TTL
        logger.info("OAuth client registered", client_id=client_info.client_id)

    # ==================== Authorization Flow ====================

    async def authorize(self, client, request: AuthorizationParams) -> str:
        """
        Handle OAuth authorization request

        Returns redirect URL to authentication form.
        """
        # Generate authorization code
        code = secrets.token_urlsafe(32)

        # Extract OAuth parameters
        redirect_uri = str(request.redirect_uri) if request.redirect_uri else ""
        scopes = request.scopes or ["cloudways:api"]
        state = request.state
        code_challenge = getattr(request, "code_challenge", None)
        code_challenge_method = getattr(request, "code_challenge_method", "S256")
        redirect_uri_provided = getattr(request, "redirect_uri_provided_explicitly", False)
        resource = getattr(request, "resource", None)

        # Create authorization code
        auth_code = CloudwaysAuthorizationCode(
            code=code,
            client_id=client.client_id,
            redirect_uri=redirect_uri,
            scopes=scopes,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            redirect_uri_provided_explicitly=redirect_uri_provided,
            resource=resource
        )

        # Store authorization code
        await self._store_authorization_code(auth_code)

        # Store OAuth parameters for later use
        session_id = secrets.token_urlsafe(32)
        # Ensure session record exists for browser auth flow
        try:
            session_manager = self.session_manager

            # If missing but we have Redis, create and cache a manager locally
            if session_manager is None and self.redis_client is not None:
                from auth.session import SessionManager
                session_manager = SessionManager(self.redis_client)
                self._session_manager = session_manager
                logger.warning(
                    "Session manager missing during OAuth authorize - created ad hoc",
                    session_id=session_id
                )

            if session_manager:
                logger.info("Creating session for OAuth flow", session_id=session_id)
                await session_manager.create_session(session_id=session_id)
                logger.info("Session created for OAuth flow", session_id=session_id)
            else:  # pragma: no cover
                logger.warning("Session manager missing during OAuth authorize", session_id=session_id)
        except Exception as e:  # pragma: no cover - defensive
            logger.warning("Failed to create session for OAuth flow", session_id=session_id, error=str(e))

        oauth_params = {
            "client_id": client.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "code": code,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method
        }

        oauth_params_key = f"session:{session_id}:oauth_params"
        await self.redis_client.setex(oauth_params_key, 600, json.dumps(oauth_params))

        logger.info(
            "Authorization request processed",
            client_id=client.client_id,
            session_id=session_id
        )

        # Redirect to authentication form
        auth_url = f"{AUTH_BASE_URL}/auth?session_id={session_id}"
        return auth_url

    async def load_authorization_code(self, client, code: str):
        """Load authorization code from storage"""
        key = f"oauth:authcode:{code}"
        code_json = await self.redis_client.get(key)

        if not code_json:
            logger.warning("Authorization code not found", code_prefix=code[:8])
            return None

        data = json.loads(code_json)
        # Backward compatibility: older entries may store "scope" as string
        if "scopes" not in data:
            scope_val = data.get("scope") or ""
            data["scopes"] = scope_val.split() if isinstance(scope_val, str) else ["cloudways:api"]
        # Drop unexpected keys to satisfy dataclass ctor; ensure required fields exist
        allowed_keys = {
            "code", "client_id", "redirect_uri", "scopes", "code_challenge",
            "code_challenge_method", "redirect_uri_provided_explicitly",
            "resource", "user_id", "session_id", "customer_id",
            "customer_email", "expires_at"
        }
        filtered = {k: v for k, v in data.items() if k in allowed_keys}
        # ensure required fields are present even if older entry omitted them
        filtered.setdefault("code", code)
        filtered.setdefault("client_id", client.client_id if client else "")
        filtered.setdefault("redirect_uri", data.get("redirect_uri", ""))
        auth_code = CloudwaysAuthorizationCode(**filtered)

        # Verify client ID matches
        if auth_code.client_id != client.client_id:
            logger.warning(
                "Client ID mismatch for authorization code",
                expected=client.client_id,
                got=auth_code.client_id
            )
            return None

        # Check expiration
        if auth_code.is_expired():
            logger.warning("Authorization code expired", code_prefix=code[:8])
            return None

        return auth_code

    async def _store_authorization_code(self, auth_code: CloudwaysAuthorizationCode):
        """Store authorization code in Redis"""
        key = f"oauth:authcode:{auth_code.code}"

        code_data = {
            "code": auth_code.code,
            "client_id": auth_code.client_id,
            "redirect_uri": auth_code.redirect_uri,
            "scopes": auth_code.scopes,
            "code_challenge": auth_code.code_challenge,
            "code_challenge_method": auth_code.code_challenge_method,
            "redirect_uri_provided_explicitly": auth_code.redirect_uri_provided_explicitly,
            "resource": auth_code.resource,
            "user_id": auth_code.user_id,
            "session_id": auth_code.session_id,
            "customer_id": auth_code.customer_id,
            "customer_email": auth_code.customer_email,
            "expires_at": auth_code.expires_at
        }

        ttl = int(auth_code.expires_at - time.time())
        await self.redis_client.setex(key, ttl, json.dumps(code_data))

        logger.info("Authorization code stored", code_prefix=auth_code.code[:8])

    # ==================== Token Exchange ====================

    async def exchange_authorization_code(self, client, code_or_authcode, request=None):
        """
        Exchange authorization code for access token

        Validates PKCE and returns access token.
        """
        # Support FastMCP AuthorizationCode objects, our CloudwaysAuthorizationCode, or raw strings
        if hasattr(code_or_authcode, "code") and not isinstance(code_or_authcode, str):
            code_value = getattr(code_or_authcode, "code")
        else:
            code_value = code_or_authcode

        if isinstance(code_or_authcode, CloudwaysAuthorizationCode):
            auth_code = code_or_authcode
        else:
            auth_code = await self.load_authorization_code(client, code_value)
            code_or_authcode = auth_code.code if auth_code else None

        if not auth_code:
            logger.warning("Invalid authorization code for exchange")
            return None

        # Validate PKCE code_verifier only when request context is provided (legacy flow)
        if request is not None:
            code_verifier = None
            if hasattr(request, "data"):
                code_verifier = request.data.get("code_verifier")
            elif hasattr(request, "code_verifier"):
                code_verifier = getattr(request, "code_verifier")

            if auth_code.code_challenge:
                if not code_verifier:
                    logger.warning("Missing code_verifier for PKCE flow")
                    return None

                # Verify code challenge
                if auth_code.code_challenge_method == "S256":
                    computed_challenge = create_s256_code_challenge(code_verifier)
                else:
                    computed_challenge = code_verifier

                if computed_challenge != auth_code.code_challenge:
                    logger.warning("PKCE verification failed")
                    return None

        # Delete authorization code (one-time use)
        code_key = f"oauth:authcode:{auth_code.code}"
        await self.redis_client.delete(code_key)

        # Generate access token
        access_token_str = secrets.token_urlsafe(32)

        access_token = CloudwaysAccessToken(
            access_token=access_token_str,
            client_id=client.client_id,
            user_id=auth_code.user_id or "unknown",
            scope=" ".join(auth_code.scopes)
        )

        # Store access token
        await self._store_access_token(access_token)

        logger.info(
            "Authorization code exchanged for access token",
            client_id=client.client_id,
            token_prefix=access_token_str[:8]
        )

        return {
            "access_token": access_token.access_token,
            "token_type": "Bearer",
            "expires_in": access_token.get_expires_in(),
            "scope": access_token.scope
        }

    async def _store_access_token(self, token: CloudwaysAccessToken):
        """Store access token in Redis"""
        key = f"oauth:token:{token.access_token}"

        token_data = {
            "access_token": token.access_token,
            "client_id": token.client_id,
            "user_id": token.user_id,
            "scope": token.scope,
            "scopes": token.scopes or token.scope.split(),
            "customer_id": token.customer_id,
            "customer_email": token.customer_email,
            "expires_at": token.expires_at,
            "claims": token.claims
        }

        if token.cloudways_token:
            encrypted = fernet.encrypt(token.cloudways_token.encode()).decode()
            token_data["cloudways_token"] = encrypted

        ttl = int(token.expires_at - time.time())
        await self.redis_client.setex(key, ttl, json.dumps(token_data))

        logger.debug("Access token stored", token_prefix=token.access_token[:8])

    async def load_access_token(self, token: str):
        """Load and validate access token"""
        key = f"oauth:token:{token}"
        token_json = await self.redis_client.get(key)

        if not token_json:
            logger.debug("Access token not found", token_prefix=token[:8])
            return None

        data = json.loads(token_json)
        allowed_keys = {
            "access_token", "client_id", "user_id", "scope",
            "scopes", "customer_id", "customer_email", "expires_at",
            "claims", "cloudways_token"
        }
        filtered = {k: v for k, v in data.items() if k in allowed_keys}

        # Backfill required fields when stored by OAuthTokenManager (which uses a slimmer schema)
        filtered.setdefault("access_token", token)
        filtered.setdefault("client_id", data.get("client_id", "unknown_client"))
        filtered.setdefault("user_id", data.get("user_id") or data.get("customer_id") or "unknown")
        filtered.setdefault("scope", data.get("scope", "cloudways:api"))
        filtered.setdefault("scopes", data.get("scopes") or filtered["scope"].split())
        if "expires_at" not in filtered:
            created_at = data.get("created_at")
            expires_in = data.get("expires_in")
            if created_at and expires_in:
                filtered["expires_at"] = float(created_at) + float(expires_in)
        filtered.setdefault("claims", {})

        # Decrypt cloudways_token if present
        if filtered.get("cloudways_token"):
            try:
                encrypted_token = filtered["cloudways_token"]
                decrypted = fernet.decrypt(encrypted_token.encode()).decode()
                filtered["cloudways_token"] = decrypted
            except Exception as e:
                logger.warning("Failed to decrypt cloudways_token", error=str(e))
                filtered["cloudways_token"] = None

        access_token = CloudwaysAccessToken(**filtered)

        if access_token.is_expired():
            logger.info("Access token expired", token_prefix=token[:8])
            await self.redis_client.delete(key)
            return None

        return access_token

    # ==================== Refresh Tokens (Not Used) ====================

    async def load_refresh_token(self, client, token: str):
        """Load refresh token (not implemented)"""
        return None

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        """Exchange refresh token (not implemented)"""
        return None

    # ==================== Token Revocation ====================

    async def revoke_token(self, token: str):
        """Revoke an access token"""
        key = f"oauth:token:{token}"
        result = await self.redis_client.delete(key)

        if result:
            logger.info("Token revoked", token_prefix=token[:8])

        return bool(result)
