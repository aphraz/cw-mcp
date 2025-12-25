"""
Custom authentication exceptions for the Cloudways MCP server.

This module defines exception types used throughout the OAuth-like
browser authentication flow.
"""


class AuthenticationError(Exception):
    """Base exception for all authentication-related errors."""

    def __init__(self, message: str, details: dict = None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)


class SessionNotFoundError(AuthenticationError):
    """Raised when a session ID is not found or has expired."""

    def __init__(self, session_id: str):
        super().__init__(
            f"Session '{session_id}' not found or expired",
            {"session_id": session_id}
        )
        self.session_id = session_id


class TokenExpiredError(AuthenticationError):
    """Raised when an access token has expired and re-authentication is required."""

    def __init__(self, session_id: str, expired_at: float = None):
        message = f"Access token expired for session '{session_id}'"
        details = {"session_id": session_id}
        if expired_at:
            details["expired_at"] = expired_at
        super().__init__(message, details)
        self.session_id = session_id
        self.expired_at = expired_at


class BrowserAuthTimeoutError(AuthenticationError):
    """Raised when user doesn't complete browser authentication within the timeout period."""

    def __init__(self, session_id: str, timeout_seconds: int):
        super().__init__(
            f"Authentication timeout for session '{session_id}' after {timeout_seconds} seconds",
            {"session_id": session_id, "timeout_seconds": timeout_seconds}
        )
        self.session_id = session_id
        self.timeout_seconds = timeout_seconds


class CloudwaysAPIError(AuthenticationError):
    """Raised when the Cloudways API rejects credentials or returns an error."""

    def __init__(self, message: str, status_code: int = None, response_data: dict = None):
        details = {}
        if status_code:
            details["status_code"] = status_code
        if response_data:
            details["response_data"] = response_data
        super().__init__(message, details)
        self.status_code = status_code
        self.response_data = response_data


class RateLimitError(AuthenticationError):
    """Raised when too many authentication attempts have been made."""

    def __init__(self, message: str, retry_after: int = None, attempt_count: int = None):
        details = {}
        if retry_after:
            details["retry_after"] = retry_after
        if attempt_count:
            details["attempt_count"] = attempt_count
        super().__init__(message, details)
        self.retry_after = retry_after
        self.attempt_count = attempt_count


class InvalidCredentialsError(AuthenticationError):
    """Raised when provided credentials are invalid or malformed."""

    def __init__(self, field: str, reason: str):
        super().__init__(
            f"Invalid {field}: {reason}",
            {"field": field, "reason": reason}
        )
        self.field = field
        self.reason = reason
