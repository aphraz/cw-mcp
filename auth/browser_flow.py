"""
Browser-based authentication flow for OAuth-like authentication.

This module handles:
- Cross-platform browser opening
- Polling for authentication completion
- Timeout handling
"""

import asyncio
import platform
import subprocess
import webbrowser
from typing import Optional, NamedTuple

import structlog

from .exceptions import BrowserAuthTimeoutError
from .session import SessionManager, AuthStatus

logger = structlog.get_logger()


class AuthResult(NamedTuple):
    """Result of an authentication attempt."""
    success: bool
    message: str
    session_id: Optional[str] = None


class BrowserAuthenticator:
    """
    Handles browser-based authentication flow.

    Responsibilities:
    - Open browser to authentication page
    - Poll session status until authenticated or timeout
    - Handle cross-platform browser opening
    """

    def __init__(self, poll_interval: float = 1.0):
        """
        Initialize browser authenticator.

        Args:
            poll_interval: Seconds between status polls (default: 1.0)
        """
        self.poll_interval = poll_interval

    def open_browser(self, auth_url: str) -> bool:
        """
        Open browser to authentication URL.

        Uses multiple fallback strategies for cross-platform compatibility:
        1. Python's webbrowser module (primary)
        2. Platform-specific commands (macOS: open, Windows: start, Linux: xdg-open)

        Args:
            auth_url: Full URL to authentication page

        Returns:
            True if browser opened successfully, False otherwise
        """
        try:
            # Primary: Use Python's webbrowser module
            webbrowser.open(auth_url)
            logger.info("Browser opened via webbrowser module", url=auth_url)
            return True

        except Exception as e:
            logger.warning(
                "Failed to open browser via webbrowser module",
                error=str(e),
                url=auth_url
            )

            # Fallback: Platform-specific commands
            return self._open_browser_fallback(auth_url)

    def _open_browser_fallback(self, auth_url: str) -> bool:
        """
        Fallback browser opening using platform-specific commands.

        Args:
            auth_url: Full URL to authentication page

        Returns:
            True if browser opened successfully, False otherwise
        """
        system = platform.system()

        try:
            if system == 'Darwin':  # macOS
                subprocess.run(['open', auth_url], check=True)
                logger.info("Browser opened via macOS 'open' command", url=auth_url)
                return True

            elif system == 'Windows':
                subprocess.run(['start', auth_url], shell=True, check=True)
                logger.info("Browser opened via Windows 'start' command", url=auth_url)
                return True

            elif system == 'Linux':
                subprocess.run(['xdg-open', auth_url], check=True)
                logger.info("Browser opened via Linux 'xdg-open' command", url=auth_url)
                return True

            else:
                logger.error("Unsupported platform for browser opening", platform=system)
                return False

        except subprocess.CalledProcessError as e:
            logger.error(
                "Failed to open browser via platform command",
                platform=system,
                error=str(e)
            )
            return False

        except FileNotFoundError as e:
            logger.error(
                "Browser opening command not found",
                platform=system,
                error=str(e)
            )
            return False

    async def wait_for_authentication(
        self,
        session_id: str,
        session_manager: SessionManager,
        timeout: int = 300
    ) -> AuthResult:
        """
        Poll session status until authenticated or timeout.

        Args:
            session_id: Session identifier to poll
            session_manager: SessionManager instance for status checks
            timeout: Maximum seconds to wait (default: 300 = 5 minutes)

        Returns:
            AuthResult with success status and message

        Raises:
            BrowserAuthTimeoutError: If authentication not completed within timeout
        """
        start_time = asyncio.get_event_loop().time()
        elapsed = 0

        logger.info(
            "Waiting for authentication",
            session_id=session_id,
            timeout=timeout
        )

        while elapsed < timeout:
            session = await session_manager.get_session(session_id)

            if not session:
                logger.error("Session disappeared during polling", session_id=session_id)
                return AuthResult(
                    success=False,
                    message="Session not found",
                    session_id=session_id
                )

            if session.auth_status == AuthStatus.AUTHENTICATED:
                logger.info(
                    "Authentication successful",
                    session_id=session_id,
                    elapsed_seconds=round(elapsed, 2)
                )
                return AuthResult(
                    success=True,
                    message="Authentication successful",
                    session_id=session_id
                )

            if session.auth_status == AuthStatus.EXPIRED:
                logger.warning("Session expired during authentication", session_id=session_id)
                return AuthResult(
                    success=False,
                    message="Session expired",
                    session_id=session_id
                )

            # Still pending, continue polling
            await asyncio.sleep(self.poll_interval)
            elapsed = asyncio.get_event_loop().time() - start_time

        # Timeout reached
        logger.warning(
            "Authentication timeout",
            session_id=session_id,
            timeout=timeout
        )

        return AuthResult(
            success=False,
            message=f"Authentication timeout after {timeout} seconds",
            session_id=session_id
        )

    async def poll_session_status(
        self,
        session_id: str,
        session_manager: SessionManager
    ) -> str:
        """
        Check current session status (single poll).

        Args:
            session_id: Session identifier
            session_manager: SessionManager instance

        Returns:
            Session status as string: "pending", "authenticated", or "expired"
        """
        session = await session_manager.get_session(session_id)

        if not session:
            return "not_found"

        return session.auth_status.value


async def initiate_browser_auth(
    session_id: str,
    auth_base_url: str,
    session_manager: SessionManager,
    browser_authenticator: BrowserAuthenticator,
    timeout: int = 300
) -> AuthResult:
    """
    Initiate browser authentication flow.

    This is the main entry point for starting browser authentication:
    1. Construct auth URL
    2. Open browser
    3. Poll for authentication completion

    Args:
        session_id: Session identifier
        auth_base_url: Base URL for auth endpoints (e.g., "http://localhost:7000")
        session_manager: SessionManager instance
        browser_authenticator: BrowserAuthenticator instance
        timeout: Maximum seconds to wait for authentication

    Returns:
        AuthResult with authentication outcome
    """
    # Construct auth URL
    auth_url = f"{auth_base_url}/auth?session_id={session_id}"

    logger.info(
        "Initiating browser authentication",
        session_id=session_id,
        auth_url=auth_url
    )

    # Open browser
    browser_opened = browser_authenticator.open_browser(auth_url)

    if not browser_opened:
        logger.error("Failed to open browser", session_id=session_id)
        return AuthResult(
            success=False,
            message="Failed to open browser. Please manually visit: " + auth_url,
            session_id=session_id
        )

    # Wait for authentication
    result = await browser_authenticator.wait_for_authentication(
        session_id=session_id,
        session_manager=session_manager,
        timeout=timeout
    )

    return result


async def initiate_re_authentication(
    session_id: str,
    auth_base_url: str,
    session_manager: SessionManager,
    browser_authenticator: BrowserAuthenticator,
    reason: str = "expired"
) -> AuthResult:
    """
    Initiate re-authentication flow after token expiry.

    Similar to initial authentication but includes a reason parameter.

    Args:
        session_id: Session identifier
        auth_base_url: Base URL for auth endpoints
        session_manager: SessionManager instance
        browser_authenticator: BrowserAuthenticator instance
        reason: Reason for re-authentication (default: "expired")

    Returns:
        AuthResult with authentication outcome
    """
    # Construct auth URL with reason
    auth_url = f"{auth_base_url}/auth?session_id={session_id}&reason={reason}"

    logger.info(
        "Initiating re-authentication",
        session_id=session_id,
        reason=reason,
        auth_url=auth_url
    )

    # Reset session to pending
    await session_manager.update_session_status(session_id, AuthStatus.PENDING)

    # Open browser
    browser_opened = browser_authenticator.open_browser(auth_url)

    if not browser_opened:
        logger.error("Failed to open browser for re-authentication", session_id=session_id)
        return AuthResult(
            success=False,
            message="Failed to open browser. Please manually visit: " + auth_url,
            session_id=session_id
        )

    # Wait for authentication (shorter timeout for re-auth)
    result = await browser_authenticator.wait_for_authentication(
        session_id=session_id,
        session_manager=session_manager,
        timeout=300  # 5 minutes
    )

    return result
