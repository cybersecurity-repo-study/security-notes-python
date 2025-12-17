"""
Shared pytest configuration for tests.

We reset the in-memory login rate-limiting state between tests so that:
- rate limiting remains active and testable, but
- tests do not interfere with each other via global `_login_attempts`.
"""

import pytest

from app import auth


@pytest.fixture(autouse=True)
def clear_rate_limit_state():
    """
    Automatically clear auth._login_attempts around each test.

    This keeps rate limiting behavior intact within a single test while
    preventing cross-test coupling via shared global state.
    """
    # Pre-test cleanup
    auth._login_attempts.get("by_username", {}).clear()
    auth._login_attempts.get("by_ip", {}).clear()

    yield

    # Post-test cleanup (defensive)
    auth._login_attempts.get("by_username", {}).clear()
    auth._login_attempts.get("by_ip", {}).clear()

