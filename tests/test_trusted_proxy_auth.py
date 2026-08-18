from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import Response

from src.trusted_proxy_auth import TrustedProxyAuth, TrustedProxyAuthError
from tests.helpers.import_state import clear_module


def _config(**overrides):
    env = {
        "TRUSTED_PROXY_AUTH_ENABLED": "true",
        "TRUSTED_PROXY_AUTH_SHARED_SECRET": "correct-horse-battery-staple",
        "TRUSTED_PROXY_AUTH_ALLOWED_DOMAINS": "applyinnovations.com.au",
        "TRUSTED_PROXY_AUTH_ADMIN_EMAILS": "alexander@applyinnovations.com.au",
        "TRUSTED_PROXY_AUTH_LOGOUT_URL": "/oauth2/sign_out",
    }
    env.update(overrides)
    return TrustedProxyAuth.from_env(env)


def _request(email="alexander@applyinnovations.com.au", secret="correct-horse-battery-staple"):
    return SimpleNamespace(
        headers={
            "X-Auth-Request-Email": email,
            "X-Odysseus-Proxy-Secret": secret,
        }
    )


@pytest.mark.asyncio
async def test_authenticates_and_provisions_configured_admin():
    manager = MagicMock()
    manager.ensure_trusted_proxy_user.return_value = True

    username = await _config().authenticate(_request(), manager)

    assert username == "alexander@applyinnovations.com.au"
    manager.ensure_trusted_proxy_user.assert_called_once_with(
        "alexander@applyinnovations.com.au", is_admin=True
    )


@pytest.mark.asyncio
async def test_provisions_allowed_non_admin_identity():
    manager = MagicMock()
    manager.ensure_trusted_proxy_user.return_value = True

    username = await _config().authenticate(
        _request(email="USER@applyinnovations.com.au"), manager
    )

    assert username == "user@applyinnovations.com.au"
    manager.ensure_trusted_proxy_user.assert_called_once_with(
        "user@applyinnovations.com.au", is_admin=False
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "proxy_request",
    [
        _request(secret="wrong"),
        _request(secret=""),
        _request(email="attacker@example.net"),
        _request(email="not-an-email"),
    ],
)
async def test_rejects_untrusted_assertions(proxy_request):
    manager = MagicMock()

    with pytest.raises(TrustedProxyAuthError):
        await _config().authenticate(proxy_request, manager)

    manager.ensure_trusted_proxy_user.assert_not_called()


def test_enabled_configuration_requires_secret_and_domains():
    with pytest.raises(RuntimeError, match="SHARED_SECRET"):
        _config(TRUSTED_PROXY_AUTH_SHARED_SECRET="")
    with pytest.raises(RuntimeError, match="ALLOWED_DOMAINS"):
        _config(TRUSTED_PROXY_AUTH_ALLOWED_DOMAINS="")


def test_admin_must_be_in_an_allowed_domain():
    with pytest.raises(RuntimeError, match="allowed domain"):
        _config(TRUSTED_PROXY_AUTH_ADMIN_EMAILS="admin@example.net")


def test_auth_manager_provisions_and_promotes_trusted_proxy_user(tmp_path):
    clear_module("core.auth")
    from core.auth import AuthManager

    manager = AuthManager(str(tmp_path / "auth.json"))
    assert manager.ensure_trusted_proxy_user("person@applyinnovations.com.au") is True
    assert manager.is_admin("person@applyinnovations.com.au") is False
    assert manager.users["person@applyinnovations.com.au"]["auth_source"] == "trusted_proxy"

    assert manager.ensure_trusted_proxy_user(
        "person@applyinnovations.com.au", is_admin=True
    ) is True
    assert manager.is_admin("person@applyinnovations.com.au") is True


@pytest.mark.asyncio
async def test_auth_routes_report_proxy_identity_and_logout_url(tmp_path):
    clear_module("core.auth")
    clear_module("routes.auth_routes")
    from core.auth import AuthManager
    from routes.auth_routes import setup_auth_routes

    manager = AuthManager(str(tmp_path / "auth.json"))
    email = "alexander@applyinnovations.com.au"
    assert manager.ensure_trusted_proxy_user(email, is_admin=True) is True
    proxy_auth = _config()
    request = SimpleNamespace(
        state=SimpleNamespace(current_user=email),
        app=SimpleNamespace(state=SimpleNamespace(trusted_proxy_auth=proxy_auth)),
        cookies={},
    )
    router = setup_auth_routes(manager)
    status_endpoint = next(
        route.endpoint
        for route in router.routes
        if route.path == "/api/auth/status" and "GET" in route.methods
    )
    logout_endpoint = next(
        route.endpoint
        for route in router.routes
        if route.path == "/api/auth/logout" and "POST" in route.methods
    )

    status = await status_endpoint(request)
    logout = await logout_endpoint(request, Response())

    assert status["authenticated"] is True
    assert status["username"] == email
    assert status["is_admin"] is True
    assert status["auth_source"] == "trusted_proxy"
    assert status["logout_url"] == "/oauth2/sign_out"
    assert logout == {"ok": True, "logout_url": "/oauth2/sign_out"}
