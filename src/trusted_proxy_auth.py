"""Authentication for deployments behind an identity-aware reverse proxy.

The proxy must overwrite the identity header and add a shared-secret header.
Odysseus validates both before trusting the asserted email address.  This is
deliberately opt-in: deployments that do not configure trusted proxy auth keep
the existing password/session behaviour.
"""

from __future__ import annotations

import asyncio
import os
import re
import secrets
from dataclasses import dataclass
from typing import Mapping

from fastapi import Request


_EMAIL_RE = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
    r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?$",
    re.IGNORECASE,
)
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class TrustedProxyAuthError(ValueError):
    """Raised when a proxy assertion is missing or invalid."""


def _csv(value: str) -> frozenset[str]:
    return frozenset(item.strip().lower() for item in value.split(",") if item.strip())


@dataclass(frozen=True)
class TrustedProxyAuth:
    enabled: bool = False
    identity_header: str = "X-Auth-Request-Email"
    secret_header: str = "X-Odysseus-Proxy-Secret"
    shared_secret: str = ""
    allowed_domains: frozenset[str] = frozenset()
    admin_emails: frozenset[str] = frozenset()
    logout_url: str = "/login"

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "TrustedProxyAuth":
        env = os.environ if environ is None else environ
        enabled = env.get("TRUSTED_PROXY_AUTH_ENABLED", "false").strip().lower() == "true"
        identity_header = env.get("TRUSTED_PROXY_AUTH_IDENTITY_HEADER", "X-Auth-Request-Email").strip()
        secret_header = env.get("TRUSTED_PROXY_AUTH_SECRET_HEADER", "X-Odysseus-Proxy-Secret").strip()
        shared_secret = env.get("TRUSTED_PROXY_AUTH_SHARED_SECRET", "")
        allowed_domains = _csv(env.get("TRUSTED_PROXY_AUTH_ALLOWED_DOMAINS", ""))
        admin_emails = _csv(env.get("TRUSTED_PROXY_AUTH_ADMIN_EMAILS", ""))
        logout_url = env.get("TRUSTED_PROXY_AUTH_LOGOUT_URL", "/login").strip() or "/login"

        if enabled:
            if not shared_secret:
                raise RuntimeError(
                    "TRUSTED_PROXY_AUTH_SHARED_SECRET is required when trusted proxy auth is enabled"
                )
            if not allowed_domains:
                raise RuntimeError(
                    "TRUSTED_PROXY_AUTH_ALLOWED_DOMAINS is required when trusted proxy auth is enabled"
                )
            if not _HEADER_NAME_RE.fullmatch(identity_header):
                raise RuntimeError("TRUSTED_PROXY_AUTH_IDENTITY_HEADER is not a valid HTTP header name")
            if not _HEADER_NAME_RE.fullmatch(secret_header):
                raise RuntimeError("TRUSTED_PROXY_AUTH_SECRET_HEADER is not a valid HTTP header name")
            invalid_admins = [email for email in admin_emails if not _EMAIL_RE.fullmatch(email)]
            if invalid_admins:
                raise RuntimeError("TRUSTED_PROXY_AUTH_ADMIN_EMAILS contains an invalid email address")
            outside_domains = [
                email for email in admin_emails if email.rsplit("@", 1)[1] not in allowed_domains
            ]
            if outside_domains:
                raise RuntimeError(
                    "Every TRUSTED_PROXY_AUTH_ADMIN_EMAILS entry must use an allowed domain"
                )

        return cls(
            enabled=enabled,
            identity_header=identity_header,
            secret_header=secret_header,
            shared_secret=shared_secret,
            allowed_domains=allowed_domains,
            admin_emails=admin_emails,
            logout_url=logout_url,
        )

    async def authenticate(self, request: Request, auth_manager) -> str:
        """Validate the proxy assertion and return its provisioned username."""
        if not self.enabled:
            raise TrustedProxyAuthError("Trusted proxy auth is disabled")

        supplied_secret = request.headers.get(self.secret_header, "")
        if not supplied_secret or not secrets.compare_digest(supplied_secret, self.shared_secret):
            raise TrustedProxyAuthError("Invalid trusted proxy assertion")

        email = request.headers.get(self.identity_header, "").strip().lower()
        if not _EMAIL_RE.fullmatch(email):
            raise TrustedProxyAuthError("Invalid trusted proxy identity")
        if email.rsplit("@", 1)[1] not in self.allowed_domains:
            raise TrustedProxyAuthError("Trusted proxy identity domain is not allowed")

        is_admin = email in self.admin_emails
        provisioned = await asyncio.to_thread(
            auth_manager.ensure_trusted_proxy_user,
            email,
            is_admin=is_admin,
        )
        if not provisioned:
            raise TrustedProxyAuthError("Unable to provision trusted proxy identity")
        return email
