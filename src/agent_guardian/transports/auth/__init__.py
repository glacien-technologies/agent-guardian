"""Authentication providers for HTTP transports (Stage 1A).

Every provider receives **pre-resolved** secret strings (never an env-var name
or a file path — secret resolution happens upstream). A provider exposes two
hooks:

* :meth:`AuthProvider.apply` — mutate the per-request headers / client kwargs in
  place before the request is sent.
* :meth:`AuthProvider.on_unauthorized` — react to a 401 from the target; return
  ``True`` to signal "retry the request once" (e.g. after refreshing a token).

See :mod:`agent_guardian.transports.auth.base` for the contract.
"""

from __future__ import annotations

from agent_guardian.transports.auth.api_key import ApiKeyAuth
from agent_guardian.transports.auth.base import AuthContext, AuthProvider, NoAuth
from agent_guardian.transports.auth.bearer import BearerAuth
from agent_guardian.transports.auth.hmac import HmacAuth
from agent_guardian.transports.auth.mtls import MutualTlsAuth
from agent_guardian.transports.auth.oauth2 import OAuth2ClientCredentialsAuth

__all__ = [
    "ApiKeyAuth",
    "AuthContext",
    "AuthProvider",
    "BearerAuth",
    "HmacAuth",
    "MutualTlsAuth",
    "NoAuth",
    "OAuth2ClientCredentialsAuth",
]
