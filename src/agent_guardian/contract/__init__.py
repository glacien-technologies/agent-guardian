"""AgentGuardian target contract package (Stage 1).

A *contract* declaratively describes the system under test and how to talk to
it, plus the Rules of Engagement that bound any scan. This package owns the
schema, secret references, content hashing, loading / discovery, JSON-Schema
export, and the migration skeleton.

This package is intentionally **decoupled from** :mod:`agent_guardian.transports`:
nothing here imports a transport, and the "build a transport from a contract"
wiring is a later stage.
"""

from __future__ import annotations

from agent_guardian.contract.errors import (
    ContractError,
    ContractValidationError,
    MigrationNeeded,
    SecretResolutionError,
    UnsupportedContractVersion,
)
from agent_guardian.contract.hashing import contract_hash_input, contract_sha256
from agent_guardian.contract.jsonschema_export import (
    CONTRACT_SCHEMA_ID,
    contract_json_schema,
    write_contract_json_schema,
)
from agent_guardian.contract.loader import (
    CONTRACT_FILENAME,
    discover_contract_path,
    load_contract,
    load_contract_file,
    parse_contract,
)
from agent_guardian.contract.migrate import MIGRATIONS, migrate_contract
from agent_guardian.contract.schema import (
    ALLOWED_TEMPLATE_VARS,
    CURRENT_CONTRACT_VERSION,
    MAX_KNOWN_CONTRACT_VERSION,
    ApiKeyAuth,
    Auth,
    BearerAuth,
    Budgets,
    Contract,
    DataEgress,
    HmacAuth,
    HttpTransport,
    Identity,
    IdSend,
    MtlsAuth,
    Network,
    NoAuth,
    OAuth2ClientCredentialsAuth,
    Observability,
    Rate,
    Request,
    Reset,
    Response,
    ResponseError,
    Retry,
    RoE,
    RoeTools,
    Session,
    Stream,
    Target,
    Tls,
    ToolRef,
    Tools,
    Transport,
)
from agent_guardian.contract.secrets import (
    SecretBackend,
    SecretRef,
    SecretResolver,
    iter_secret_refs,
    redact,
    resolve_secret,
    resolve_secrets,
)

__all__ = [
    "ALLOWED_TEMPLATE_VARS",
    "CONTRACT_FILENAME",
    "CONTRACT_SCHEMA_ID",
    "CURRENT_CONTRACT_VERSION",
    "MAX_KNOWN_CONTRACT_VERSION",
    "MIGRATIONS",
    "ApiKeyAuth",
    "Auth",
    "BearerAuth",
    "Budgets",
    "Contract",
    "ContractError",
    "ContractValidationError",
    "DataEgress",
    "HmacAuth",
    "HttpTransport",
    "IdSend",
    "Identity",
    "MigrationNeeded",
    "MtlsAuth",
    "Network",
    "NoAuth",
    "OAuth2ClientCredentialsAuth",
    "Observability",
    "Rate",
    "Request",
    "Reset",
    "Response",
    "ResponseError",
    "Retry",
    "RoE",
    "RoeTools",
    "SecretBackend",
    "SecretRef",
    "SecretResolutionError",
    "SecretResolver",
    "Session",
    "Stream",
    "Target",
    "Tls",
    "ToolRef",
    "Tools",
    "Transport",
    "UnsupportedContractVersion",
    "contract_hash_input",
    "contract_json_schema",
    "contract_sha256",
    "discover_contract_path",
    "iter_secret_refs",
    "load_contract",
    "load_contract_file",
    "migrate_contract",
    "parse_contract",
    "redact",
    "resolve_secret",
    "resolve_secrets",
    "write_contract_json_schema",
]
