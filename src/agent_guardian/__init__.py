"""AgentGuardian Open — adversarial swarm framework for agentic AI red-teaming."""

from agent_guardian._version import __version__
from agent_guardian.adapters.base import (
    TargetAdapter,
    TargetFingerprint,
    TargetMode,
)
from agent_guardian.adapters.code import CodeAdapter
from agent_guardian.adapters.framework.adk import ADKAdapter
from agent_guardian.adapters.framework.autogen import AutoGenAdapter
from agent_guardian.adapters.framework.base import FrameworkAdapter
from agent_guardian.adapters.framework.crewai import CrewAIAdapter
from agent_guardian.adapters.framework.langgraph import LangGraphAdapter
from agent_guardian.adapters.framework.openai_agents import OpenAIAgentsAdapter
from agent_guardian.adapters.framework.strands import StrandsAdapter
from agent_guardian.adapters.http import HttpAdapter
from agent_guardian.adapters.http_shapes.base import (
    HttpShape,
    get_shape,
    list_shapes,
    register_shape,
)
from agent_guardian.adapters.prompt import PromptAdapter
from agent_guardian.agents.a2a import A2AAgent
from agent_guardian.agents.base import (
    AgentBudget,
    AgentReport,
    AsiAgent,
    Judge,
    JudgeRubric,
)
from agent_guardian.agents.cascade import CascadeAgent
from agent_guardian.agents.code_exec import CodeExecAgent
from agent_guardian.agents.drift import DriftAgent
from agent_guardian.agents.goal_hijack import GoalHijackAgent
from agent_guardian.agents.memory_poison import MemoryPoisonAgent
from agent_guardian.agents.privilege import PrivilegeAgent
from agent_guardian.agents.recon import ReconAgent
from agent_guardian.agents.supply_chain import SupplyChainAgent
from agent_guardian.agents.tool_abuse import ToolAbuseAgent
from agent_guardian.agents.trust_exploit import TrustExploitAgent
from agent_guardian.core.budget import BudgetController, BudgetSlice
from agent_guardian.core.memory import (
    MemoryFeatureUnavailable,
    MemoryRecord,
    MemoryStats,
    SharedMemory,
    VectorHit,
)
from agent_guardian.core.redact import PiiRedactor
from agent_guardian.core.sandbox import Sandbox, SandboxPolicy, SandboxViolation
from agent_guardian.core.scoring import (
    AIVSS_FORMULA_VERSION,
    AivssResult,
    compute_aivss,
)
from agent_guardian.core.swarm import (
    CheckpointDecision,
    SwarmCommander,
    SwarmConfig,
    SwarmEvent,
    SwarmObserver,
)
from agent_guardian.core.tiering import detect_tier
from agent_guardian.cost import (
    PRICE_TABLE,
    PRICE_TABLE_AS_OF,
    PriceRow,
    estimate_scan_cost,
    lookup_price,
)
from agent_guardian.crypto.ed25519_sig import (
    DEFAULT_KEYS_DIR,
    Ed25519Keypair,
    Ed25519SignatureBlock,
    load_or_create_keypair,
    sign_ed25519,
    verify_ed25519,
)
from agent_guardian.crypto.hmac_sig import (
    DEFAULT_PBKDF2_ITERATIONS,
    DEFAULT_SIGNING_SECRET,
    HMAC_ALGORITHM,
    SIGNATURE_VERSION,
    HmacSignatureBlock,
    derive_key,
    sign_hmac,
    verify_hmac,
)
from agent_guardian.llm import (
    AnthropicClient,
    BaseLLM,
    BedrockClient,
    GeminiClient,
    LLMAuthError,
    LLMError,
    LLMMessage,
    LLMPermanentError,
    LLMRateLimitError,
    LLMRequest,
    LLMResponse,
    LLMResponseFormatError,
    LLMTimeoutError,
    LLMTransientError,
    LLMUsage,
    OllamaClient,
    OpenAIClient,
    StubLLM,
    StubScript,
    VertexClient,
)
from agent_guardian.models.asi import AsiCategory
from agent_guardian.models.csa import CsaCategory
from agent_guardian.models.finding import Finding
from agent_guardian.models.judge import JudgeVerdict
from agent_guardian.models.probe import (
    Probe,
    ProbeValidationError,
    load_probe,
    load_probes_from_dir,
)
from agent_guardian.models.scan import Scan
from agent_guardian.models.scenario import (
    AgentOrigin,
    DeliveryVector,
    Scenario,
    ScenarioBatch,
    ScenarioType,
)
from agent_guardian.models.severity import (
    Severity,
    SeverityBand,
    band_for_score,
    colour_for_band,
)
from agent_guardian.models.swarm_brief import (
    AgentBrief,
    SubGoal,
    SwarmBrief,
)
from agent_guardian.models.tier import ObservedSurface, Tier
from agent_guardian.probes.loader import (
    PROBE_CORPUS_VERSION,
    load_all_probes,
    load_probes_for_asi,
)
from agent_guardian.reports.canonical import to_canonical_json
from agent_guardian.reports.json_report import (
    SCHEMA_VERSION,
    VerifyResult,
    emit_json,
    sign_payload,
    verify_signatures,
    write_json,
)
from agent_guardian.reports.junit import emit_junit, write_junit
from agent_guardian.reports.markdown import emit_markdown, write_markdown
from agent_guardian.reports.pdf import (
    PdfFeatureUnavailable,
    available_pdf_engines,
    write_pdf,
)
from agent_guardian.reports.sarif import emit_sarif, write_sarif
from agent_guardian.server import ScanStore, create_app
from agent_guardian.strategies.base import (
    NextPrompt,
    Strategy,
    StrategyContext,
    StrategyDone,
    StrategyResult,
    Turn,
)
from agent_guardian.strategies.crescendo import CrescendoStrategy
from agent_guardian.strategies.mad_max import MadMaxStrategy
from agent_guardian.strategies.pair import PAIRStrategy
from agent_guardian.strategies.tap import TAPStrategy

__all__ = [
    "AIVSS_FORMULA_VERSION",
    "DEFAULT_KEYS_DIR",
    "DEFAULT_PBKDF2_ITERATIONS",
    "DEFAULT_SIGNING_SECRET",
    "HMAC_ALGORITHM",
    "PRICE_TABLE",
    "PRICE_TABLE_AS_OF",
    "PROBE_CORPUS_VERSION",
    "SCHEMA_VERSION",
    "SIGNATURE_VERSION",
    "A2AAgent",
    "ADKAdapter",
    "AgentBrief",
    "AgentBudget",
    "AgentOrigin",
    "AgentReport",
    "AivssResult",
    "AnthropicClient",
    "AsiAgent",
    "AsiCategory",
    "AutoGenAdapter",
    "BaseLLM",
    "BedrockClient",
    "BudgetController",
    "BudgetSlice",
    "CascadeAgent",
    "CheckpointDecision",
    "CodeAdapter",
    "CodeExecAgent",
    "CrescendoStrategy",
    "CrewAIAdapter",
    "CsaCategory",
    "DeliveryVector",
    "DriftAgent",
    "Ed25519Keypair",
    "Ed25519SignatureBlock",
    "Finding",
    "FrameworkAdapter",
    "GeminiClient",
    "GoalHijackAgent",
    "HmacSignatureBlock",
    "HttpAdapter",
    "HttpShape",
    "Judge",
    "JudgeRubric",
    "JudgeVerdict",
    "LLMAuthError",
    "LLMError",
    "LLMMessage",
    "LLMPermanentError",
    "LLMRateLimitError",
    "LLMRequest",
    "LLMResponse",
    "LLMResponseFormatError",
    "LLMTimeoutError",
    "LLMTransientError",
    "LLMUsage",
    "LangGraphAdapter",
    "MadMaxStrategy",
    "MemoryFeatureUnavailable",
    "MemoryPoisonAgent",
    "MemoryRecord",
    "MemoryStats",
    "NextPrompt",
    "ObservedSurface",
    "OllamaClient",
    "OpenAIAgentsAdapter",
    "OpenAIClient",
    "PAIRStrategy",
    "PdfFeatureUnavailable",
    "PiiRedactor",
    "PriceRow",
    "PrivilegeAgent",
    "Probe",
    "ProbeValidationError",
    "PromptAdapter",
    "ReconAgent",
    "Sandbox",
    "SandboxPolicy",
    "SandboxViolation",
    "Scan",
    "ScanStore",
    "Scenario",
    "ScenarioBatch",
    "ScenarioType",
    "Severity",
    "SeverityBand",
    "SharedMemory",
    "StrandsAdapter",
    "Strategy",
    "StrategyContext",
    "StrategyDone",
    "StrategyResult",
    "StubLLM",
    "StubScript",
    "SubGoal",
    "SupplyChainAgent",
    "SwarmBrief",
    "SwarmCommander",
    "SwarmConfig",
    "SwarmEvent",
    "SwarmObserver",
    "TAPStrategy",
    "TargetAdapter",
    "TargetFingerprint",
    "TargetMode",
    "Tier",
    "ToolAbuseAgent",
    "TrustExploitAgent",
    "Turn",
    "VectorHit",
    "VerifyResult",
    "VertexClient",
    "__version__",
    "available_pdf_engines",
    "band_for_score",
    "colour_for_band",
    "compute_aivss",
    "create_app",
    "derive_key",
    "detect_tier",
    "emit_json",
    "emit_junit",
    "emit_markdown",
    "emit_sarif",
    "estimate_scan_cost",
    "get_shape",
    "list_shapes",
    "load_all_probes",
    "load_or_create_keypair",
    "load_probe",
    "load_probes_for_asi",
    "load_probes_from_dir",
    "lookup_price",
    "register_shape",
    "sign_ed25519",
    "sign_hmac",
    "sign_payload",
    "to_canonical_json",
    "verify_ed25519",
    "verify_hmac",
    "verify_signatures",
    "write_json",
    "write_junit",
    "write_markdown",
    "write_pdf",
    "write_sarif",
]
