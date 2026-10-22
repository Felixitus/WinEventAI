"""AI layer: works exclusively on the condensed finding."""

from .bundles import FindingBundle, SystemContext, build_bundle, estimate_tokens, fit_to_budget
from .client import (
    CloudCallBlockedError,
    ModelReply,
    OllamaClient,
    OllamaUnavailableError,
    assert_local,
)
from .pipeline import AiFindingResult, AiLayer, AiRunResult
from .redaction import Redactor
from .schema import (
    CorrelatorOutput,
    Evidence,
    ExplainerOutput,
    Statement,
    json_schema_for,
)
from .verify import VerificationReport, verify_correlator, verify_explainer

__all__ = [
    "AiFindingResult",
    "AiLayer",
    "AiRunResult",
    "CloudCallBlockedError",
    "CorrelatorOutput",
    "Evidence",
    "ExplainerOutput",
    "FindingBundle",
    "ModelReply",
    "OllamaClient",
    "OllamaUnavailableError",
    "Redactor",
    "Statement",
    "SystemContext",
    "VerificationReport",
    "assert_local",
    "build_bundle",
    "estimate_tokens",
    "fit_to_budget",
    "json_schema_for",
    "verify_correlator",
    "verify_explainer",
]
