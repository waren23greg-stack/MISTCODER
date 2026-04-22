from __future__ import annotations

from dataclasses import dataclass

TOKEN_LIMIT_TOTAL = 8_000
TOKEN_WARNING_THRESHOLD = 0.85

ENGAGEMENT_TYPES = (
    "threat_model",
    "arch_review",
    "red_team_lab",
    "code_audit",
    "cloud_assess",
    "api_sec",
)

ANALYSIS_DEPTHS = ("rapid", "deep", "apex")


@dataclass(frozen=True)
class EngagementContext:
    engagement_type: str
    analysis_depth: str
    target_system: str

    def validate(self) -> None:
        if self.engagement_type not in ENGAGEMENT_TYPES:
            raise ValueError(f"Unsupported engagement type: {self.engagement_type}")
        if self.analysis_depth not in ANALYSIS_DEPTHS:
            raise ValueError(f"Unsupported analysis depth: {self.analysis_depth}")
        if not self.target_system or not self.target_system.strip():
            raise ValueError("target_system must be non-empty")


@dataclass(frozen=True)
class DeliberationConfig:
    token_limit_total: int = TOKEN_LIMIT_TOTAL
    token_warning_threshold: float = TOKEN_WARNING_THRESHOLD
