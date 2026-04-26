from __future__ import annotations

import inspect
import json
import logging
import uuid
from dataclasses import asdict
from typing import Any, Dict, Mapping, Optional

from config import DeliberationConfig, EngagementContext
from consensus import synthesize_consensus
from findings import (
    AuditTrailEntry,
    StageFindings,
    UnifiedFindings,
    stage_findings_from_dict,
)

LOGGER = logging.getLogger(__name__)
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


class DeliberationSession:
    def __init__(
        self,
        context: EngagementContext,
        phantom_engine: Any,
        oracle_engine: Any,
        covenant_engine: Any,
        config: DeliberationConfig = DeliberationConfig(),
    ):
        context.validate()
        self.context = context
        self.config = config
        self.engines = {
            "PHANTOM": phantom_engine,
            "ORACLE": oracle_engine,
            "COVENANT": covenant_engine,
        }
        self.session_id = str(uuid.uuid4())
        self._audit: list[AuditTrailEntry] = []
        self._token_spend: Dict[str, int] = {}
        self._warnings: list[str] = []
        self._errors: list[str] = []
        self._results: Dict[str, StageFindings] = {}
        self._spent_total = 0

    def run(self) -> Dict[str, Any]:
        self._run_stage_sync("PHANTOM")
        self._run_stage_sync("ORACLE")
        self._run_stage_sync("COVENANT")
        return self._finalize()

    async def run_async(self) -> Dict[str, Any]:
        await self._run_stage_async("PHANTOM")
        await self._run_stage_async("ORACLE")
        await self._run_stage_async("COVENANT")
        return self._finalize()

    def _build_context(self, stage: str) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "session_id": self.session_id,
            "engagement_type": self.context.engagement_type,
            "analysis_depth": self.context.analysis_depth,
            "target_system": self.context.target_system,
        }
        if stage in ("ORACLE", "COVENANT"):
            payload["phantom"] = (
                asdict(self._results["PHANTOM"]) if "PHANTOM" in self._results else None
            )
        if stage == "COVENANT":
            payload["oracle"] = (
                asdict(self._results["ORACLE"]) if "ORACLE" in self._results else None
            )
        return payload

    def _validate_context(self, stage: str) -> None:
        if stage in ("ORACLE", "COVENANT") and "PHANTOM" not in self._results:
            raise ValueError("ORACLE/COVENANT require PHANTOM findings")
        if stage == "COVENANT" and "ORACLE" not in self._results:
            raise ValueError("COVENANT requires ORACLE findings")

    def _estimate_tokens(self, payload: Mapping[str, Any]) -> int:
        text = json.dumps(payload, sort_keys=True, default=str)
        return max(1, len(text) // 4)

    def _consume_budget(self, stage: str, payload_tokens: int, result: Mapping[str, Any]) -> bool:
        usage = result.get("token_usage") if isinstance(result, Mapping) else None
        result_tokens = 0
        if isinstance(usage, Mapping):
            result_tokens = int(usage.get("total", usage.get("output", 0)) or 0)
        if result_tokens <= 0:
            result_tokens = self._estimate_tokens(result if isinstance(result, Mapping) else {})
        stage_tokens = payload_tokens + result_tokens
        projected = self._spent_total + stage_tokens
        if projected > self.config.token_limit_total:
            msg = (
                f"Token limit exceeded before completing {stage}: "
                f"{projected}>{self.config.token_limit_total}"
            )
            LOGGER.warning(msg)
            self._warnings.append(msg)
            self._errors.append(msg)
            return False
        self._token_spend[stage] = stage_tokens
        self._spent_total = projected
        if self._spent_total >= int(self.config.token_limit_total * self.config.token_warning_threshold):
            warn = (
                f"Token budget warning: spent {self._spent_total}/"
                f"{self.config.token_limit_total}"
            )
            if warn not in self._warnings:
                LOGGER.warning(warn)
                self._warnings.append(warn)
        return True

    def _append_audit(self, stage: str, event: str, payload: Mapping[str, Any]) -> None:
        prev_hash = self._audit[-1].entry_hash if self._audit else "0" * 64
        entry = AuditTrailEntry.create(
            index=len(self._audit), stage=stage, event=event, payload=payload, prev_hash=prev_hash
        )
        self._audit.append(entry)

    def _engine_invoke_sync(self, stage: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        engine = self.engines[stage]
        if hasattr(engine, "analyze"):
            return engine.analyze(payload)
        if callable(engine):
            return engine(payload)
        raise TypeError(f"{stage} engine is not callable")

    async def _engine_invoke_async(self, stage: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        engine = self.engines[stage]
        if hasattr(engine, "analyze_async"):
            return await engine.analyze_async(payload)
        if hasattr(engine, "analyze"):
            maybe = engine.analyze(payload)
            if inspect.isawaitable(maybe):
                return await maybe
            return maybe
        if callable(engine):
            maybe = engine(payload)
            if inspect.isawaitable(maybe):
                return await maybe
            return maybe
        raise TypeError(f"{stage} engine is not callable")

    def _process_stage_output(self, stage: str, output: Any) -> Optional[StageFindings]:
        if output is None:
            self._errors.append(f"{stage} produced no output")
            return None
        if isinstance(output, StageFindings):
            findings = output
        elif isinstance(output, Mapping):
            findings = stage_findings_from_dict(stage, output)
        else:
            self._errors.append(f"{stage} output format unsupported")
            return None
        self._results[stage] = findings
        self._append_audit(stage, "COMPLETED", asdict(findings))
        return findings

    def _run_stage_sync(self, stage: str) -> None:
        if self._errors and "Token limit exceeded" in self._errors[-1]:
            return
        try:
            self._validate_context(stage)
            payload = self._build_context(stage)
            payload_tokens = self._estimate_tokens(payload)
            self._append_audit(stage, "START", payload)
            output = self._engine_invoke_sync(stage, payload)
            output_map = output if isinstance(output, Mapping) else {}
            if not self._consume_budget(stage, payload_tokens, output_map):
                return
            self._process_stage_output(stage, output)
        except Exception as exc:  # noqa: BLE001
            msg = f"{stage} failure: {exc}"
            LOGGER.exception(msg)
            self._errors.append(msg)
            self._append_audit(stage, "FAILED", {"error": msg})

    async def _run_stage_async(self, stage: str) -> None:
        if self._errors and "Token limit exceeded" in self._errors[-1]:
            return
        try:
            self._validate_context(stage)
            payload = self._build_context(stage)
            payload_tokens = self._estimate_tokens(payload)
            self._append_audit(stage, "START", payload)
            output = await self._engine_invoke_async(stage, payload)
            output_map = output if isinstance(output, Mapping) else {}
            if not self._consume_budget(stage, payload_tokens, output_map):
                return
            self._process_stage_output(stage, output)
        except Exception as exc:  # noqa: BLE001
            msg = f"{stage} failure: {exc}"
            LOGGER.exception(msg)
            self._errors.append(msg)
            self._append_audit(stage, "FAILED", {"error": msg})

    def _finalize(self) -> Dict[str, Any]:
        findings = UnifiedFindings(
            session_id=self.session_id,
            phantom=self._results.get("PHANTOM"),
            oracle=self._results.get("ORACLE"),
            covenant=self._results.get("COVENANT"),
            token_spend=dict(self._token_spend),
            audit_trail=tuple(self._audit),
            warnings=tuple(self._warnings),
            errors=tuple(self._errors),
        )
        consensus = synthesize_consensus(findings)
        return {
            "session_id": self.session_id,
            "findings": findings.to_dict(),
            "consensus": asdict(consensus),
            "completed_stages": tuple(stage for stage in ("PHANTOM", "ORACLE", "COVENANT") if stage in self._results),
            "errors": list(self._errors),
            "warnings": list(self._warnings),
        }
