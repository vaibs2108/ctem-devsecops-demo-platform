"""
GuardrailManager — Five-layer safety and quality gate system.

Layer 1: Pydantic structured output validation (with 1 retry)
Layer 2: Content safety — PII detection, prompt injection detection, moderation
Layer 3: Human-in-the-loop (HITL) gate thresholds per use-case / stage
Layer 4: Synthetic data caution indicators
Layer 5: Remediation pre-action safety gate

No raw, unvalidated LLM output is ever shown to the user.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional, Type

from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError, field_validator

load_dotenv(override=True)

logger = logging.getLogger(__name__)

# =====================================================================
# Layer 1 — Pydantic schemas for agent output
# =====================================================================


class MetricCard(BaseModel):
    """A single KPI metric tile displayed in the UI."""

    label: str
    value: str
    delta: str = ""
    colour: str = "#00d4ff"


class AgentOutcome(BaseModel):
    """Validated output schema for every lifecycle-stage agent.

    All four metric cards are mandatory so the UI never renders
    an incomplete dashboard.
    """

    lifecycle_stage: str
    data_source: str
    analysis_markdown: str = Field(min_length=50)
    metrics: List[MetricCard] = Field(min_length=4, max_length=4)
    data_grid: List[dict] = Field(min_length=1, max_length=10)  # type: ignore[type-arg]
    ai_confidence: int = Field(ge=40, le=99)
    confidence_rationale: str

    @field_validator("metrics")
    @classmethod
    def no_placeholder_values(cls, v):
        for card in v:
            if card.value in ("0", "0.0", "N/A", "", "TBD"):
                raise ValueError(f"Placeholder metric value '{card.value}' detected for label '{card.label}'")
        return v


class RemediationAction(BaseModel):
    """A single remediation step for Layer 5 pre-action gate."""

    finding_id: str
    action: str
    target_asset: str
    command: str = ""
    risk_level: str = Field(
        default="medium",
        pattern=r"^(low|medium|high|critical)$",
    )
    requires_approval: bool = True
    impact_assessment: str = ""


class RemediationPlan(BaseModel):
    """Validated remediation plan with mandatory impact assessment."""

    plan_id: str
    use_case: str
    actions: List[RemediationAction] = Field(min_length=1)
    overall_risk: str
    rollback_plan: str = Field(min_length=20)


# =====================================================================
# Layer 2 — Content safety patterns
# =====================================================================

# PII detection patterns
_PII_PATTERNS: Dict[str, re.Pattern[str]] = {
    "email": re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE
    ),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
    "phone_us": re.compile(
        r"\b(?:\+1[-.]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),
    "ip_address": re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ),
}

# Prompt injection / jailbreak indicators
_INJECTION_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?:a|an)\s+(?:evil|unrestricted)", re.IGNORECASE),
    re.compile(r"disregard\s+(?:your|all)\s+(?:rules|guidelines)", re.IGNORECASE),
    re.compile(r"pretend\s+(?:you(?:'re|\s+are)\s+)?(?:not|no\s+longer)\s+an?\s+AI", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*:", re.IGNORECASE),
    re.compile(r"<\|im_start\|>", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"DAN\s+mode", re.IGNORECASE),
]


# =====================================================================
# Layer 3 — HITL thresholds
# =====================================================================

# Structure: { use_case: { stage: { threshold_key: value } } }
_HITL_THRESHOLDS: Dict[str, Dict[str, Dict[str, Any]]] = {
    "ctem": {
        "scoping": {
            "require_approval": False,
            "confidence_threshold": 70,
            "max_auto_findings": 100,
        },
        "discovery": {
            "require_approval": False,
            "confidence_threshold": 65,
            "max_auto_findings": 500,
        },
        "prioritisation": {
            "require_approval": True,
            "confidence_threshold": 80,
            "max_auto_findings": 50,
            "note": "KEV re-ranking decisions require analyst review.",
        },
        "validation": {
            "require_approval": True,
            "confidence_threshold": 85,
            "max_auto_findings": 30,
            "note": "False-positive classification must be analyst-confirmed.",
        },
        "mobilisation": {
            "require_approval": True,
            "confidence_threshold": 90,
            "max_auto_findings": 10,
            "note": "All remediation actions require explicit approval.",
        },
    },
    "hunt": {
        "hypothesis_generation": {
            "require_approval": False,
            "confidence_threshold": 60,
            "max_auto_findings": 20,
        },
        "data_ingestion": {
            "require_approval": False,
            "confidence_threshold": 60,
            "max_auto_findings": 1000,
        },
        "investigation": {
            "require_approval": True,
            "confidence_threshold": 75,
            "max_auto_findings": 50,
        },
        "response": {
            "require_approval": True,
            "confidence_threshold": 85,
            "max_auto_findings": 20,
        },
        "reporting": {
            "require_approval": True,
            "confidence_threshold": 80,
            "max_auto_findings": 10,
        },
    },
    "pentest": {
        "recon": {
            "require_approval": False,
            "confidence_threshold": 60,
            "max_auto_findings": 200,
        },
        "vulnerability_analysis": {
            "require_approval": True,
            "confidence_threshold": 75,
            "max_auto_findings": 100,
        },
        "exploitation": {
            "require_approval": True,
            "confidence_threshold": 90,
            "max_auto_findings": 20,
            "note": "Exploit execution always requires analyst authorisation.",
        },
        "post_exploitation": {
            "require_approval": True,
            "confidence_threshold": 90,
            "max_auto_findings": 10,
        },
        "reporting": {
            "require_approval": True,
            "confidence_threshold": 80,
            "max_auto_findings": 10,
        },
    },
    "detection": {
        "gap_analysis": {
            "require_approval": False,
            "confidence_threshold": 65,
            "max_auto_findings": 100,
        },
        "rule_generation": {
            "require_approval": True,
            "confidence_threshold": 80,
            "max_auto_findings": 50,
            "note": "Generated rules must pass validation before deployment.",
        },
        "testing": {
            "require_approval": True,
            "confidence_threshold": 85,
            "max_auto_findings": 30,
        },
        "tuning": {
            "require_approval": True,
            "confidence_threshold": 80,
            "max_auto_findings": 30,
        },
        "deployment": {
            "require_approval": True,
            "confidence_threshold": 90,
            "max_auto_findings": 10,
            "note": "Production deployment requires explicit sign-off.",
        },
        "monitoring": {
            "require_approval": False,
            "confidence_threshold": 70,
            "max_auto_findings": 200,
        },
    },
}


# =====================================================================
# GuardrailManager
# =====================================================================


class GuardrailManager:
    """Centralised guardrail and safety-gate manager.

    Usage::

        gm = GuardrailManager()

        # Layer 1 — validate LLM output
        outcome = gm.validate_output(raw_json, AgentOutcome)

        # Layer 2 — screen user input
        report = gm.screen_input("ignore previous instructions and ...")

        # Layer 3 — check HITL gate
        needs_human = gm.check_hitl_required("ctem", "mobilisation", findings)
    """

    def __init__(self) -> None:
        self._openai_api_key: str = os.getenv("OPENAI_API_KEY", "")

    # ------------------------------------------------------------------
    # Layer 1 — Pydantic validation (with 1 retry via LLM)
    # ------------------------------------------------------------------

    def validate_output(
        self,
        raw_output: Any,
        schema: Type[BaseModel],
        retry_llm: Optional[Any] = None,
    ) -> BaseModel:
        """Validate *raw_output* against *schema*.

        If validation fails on the first attempt and a ``retry_llm`` callable
        is provided, it will be called once with the validation errors to let
        the LLM self-correct.

        Args:
            raw_output: Dict or JSON string from the LLM.
            schema: The Pydantic model class.
            retry_llm: Optional callable ``(messages) -> dict`` for retry.

        Returns:
            A validated Pydantic model instance.

        Raises:
            ValueError: After 2 failed validation attempts.
        """
        # Attempt 1 — direct parse
        last_error: Optional[Exception] = None
        for attempt in range(2):
            try:
                if isinstance(raw_output, str):
                    return schema.model_validate_json(raw_output)
                elif isinstance(raw_output, dict):
                    return schema.model_validate(raw_output)
                elif isinstance(raw_output, BaseModel):
                    # Already validated (e.g. from with_structured_output)
                    return schema.model_validate(raw_output.model_dump())
                else:
                    raise TypeError(
                        f"Unsupported raw_output type: {type(raw_output)}"
                    )
            except (ValidationError, TypeError) as exc:
                last_error = exc
                logger.warning(
                    "Validation attempt %d failed: %s", attempt + 1, exc
                )

                if attempt == 0 and retry_llm is not None:
                    # Ask the LLM to fix its output
                    retry_messages = [
                        {
                            "role": "system",
                            "content": (
                                "The previous output failed Pydantic validation. "
                                "Fix the JSON to match the schema. Return ONLY "
                                "the corrected JSON."
                            ),
                        },
                        {
                            "role": "human",
                            "content": (
                                f"Schema: {schema.model_json_schema()}\n\n"
                                f"Errors: {exc}\n\n"
                                f"Original output: {raw_output}"
                            ),
                        },
                    ]
                    try:
                        retry_result = retry_llm(retry_messages)
                        raw_output = retry_result.get(
                            "content", retry_result
                        )
                    except Exception as retry_exc:
                        logger.error("Retry LLM call failed: %s", retry_exc)

        raise ValueError(
            f"Output validation failed after 2 attempts: {last_error}"
        )

    # ------------------------------------------------------------------
    # Layer 2 — Content safety screening
    # ------------------------------------------------------------------

    def screen_input(self, text: str) -> Dict[str, Any]:
        """Screen user input for PII, prompt injection, and moderation.

        Args:
            text: The raw user input string.

        Returns:
            Dict with keys:
            - ``safe`` (bool): overall safety verdict
            - ``pii_detected`` (list of dicts): PII matches found
            - ``injection_detected`` (bool): prompt injection attempt
            - ``injection_patterns`` (list of str): matched patterns
            - ``moderation`` (dict): OpenAI moderation result (if available)
        """
        result: Dict[str, Any] = {
            "safe": True,
            "pii_detected": [],
            "injection_detected": False,
            "injection_patterns": [],
            "moderation": {},
        }

        # --- PII scan ---
        for pii_type, pattern in _PII_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                result["pii_detected"].append({
                    "type": pii_type,
                    "count": len(matches),
                    "samples": matches[:3],  # Don't log all PII
                })

        if result["pii_detected"]:
            result["safe"] = False
            logger.warning(
                "PII detected in input: %s",
                [p["type"] for p in result["pii_detected"]],
            )

        # --- Prompt injection scan ---
        for pattern in _INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                result["injection_detected"] = True
                result["injection_patterns"].append(match.group())

        if result["injection_detected"]:
            result["safe"] = False
            logger.warning(
                "Prompt injection detected: %s", result["injection_patterns"]
            )

        # --- OpenAI Moderation (best-effort) ---
        if self._openai_api_key:
            try:
                import openai

                client = openai.OpenAI(api_key=self._openai_api_key)
                mod_resp = client.moderations.create(input=text)
                mod_result = mod_resp.results[0]
                result["moderation"] = {
                    "flagged": mod_result.flagged,
                    "categories": {
                        k: v
                        for k, v in mod_result.categories.model_dump().items()
                        if v
                    },
                }
                if mod_result.flagged:
                    result["safe"] = False
                    logger.warning("OpenAI moderation flagged input.")
            except Exception:
                logger.debug("Moderation API call failed — skipping.")

        return result

    def screen_output(self, text: str) -> Dict[str, Any]:
        """Screen LLM output for safety issues.

        Same logic as ``screen_input`` but applied to model responses.
        """
        return self.screen_input(text)

    # ------------------------------------------------------------------
    # Layer 3 — HITL gates
    # ------------------------------------------------------------------

    def get_hitl_thresholds(
        self, use_case: str, stage: str
    ) -> Dict[str, Any]:
        """Return the HITL threshold config for a use-case / stage pair.

        Returns a default permissive config if the pair is not registered.
        """
        default: Dict[str, Any] = {
            "require_approval": False,
            "confidence_threshold": 60,
            "max_auto_findings": 100,
        }
        return (
            _HITL_THRESHOLDS
            .get(use_case, {})
            .get(stage, default)
        )

    def check_hitl_required(
        self,
        use_case: str,
        stage: str,
        findings: Optional[List[Any]] = None,
        ai_confidence: Optional[int] = None,
    ) -> bool:
        """Determine whether human approval is required.

        HITL is required if ANY of:
        1. Condition matching the use-case/stage evaluates to True.
        2. AI confidence is below the use-case floor.
        3. Number of findings exceeds ``max_auto_findings``.

        Args:
            use_case: Use-case label (``ctem``, ``hunt``, etc.).
            stage: Lifecycle stage label.
            findings: List of finding dicts/objects from the analysis.
            ai_confidence: The AI's self-reported confidence score (0–100).

        Returns:
            ``True`` if human review is required.
        """
        # --- Version 5.0 Condition Evaluation ---
        normalized_key = f"{use_case.lower()}_{stage.lower()}"
        stage_mappings = {
            ("ctem", "validation"): "ctem_stage4",
            ("hunt", "response"): "hunt_stage4",
            ("hunt", "validation"): "hunt_stage4",
            ("pentest", "exploitation"): "pentest_stage3",
            ("detection", "testing"): "detection_stage3",
            ("detection", "evaluation"): "detection_stage3",
            ("detection", "rule_evaluation"): "detection_stage3",
        }
        matched_threshold_key = stage_mappings.get((use_case.lower(), stage.lower()), normalized_key)
        
        V5_THRESHOLDS = {
            "ctem_stage4": {
                "condition": "exploitability_confirmed AND cvss >= 9.0",
                "confidence_floor": 85
            },
            "hunt_stage4": {
                "condition": "conclusion == Confirmed AND severity == Critical",
                "confidence_floor": 85
            },
            "pentest_stage3": {
                "condition": "chain_severity == Critical",
                "confidence_floor": 85
            },
            "detection_stage3": {
                "condition": "gap_priority == P1 AND active_threat_actor",
                "confidence_floor": 80
            },
        }

        if matched_threshold_key in V5_THRESHOLDS:
            config = V5_THRESHOLDS[matched_threshold_key]
            conf_floor = config.get("confidence_floor", 80)
            
            # 1. Check confidence floor
            if ai_confidence is not None and ai_confidence < conf_floor:
                logger.info("HITL triggered: AI confidence %d < floor %d", ai_confidence, conf_floor)
                return True
                
            # 2. Check findings condition
            if findings:
                for f in findings:
                    if not isinstance(f, dict):
                        continue
                    
                    if matched_threshold_key == "ctem_stage4":
                        exp_confirmed = f.get("exploitability_confirmed", False) or f.get("exploit_confirmed", False)
                        if not exp_confirmed and "confirmed" in str(f).lower():
                            exp_confirmed = True
                        
                        cvss_val = f.get("cvss", f.get("cvss_score", 0.0))
                        if not cvss_val and f.get("severity", "").upper() == "CRITICAL":
                            cvss_val = 9.5
                        
                        if exp_confirmed and cvss_val >= 9.0:
                            logger.info("HITL triggered by ctem_stage4 condition: %s", f)
                            return True
                            
                    elif matched_threshold_key == "hunt_stage4":
                        conclusion = str(f.get("conclusion", "")).upper()
                        severity = str(f.get("severity", "")).upper()
                        if (conclusion == "CONFIRMED" or "CONFIRMED" in str(f).upper()) and (severity == "CRITICAL" or "CRITICAL" in str(f).upper()):
                            logger.info("HITL triggered by hunt_stage4 condition: %s", f)
                            return True
                            
                    elif matched_threshold_key == "pentest_stage3":
                        chain_severity = str(f.get("chain_severity", f.get("severity", ""))).upper()
                        if chain_severity == "CRITICAL":
                            logger.info("HITL triggered by pentest_stage3 condition: %s", f)
                            return True
                            
                    elif matched_threshold_key == "detection_stage3":
                        gap_prio = str(f.get("gap_priority", f.get("priority", ""))).upper()
                        active_actor = f.get("active_threat_actor", False) or f.get("threat_actor", False) or "actor" in str(f).lower()
                        if gap_prio == "P1" and active_actor:
                            logger.info("HITL triggered by detection_stage3 condition: %s", f)
                            return True

        # Fallback to standard check if no matching V5 threshold or conditions not met
        thresholds = self.get_hitl_thresholds(use_case, stage)

        if thresholds.get("require_approval", False):
            return True

        if ai_confidence is not None:
            threshold = thresholds.get("confidence_threshold", 60)
            if ai_confidence < threshold:
                logger.info(
                    "HITL triggered: confidence %d < threshold %d",
                    ai_confidence,
                    threshold,
                )
                return True

        if findings is not None:
            max_auto = thresholds.get("max_auto_findings", 100)
            if len(findings) > max_auto:
                logger.info(
                    "HITL triggered: %d findings > max_auto %d",
                    len(findings),
                    max_auto,
                )
                return True

        return False

    # ------------------------------------------------------------------
    # Layer 4 — Synthetic data watermark check
    # ------------------------------------------------------------------

    @staticmethod
    def is_synthetic_data(data_source: str) -> bool:
        """Check whether the data source is synthetic."""
        return data_source.lower() in ("synthetic", "demo", "generated")

    @staticmethod
    def get_synthetic_caution_banner(data_source: str) -> Optional[str]:
        """Return a caution banner if data is synthetic, else ``None``."""
        if data_source.lower() in ("synthetic", "demo", "generated"):
            return (
                "⚠️ **Synthetic Data** — This analysis uses AI-generated "
                "demonstration data. Results illustrate platform capabilities "
                "and do not represent real security findings."
            )
        return None

    # ------------------------------------------------------------------
    # Layer 5 — Remediation pre-action gate
    # ------------------------------------------------------------------

    def validate_remediation_plan(
        self, plan: Dict[str, Any]
    ) -> RemediationPlan:
        """Validate a remediation plan before execution.

        Ensures every action has an impact assessment and all critical/high
        actions require approval.

        Args:
            plan: Raw remediation plan dict.

        Returns:
            Validated ``RemediationPlan`` instance.

        Raises:
            ValueError: If validation fails.
        """
        validated = self.validate_output(plan, RemediationPlan)
        assert isinstance(validated, RemediationPlan)

        # Enforce approval for critical/high actions
        for action in validated.actions:
            if action.risk_level in ("critical", "high"):
                action.requires_approval = True
            if not action.impact_assessment:
                action.impact_assessment = (
                    "Impact assessment pending — manual review required."
                )

        return validated

    def check_remediation_gate(
        self,
        plan: RemediationPlan,
        approved_action_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Check whether a remediation plan is cleared for execution.

        Returns:
            Dict with ``cleared`` (bool), ``pending_approvals`` (list),
            ``auto_execute`` (list).
        """
        approved = set(approved_action_ids or [])
        pending: List[str] = []
        auto_exec: List[str] = []

        for action in plan.actions:
            if action.requires_approval and action.finding_id not in approved:
                pending.append(action.finding_id)
            else:
                auto_exec.append(action.finding_id)

        return {
            "cleared": len(pending) == 0,
            "pending_approvals": pending,
            "auto_execute": auto_exec,
            "total_actions": len(plan.actions),
        }
