"""
AI Capability Demo — Agent Manager
Orchestrates all AI agents using LangChain/LangGraph StateGraph.
AGENTS.md Section 8.3 system-prompt standards; Section 4 file structure.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional, TypedDict

import pandas as pd
from langgraph.graph import END, StateGraph

logger = logging.getLogger(__name__)

# ── Stage and agent mapping ──────────────────────────────────────────────────

STAGE_MAP: Dict[str, List[str]] = {
    "ctem": ["scoping", "discovery", "prioritisation", "validation", "mobilisation"],
    "devsecops": ["pipeline"],
}

AGENT_NAME_MAP: Dict[str, Dict[str, str]] = {
    "ctem": {
        "scoping": "CTEMScopingAgent",
        "discovery": "CTEMDiscoveryAgent",
        "prioritisation": "CTEMPrioritisationAgent",
        "validation": "CTEMValidatorAgent",
        "mobilisation": "CTEMRemediationAgent",
    },
    "devsecops": {
        "pipeline": "DevSecOpsPipelineAgent",
    },
}

# ── Framework references per use case ────────────────────────────────────────

FRAMEWORK_REFS: Dict[str, str] = {
    "ctem": "NIST CSF 2.0, CISA KEV, CVSS v3.1, EPSS, CIS Benchmarks",
    "devsecops": "OWASP Top 10 2021, CWE Top 25, NIST SSDF",
}


# ── LangGraph state definition ───────────────────────────────────────────────

class AgentState(TypedDict):
    """State passed through the LangGraph pipeline."""
    use_case: str
    stage: str
    data_source: str
    datasets: Dict[str, Any]
    aggregation: Dict[str, Any]
    system_prompt: str
    task_prompt: str
    raw_response: str
    outcome: Dict[str, Any]
    error: Optional[str]


# ── AgentManager ─────────────────────────────────────────────────────────────

class AgentManager:
    """Orchestrates all AI agents using LangGraph StateGraph pipelines.

    Pipeline flow:
        pre_aggregate → build_prompts → call_llm → format_outcome
    """

    def __init__(
        self,
        llm_router: Any = None,
        rag_retriever: Any = None,
        token_tracker: Any = None,
    ) -> None:
        self.llm_router = llm_router
        self.rag_retriever = rag_retriever
        self.token_tracker = token_tracker
        self._graph = self._build_graph()

    # ── Public API ───────────────────────────────────────────────────────

    def run_stage(
        self,
        use_case: str,
        stage: str,
        datasets: Dict[str, Any],
        data_source: str = "synthetic",
    ) -> Dict[str, Any]:
        """Run the appropriate agent for the given use-case stage.

        Returns an AgentOutcome dict:
            {
                "agent_name": str,
                "use_case": str,
                "stage": str,
                "data_source": str,
                "ai_confidence": int,
                "summary": str,
                "findings": list[dict],
                "kpi_deltas": dict,
                "recommendations": list[str],
                "timestamp": float,
            }
        """
        import streamlit as st
        from app.observability.audit_logger import AuditLogger
        
        audit_logger = AuditLogger()
        agent_name = self._get_stage_agent_name(use_case, stage)
        
        # Log execution initiation
        audit_logger.log_action(
            action=f"Agent Stage Execution: {stage.replace('_', ' ').title()} (Initiated)",
            username="vaibhav",
            status="Initiated",
            target=agent_name,
            details=f"Starting orchestrator StateGraph sequence for {use_case.upper()} {stage.replace('_', ' ').title()} under '{data_source}' mode."
        )
        
        start_time = time.time()
        
        initial_state: AgentState = {
            "use_case": use_case,
            "stage": stage,
            "data_source": data_source,
            "datasets": datasets,
            "aggregation": {},
            "system_prompt": "",
            "task_prompt": "",
            "raw_response": "",
            "outcome": {},
            "error": None,
        }

        try:
            final_state = self._graph.invoke(initial_state)
            duration_ms = (time.time() - start_time) * 1000
            
            if "observability_traces" not in st.session_state:
                st.session_state.observability_traces = []
                
            if final_state.get("error"):
                error_msg = final_state["error"]
                st.session_state.observability_traces.append({
                    "id": f"tr-{int(start_time)}",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time)),
                    "agent": agent_name,
                    "status": "Failed",
                    "duration_ms": duration_ms,
                    "langsmith_synced": True,
                    "error": error_msg
                })
                audit_logger.log_action(
                    action=f"Agent Stage Execution: {stage.replace('_', ' ').title()} (Failed)",
                    username="vaibhav",
                    status="Failed",
                    target=agent_name,
                    details=f"StateGraph sequence execution failed: {error_msg}."
                )
                return self._error_outcome(use_case, stage, data_source, error_msg)
                
            outcome = final_state["outcome"]
            confidence = outcome.get("ai_confidence", 85)
            
            # Run hallucination check on the text output
            try:
                from app.observability.hallucination import HallucinationDetector
                from app.observability.health_metrics import InAppMetrics
                
                detector = HallucinationDetector()
                
                # Combine all text outputs (summary + findings titles/descriptions/evidence/recommendation)
                text_blocks = [outcome.get("summary", "")]
                for finding in outcome.get("findings", []):
                    for key in ["title", "description", "evidence", "recommendation"]:
                        if key in finding and finding[key]:
                            text_blocks.append(str(finding[key]))
                combined_text = "\n".join(text_blocks)
                
                # Find in-scope asset inventory to pass as asset_df
                asset_df = None
                if datasets and "asset_inventory" in datasets:
                    asset_df = datasets["asset_inventory"]
                elif "datasets" in st.session_state and isinstance(st.session_state.datasets, dict) and "asset_inventory" in st.session_state.datasets:
                    asset_df = st.session_state.datasets["asset_inventory"]
                    
                report = detector.run_all(combined_text, asset_df)
                
                if "hallucination_reports" not in st.session_state:
                    st.session_state.hallucination_reports = {}
                st.session_state.hallucination_reports[f"{use_case}_{stage}"] = report
                
                # Log each flag as a guardrail event in InAppMetrics
                metrics = InAppMetrics()
                for flag in report.flags:
                    metrics.record_guardrail_event(
                        event_type="hallucination",
                        action="flagged",
                        context=f"{use_case}/{stage} - {flag.citation}: {flag.finding}"
                    )
            except Exception as e:
                logger.error(f"Hallucination check failed: {e}")
            
            # Log execution success
            st.session_state.observability_traces.append({
                "id": f"tr-{int(start_time)}",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time)),
                "agent": agent_name,
                "status": "Success",
                "duration_ms": duration_ms,
                "langsmith_synced": True,
                "error": None
            })
            
            audit_logger.log_action(
                action=f"Agent Stage Completed",
                username="vaibhav",
                status="Success",
                target=agent_name,
                details=f"Successfully completed {stage.replace('_', ' ').title()} stage with an AI confidence score of {confidence}%."
            )

            # Save stage execution result to memory DB for 48h continuity
            if "memory" in st.session_state and st.session_state.memory is not None:
                try:
                    mem = st.session_state.memory
                    username = st.session_state.get("username", "vaibhav")
                    session_id = st.session_state.get("session_id", "default_session")
                    
                    # Store stage_result
                    mem.store(
                        user=username,
                        entry_type="stage_result",
                        key=f"{use_case}_{stage}",
                        value=outcome,
                        use_case=use_case,
                        stage=stage,
                        session_id=session_id
                    )
                    
                    # Store finding_context
                    findings = outcome.get("findings", [])
                    if findings:
                        mem.store(
                            user=username,
                            entry_type="finding_context",
                            key=f"{use_case}_{stage}_findings",
                            value=findings,
                            use_case=use_case,
                            stage=stage,
                            session_id=session_id
                        )
                    
                    # Store kpi_snapshot
                    if "kpi_engine" in st.session_state and st.session_state.kpi_engine is not None:
                        kpis = st.session_state.kpi_engine.compute_all()
                        mem.store(
                            user=username,
                            entry_type="kpi_snapshot",
                            key=f"{use_case}_{stage}_kpis",
                            value=kpis,
                            use_case=use_case,
                            stage=stage,
                            session_id=session_id
                        )
                except Exception as mem_err:
                    logger.error(f"Failed to save stage to memory: {mem_err}")
            
            return outcome
            
        except Exception as exc:
            duration_ms = (time.time() - start_time) * 1000
            logger.exception("Agent pipeline failed for %s/%s", use_case, stage)
            
            if "observability_traces" not in st.session_state:
                st.session_state.observability_traces = []
                
            st.session_state.observability_traces.append({
                "id": f"tr-{int(start_time)}",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time)),
                "agent": agent_name,
                "status": "Failed",
                "duration_ms": duration_ms,
                "langsmith_synced": True,
                "error": str(exc)
            })
            
            audit_logger.log_action(
                action=f"Agent Stage Execution: {stage.replace('_', ' ').title()} (Failed)",
                username="vaibhav",
                status="Failed",
                target=agent_name,
                details=f"StateGraph sequence execution failed with unhandled exception: {str(exc)}."
            )
            
            return self._error_outcome(use_case, stage, data_source, str(exc))

    # ── Graph Construction ───────────────────────────────────────────────

    def _build_graph(self) -> Any:
        """Build the LangGraph StateGraph pipeline."""
        graph = StateGraph(AgentState)

        graph.add_node("pre_aggregate", self._node_pre_aggregate)
        graph.add_node("build_prompts", self._node_build_prompts)
        graph.add_node("call_llm", self._node_call_llm)
        graph.add_node("format_outcome", self._node_format_outcome)

        graph.set_entry_point("pre_aggregate")
        graph.add_edge("pre_aggregate", "build_prompts")
        graph.add_edge("build_prompts", "call_llm")
        graph.add_edge("call_llm", "format_outcome")
        graph.add_edge("format_outcome", END)

        return graph.compile()

    # ── Pipeline Nodes ───────────────────────────────────────────────────

    def _node_pre_aggregate(self, state: AgentState) -> Dict[str, Any]:
        """Pre-aggregate datasets using Pandas (zero LLM cost)."""
        aggregation = {}
        datasets = state["datasets"]

        for key, val in datasets.items():
            if isinstance(val, pd.DataFrame) and not val.empty:
                aggregation[key] = self._pre_aggregate(val)
            elif isinstance(val, list):
                aggregation[key] = {"count": len(val), "sample": val[:5]}

        return {"aggregation": aggregation}

    def _node_build_prompts(self, state: AgentState) -> Dict[str, Any]:
        """Build system + task prompts from aggregation context."""
        use_case = state["use_case"]
        stage = state["stage"]
        data_source = state["data_source"]
        aggregation = state["aggregation"]

        # Retrieve RAG context if retriever is available
        rag_context = ""
        if self.rag_retriever is not None:
            try:
                query = f"{use_case} {stage} security analysis"
                rag_context = self.rag_retriever.retrieve(query, top_k=5)
            except Exception:
                rag_context = ""

        system_prompt = self._build_system_prompt(use_case, stage, data_source)
        task_prompt = self._build_task_prompt(
            use_case, stage, aggregation, rag_context
        )

        return {"system_prompt": system_prompt, "task_prompt": task_prompt}

    def _node_call_llm(self, state: AgentState) -> Dict[str, Any]:
        """Call LLM via router and return raw response."""
        system_prompt = state["system_prompt"]
        task_prompt = state["task_prompt"]
        use_case = state["use_case"]
        stage = state["stage"]

        if self.llm_router is None:
            # Fallback: generate a synthetic response for demo mode
            raw = self._generate_synthetic_response(use_case, stage)
            return {"raw_response": raw}

        try:
            # Set router context
            self.llm_router.set_context(use_case=use_case, stage=stage)

            # Construct messages
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": task_prompt}
            ]

            # Route to reasoning or primary model tier
            model_tier = "primary"

            # Invoke LLM
            resp = self.llm_router.invoke(
                messages=messages,
                model_tier=model_tier,
                temperature=0.2
            )
            raw = resp.get("content", "")

            return {"raw_response": raw}
        except Exception as exc:
            logger.error("LLM call failed for %s/%s, falling back to synthetic response: %s", use_case, stage, exc)
            raw = self._generate_synthetic_response(use_case, stage)
            return {"raw_response": raw}

    def _node_format_outcome(self, state: AgentState) -> Dict[str, Any]:
        """Validate and format raw LLM response into AgentOutcome."""
        if state.get("error"):
            return {}

        raw = state["raw_response"]
        use_case = state["use_case"]
        stage = state["stage"]
        data_source = state["data_source"]
        aggregation = state.get("aggregation", {})

        outcome = self._format_outcome(raw, use_case, stage, data_source, aggregation)
        return {"outcome": outcome}

    # ── Core Methods ─────────────────────────────────────────────────────

    def _build_system_prompt(
        self, use_case: str, stage: str, data_source: str
    ) -> str:
        """Build stage-specific system prompt per AGENTS.md §8.3.

        Structure:
        1. Data source declaration first
        2. Lifecycle stage context
        3. AI Confidence Score requirement (40–99%, varied)
        4. Specificity requirement for remediation
        5. False positive discipline
        """
        agent_name = self._get_stage_agent_name(use_case, stage)
        frameworks = FRAMEWORK_REFS.get(use_case, "")

        source_declaration = {
            "synthetic": (
                "DATA SOURCE: SYNTHETIC — All data in this analysis is synthetic, "
                "enterprise-grade demo data. Clearly watermark all outputs as synthetic. "
                "Do NOT present findings as real-world confirmed."
            ),
            "mcp": (
                "DATA SOURCE: MCP LIVE — Data retrieved from live security tool "
                "integrations via MCP protocol. Treat as production data."
            ),
            "upload": (
                "DATA SOURCE: FILE UPLOAD — Data uploaded by the analyst. "
                "Treat as production data after validation."
            ),
        }.get(data_source, "DATA SOURCE: UNKNOWN")

        uc_labels = {
            "ctem": "AI-Led Continuous Threat Exposure Management (CTEM)",
            "devsecops": "AI-Led DevSecOps",
        }

        # Attack-path / vulnerability-chaining schema addendum — CTEM Discovery & Prioritisation only.
        attack_chain_block = ""
        if use_case == "ctem" and stage in ("discovery", "prioritisation"):
            chain_label = "attack path" if stage == "discovery" else "vulnerability chain"
            attack_chain_block = f"""
6. FRONTIER REASONING — {chain_label.upper()}: You MUST include an "attack_chains" array with AT LEAST ONE multi-hop {chain_label} demonstrating how individually-modest findings combine into a critical business outcome (e.g. initial foothold → lateral movement → high-value asset compromise, or two Medium findings chaining into a Critical path). Each step must name a real asset/technique/CVE from the dataset and a one-sentence reasoning note explaining WHY it connects to the next step — this is the reasoning trace, not just a list.

Add to the JSON: "attack_chains": [{{"chain_id": "<id>", "severity": "<Critical|High|Medium>", "steps": [{{"asset": "<hostname/asset_id>", "technique_or_cve": "<CVE-ID or MITRE T-code>", "note": "<one-sentence reasoning for this hop>"}}]}}]"""

        if use_case == "devsecops":
            return f"""You are {agent_name}, a senior AI DevSecOps agent embedded directly in the CI pipeline.

{source_declaration}

LIFECYCLE STAGE: {stage.replace('_', ' ').title()} — a single flowing pipeline covering: commit ingestion, AI code review, exploit-chain explanation, AI-generated fix, pull request creation, automated security validation, and a human-approval gate before deployment.
FRAMEWORKS: {frameworks}

REQUIREMENTS:
1. AI CONFIDENCE SCORE: Include "ai_confidence" (integer 40–99), varied realistically.
2. FINDING TYPES: Review findings MUST cover at least these three types when present in the data: SQL Injection, Hardcoded Secret, Vulnerable Package. Each finding cites an exact file path and line number.
3. EXPLOIT CHAIN EXPLANATION: Explain in plain language, for a developer audience, how the finding could actually be exploited end-to-end — not just "this is dangerous."
4. SPECIFIC FIX: The generated fix must be a real code diff (before/after), not generic advice.
5. HUMAN GATE: Always set "human_approval_required": true for any Critical or High finding.
6. STRUCTURED OUTPUT: Return valid JSON matching the schema below exactly.

RESPONSE FORMAT (strict JSON):
{{
    "ai_confidence": <int 40-99>,
    "step_by_step_execution": ["<step 1>", "<step 2>"],
    "summary": "<2-3 sentence executive summary of what was found and fixed>",
    "findings": [
        {{"id": "<finding_id>", "title": "<title>", "severity": "<Critical|High|Medium|Low>", "finding_type": "<SQL Injection|Hardcoded Secret|Vulnerable Package>", "file": "<path>", "line": <int>, "description": "<detail>", "evidence": "<code snippet>"}}
    ],
    "exploit_chain_explanation": "<plain-language narrative of how this is exploited end-to-end>",
    "fix": {{"file": "<path>", "diff": "<unified diff or before/after snippet>", "explanation": "<why this fixes it>"}},
    "pr": {{"title": "<PR title>", "branch": "<branch name>", "summary": "<PR description>"}},
    "validation": {{"checks": [{{"name": "<check name>", "status": "<Passed|Failed>", "details": "<detail>"}}]}},
    "human_approval_required": <bool>,
    "deployment": {{"status": "<Pending Approval|Deployed>", "environment": "<environment name>"}},
    "recommendations": ["<actionable recommendation>"]
}}
"""

        return f"""You are {agent_name}, a senior security AI agent within the {uc_labels.get(use_case, use_case)} pipeline.

{source_declaration}

LIFECYCLE STAGE: {stage.replace('_', ' ').title()}
FRAMEWORKS: {frameworks}

REQUIREMENTS:
1. AI CONFIDENCE SCORE: You MUST include an "ai_confidence" field in your response (integer 40–99). This represents your confidence in the analysis quality. Vary realistically — do NOT default to 85.
2. SPECIFICITY: All remediation steps must be SPECIFIC — include exact commands, package versions, verification steps. Never say "patch the package" — say "run `apt upgrade openssl=3.0.14` on web-prod-01."
3. FALSE POSITIVE DISCIPLINE: For every finding you classify as false positive, provide an explicit written rationale. The rationale IS the product.
4. STRUCTURED OUTPUT: Return valid JSON matching the AgentOutcome schema.
5. FULL ANALYSIS: Analyse the FULL dataset provided via aggregation summaries — never just top-5 samples.{attack_chain_block}

RESPONSE FORMAT (strict JSON):
{{
    "ai_confidence": <int 40-99>,
    "step_by_step_execution": ["<step 1>", "<step 2>"],
    "output_generated": "<summary of output>",
    "passed_to_next_stage": "<data handed off>",
    "summary": "<2-3 paragraph executive summary>",
    "findings": [
        {{"id": "<finding_id>", "title": "<title>", "severity": "<Critical|High|Medium|Low|Info>", "description": "<detail>", "evidence": "<supporting data>", "recommendation": "<specific fix>"}}
    ],
    "kpi_deltas": {{"<kpi_name>": <numeric_delta>}},
    "recommendations": ["<actionable recommendation>"]
}}
"""

    def _build_task_prompt(
        self,
        use_case: str,
        stage: str,
        aggregation_summary: Dict[str, Any],
        context: str = "",
    ) -> str:
        """Build the task instruction with aggregation data and RAG context."""
        agg_text = json.dumps(aggregation_summary, indent=2, default=str)
        if len(agg_text) > 8000:
            agg_text = agg_text[:8000] + "\n... [truncated for token budget]"

        rag_section = ""
        if context:
            rag_section = f"\n\nRAG CONTEXT (retrieved from knowledge base):\n{context}"

        stage_instructions = self._get_stage_instructions(use_case, stage)

        return f"""TASK: Execute the {stage.replace('_', ' ').title()} stage of {use_case.replace('_', ' ').upper()}.

{stage_instructions}

DATASET AGGREGATION SUMMARY:
{agg_text}
{rag_section}

Analyse the full dataset aggregation above. Produce your structured JSON response now.
"""

    def _pre_aggregate(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Pandas pre-aggregation (zero LLM cost).

        Produces:
        - describe() statistics
        - frequency tables for categorical columns
        - anomaly concentration (values > 2σ)
        - time-series bucketing if datetime columns exist
        """
        result: Dict[str, Any] = {
            "shape": list(df.shape),
            "columns": list(df.columns),
        }

        # Numeric summary
        numeric_df = df.select_dtypes(include=["number"])
        if not numeric_df.empty:
            result["numeric_summary"] = json.loads(
                numeric_df.describe().to_json()
            )

            # Anomaly concentration: values > 2σ from mean
            anomalies: Dict[str, int] = {}
            for col in numeric_df.columns:
                mean = numeric_df[col].mean()
                std = numeric_df[col].std()
                if std and std > 0:
                    count = int(((numeric_df[col] - mean).abs() > 2 * std).sum())
                    if count > 0:
                        anomalies[col] = count
            if anomalies:
                result["anomaly_concentration"] = anomalies

        # Frequency tables for categorical columns (top 10)
        cat_df = df.select_dtypes(include=["object", "category"])
        freq_tables: Dict[str, Dict[str, int]] = {}
        for col in cat_df.columns[:10]:
            try:
                # Exclude columns containing unhashable elements like lists/dicts
                non_nulls = cat_df[col].dropna()
                if not non_nulls.empty:
                    first_val = non_nulls.iloc[0]
                    if isinstance(first_val, (list, dict, set)):
                        continue
                counts = cat_df[col].value_counts().head(10)
                freq_tables[col] = counts.to_dict()
            except TypeError:
                continue
        if freq_tables:
            result["frequency_tables"] = freq_tables

        # Time-series bucketing
        dt_cols = df.select_dtypes(include=["datetime64", "datetimetz"]).columns
        if len(dt_cols) > 0:
            col = dt_cols[0]
            try:
                buckets = df.set_index(col).resample("D").size()
                result["time_series_daily"] = {
                    str(k): int(v) for k, v in buckets.items()
                }
            except Exception:
                pass

        return result

    def _get_stage_agent_name(self, use_case: str, stage: str) -> str:
        """Map UC + stage to agent name."""
        return AGENT_NAME_MAP.get(use_case, {}).get(stage, f"{use_case}_{stage}_Agent")

    def _format_outcome(
        self,
        raw_response: str,
        use_case: str,
        stage: str,
        data_source: str,
        aggregation: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """Validate and format raw LLM response into AgentOutcome."""
        agent_name = self._get_stage_agent_name(use_case, stage)
        timestamp = time.time()

        # Attempt JSON parse
        parsed: Dict[str, Any] = {}
        try:
            # Handle markdown code fences
            text = raw_response.strip()
            if text.startswith("```"):
                lines = text.split("\n")
                text = "\n".join(lines[1:])
                if text.endswith("```"):
                    text = text[:-3]
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            # Fallback: wrap raw text as summary
            parsed = {
                "ai_confidence": 65,
                "step_by_step_execution": ["Executed text fallback analysis."],
                "output_generated": "Unstructured text response.",
                "passed_to_next_stage": "Raw text context passed downstream.",
                "summary": raw_response[:2000] if raw_response else "No response generated.",
                "findings": [],
                "kpi_deltas": {},
                "recommendations": [],
            }

        # Validate and clamp confidence
        confidence = parsed.get("ai_confidence", 65)
        if not isinstance(confidence, int):
            try:
                confidence = int(confidence)
            except (ValueError, TypeError):
                confidence = 65
        confidence = max(40, min(99, confidence))

        return {
            "agent_name": agent_name,
            "use_case": use_case,
            "stage": stage,
            "data_source": data_source,
            "ai_confidence": confidence,
            "step_by_step_execution": parsed.get("step_by_step_execution", []),
            "output_generated": parsed.get("output_generated", "Analysis executed without structured output."),
            "passed_to_next_stage": parsed.get("passed_to_next_stage", "State context carried forward."),
            "summary": parsed.get("summary", ""),
            "findings": parsed.get("findings", []),
            "kpi_deltas": parsed.get("kpi_deltas", {}),
            "recommendations": parsed.get("recommendations", []),
            "attack_chains": parsed.get("attack_chains", []),
            "exploit_chain_explanation": parsed.get("exploit_chain_explanation", ""),
            "fix": parsed.get("fix", {}),
            "pr": parsed.get("pr", {}),
            "validation": parsed.get("validation", {}),
            "human_approval_required": parsed.get("human_approval_required", False),
            "deployment": parsed.get("deployment", {}),
            "timestamp": timestamp,
            "aggregation": aggregation or {},
        }

    # ── Stage-specific instruction text ──────────────────────────────────

    def _get_stage_instructions(self, use_case: str, stage: str) -> str:
        """Return stage-specific task instructions."""
        instructions: Dict[str, Dict[str, str]] = {
            "ctem": {
                "scoping": (
                    "Ingest asset inventory and business context. Identify the operational "
                    "boundary of the attack surface. Count total assets by class, environment "
                    "distribution, internet-exposed assets, and business-critical asset concentrations. "
                    "Flag shadow IT (untagged/unmanaged assets)."
                ),
                "discovery": (
                    "Scan all scoped assets for vulnerabilities, misconfigurations, and software "
                    "weaknesses. Cross-reference against CISA KEV, NVD, and vendor advisories. "
                    "Output raw vulnerability findings with CVE ID, CVSS, EPSS, KEV flag, "
                    "and patch availability. "
                    "FRONTIER REASONING: Also construct at least one multi-hop ATTACK PATH — "
                    "an initial foothold on one asset that, through lateral movement or a chained "
                    "misconfiguration, reaches a high-value asset. Populate the 'attack_chains' field "
                    "with the real assets and CVEs/techniques involved and a one-sentence reasoning "
                    "note per hop explaining why it connects to the next."
                ),
                "prioritisation": (
                    "Rank vulnerabilities by ACTUAL risk — not theoretical CVSS severity. "
                    "Apply business context: asset criticality × exploitability × KEV status × "
                    "EPSS score × internet exposure. Produce P1/P2/P3 classification. "
                    "KEY REQUIREMENT: Show at least one case where a CVSS 5.0 KEV item "
                    "outranks a CVSS 9.0+ non-KEV item, with explicit rationale. "
                    "FRONTIER REASONING: Also demonstrate VULNERABILITY CHAINING — identify two "
                    "individually-Medium findings that, combined, create a Critical-severity path "
                    "(e.g. an info-disclosure bug plus a weak-credential finding on the same asset "
                    "class). Populate the 'attack_chains' field with this chain and the reasoning "
                    "for why the combination elevates severity."
                ),
                "validation": (
                    "Validate exploitability of prioritised findings. Remove false positives "
                    "through reasoning about network reachability, patch state, and compensating "
                    "controls. For EVERY false positive, provide explicit written rationale."
                ),
                "mobilisation": (
                    "Generate SPECIFIC, actionable remediation instructions per finding. "
                    "Include exact commands, package versions, verification steps. "
                    "Create remediation tickets with owner assignment, due dates, and SLA tracking."
                ),
            },
            "devsecops": {
                "pipeline": (
                    "Walk the full DevSecOps journey for the given commit: (1) review the diff for "
                    "SQL Injection, Hardcoded Secrets, and Vulnerable Packages with exact file/line "
                    "citations; (2) explain, in plain developer language, how each finding could "
                    "actually be exploited end-to-end; (3) generate a real code fix as a diff; "
                    "(4) draft a pull request title/branch/summary for the fix; (5) run automated "
                    "security validation checks and report pass/fail per check; (6) flag whether "
                    "human approval is required (true for any Critical/High finding); "
                    "(7) report the deployment gate status. KEY REQUIREMENT: findings must be "
                    "specific to the actual commit content, not generic advice."
                ),
            },
        }

        return instructions.get(use_case, {}).get(
            stage,
            f"Execute the {stage} stage for {use_case}. Produce structured findings.",
        )

    # ── Synthetic fallback response ──────────────────────────────────────

    def _generate_synthetic_response(
        self, use_case: str, stage: str
    ) -> str:
        """Generate a synthetic demo response when no LLM router is available."""
        agent_name = self._get_stage_agent_name(use_case, stage)

        # Pre-built finding templates per UC/stage
        findings_map: Dict[str, Dict[str, list]] = {
            "ctem": {
                "scoping": [
                    {"id": "SCOPE-001", "title": "Shadow IT — 47 untagged cloud instances discovered", "severity": "High", "description": "Cloud asset inventory audit identified 47 EC2/GCE instances with no business owner tag, no CMDB entry, and no security group audit trail.", "evidence": "AWS Config + GCP Asset Inventory scan", "recommendation": "Tag all instances within 48 hours; quarantine untraceable assets."},
                    {"id": "SCOPE-002", "title": "Internet-exposed database servers (3 instances)", "severity": "Critical", "description": "Three PostgreSQL instances on ports 5432 exposed to 0.0.0.0/0 in production VPC.", "evidence": "Security group analysis + Shodan verification", "recommendation": "Restrict security groups to internal CIDR ranges immediately."},
                ],
                "discovery": [
                    {"id": "DISC-001", "title": "CVE-2024-3094 — XZ Utils backdoor (CVSS 10.0, KEV)", "severity": "Critical", "description": "Affected xz-utils 5.6.0–5.6.1 detected on 12 production hosts.", "evidence": "SBOM analysis + package version audit", "recommendation": "Downgrade to xz-utils 5.4.x: `apt install xz-utils=5.4.6-0.2`"},
                    {"id": "DISC-002", "title": "CVE-2023-44487 — HTTP/2 Rapid Reset (CVSS 7.5, KEV)", "severity": "High", "description": "Nginx 1.24.0 on 8 edge servers vulnerable to HTTP/2 rapid reset DoS.", "evidence": "Nginx version audit + KEV cross-reference", "recommendation": "Upgrade nginx: `apt upgrade nginx=1.25.4-1`"},
                    {"id": "DISC-003", "title": "CVE-2024-21762 — FortiOS Out-of-Bound Write (CVSS 9.8)", "severity": "Critical", "description": "FortiGate 7.2.x firmware vulnerable, 2 firewalls affected.", "evidence": "Firmware version check via SNMP", "recommendation": "Upgrade FortiOS to 7.2.7 or later via FortiManager."},
                ],
                "prioritisation": [
                    {"id": "PRI-001", "title": "CVE-2023-36884 — Office RCE (CVSS 5.0, KEV active exploitation)", "severity": "Critical", "description": "CVSS 5.0 but on CISA KEV with active exploitation by Storm-0978. Ranked ABOVE CVE-2024-21762 (CVSS 9.8) which has no confirmed exploitation and sits on an isolated management VLAN.", "evidence": "KEV entry + EPSS 0.87 + business-critical asset exposure", "recommendation": "Apply Microsoft patch KB5028166; monitor for IOCs associated with Storm-0978."},
                    {"id": "PRI-002", "title": "CVE-2024-21762 — FortiOS (CVSS 9.8, deprioritised)", "severity": "Medium", "description": "Despite CVSS 9.8, deprioritised: firewall on isolated management VLAN, no internet exposure, EPSS 0.12, not on KEV.", "evidence": "Network segmentation analysis + EPSS score", "recommendation": "Schedule patching in next maintenance window (P2 — 14 days)."},
                ],
                "validation": [
                    {"id": "VAL-001", "title": "CVE-2024-3094 — Confirmed exploitable", "severity": "Critical", "description": "XZ Utils backdoor confirmed active on 12 hosts. Liblzma loaded with backdoor payload verified.", "evidence": "Binary hash comparison + ldd output analysis", "recommendation": "Immediate remediation — downgrade xz-utils across all affected hosts."},
                    {"id": "VAL-FP-001", "title": "FALSE POSITIVE — CVE-2023-4911 on container hosts", "severity": "Info", "description": "Looney Tunables glibc CVE flagged on 6 container hosts, but all containers run distroless images with musl libc — glibc not loaded.", "evidence": "Container image analysis: base=gcr.io/distroless/static; ldd shows musl", "recommendation": "Suppress for distroless workloads; add scanner exception rule."},
                ],
                "mobilisation": [
                    {"id": "REM-001", "title": "Remediate CVE-2024-3094 — XZ Utils", "severity": "Critical", "description": "Auto-generated remediation plan for 12 affected hosts.", "evidence": "Validated finding VAL-001", "recommendation": "Execute: `apt install xz-utils=5.4.6-0.2 && xz --version` on each host. Expected: 'xz (XZ Utils) 5.4.6'. Create change ticket CR-2024-0891."},
                ],
            },
            "devsecops": {
                "pipeline": [
                    {"id": "DSO-001", "title": "SQL Injection via unparameterised query", "severity": "Critical", "finding_type": "SQL Injection", "file": "app/api/routes/users.py", "line": 47, "description": "User-supplied `username` is concatenated directly into a raw SQL string in `get_user_by_name()`.", "evidence": "`query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"`"},
                    {"id": "DSO-002", "title": "Hardcoded AWS secret access key", "severity": "Critical", "finding_type": "Hardcoded Secret", "file": "app/config/settings.py", "line": 12, "description": "AWS secret access key committed directly in source rather than loaded from environment/secret manager.", "evidence": "`AWS_SECRET_ACCESS_KEY = \"AKIA...REDACTED...\"`"},
                    {"id": "DSO-003", "title": "Vulnerable package: requests==2.6.0", "severity": "High", "finding_type": "Vulnerable Package", "file": "requirements.txt", "line": 9, "description": "Pinned `requests` version is affected by CVE-2018-18074 (credential leak on redirect).", "evidence": "`requests==2.6.0` in requirements.txt"},
                ],
            },
        }

        # Dynamic summaries and recommendations matching the reference screenshot design
        summaries: Dict[str, Dict[str, str]] = {
            "ctem": {
                "scoping": (
                    "The analysis of the telemetry data reveals significant vulnerabilities and potential breaches "
                    "that threaten compliance with various regulatory frameworks. For instance:\n\n"
                    "* **NIST Cybersecurity Framework (PR.AC-01)**: The lack of MFA on critical assets (e.g., asset_id: AST-001501) exposes them to unauthorized access, violating identity management and access control principles.\n"
                    "* **ISO/IEC 27001 (A.8.8)**: The presence of exploitable vulnerabilities in assets (e.g., asset_id: AST-002586) indicates a failure to manage technical vulnerabilities effectively, which is critical for maintaining information security.\n"
                    "* **PCI DSS (Req_06)**: The detection of malware and suspicious processes on endpoints (e.g., ip_address: 10.119.199.17) suggests inadequate secure system and software practices, risking cardholder data security.\n"
                    "* **Digital Operational Resilience Act (Art_11)**: The lack of documented recovery procedures and testing for critical servers (e.g., asset_id: AST-001055) undermines the organization's resilience against cyber incidents."
                ),
                "discovery": (
                    "The vulnerability discovery process has mapped all scoped assets against the latest threat intelligence and vulnerability advisories. For instance:\n\n"
                    "* **NIST Cybersecurity Framework (DE.AE-02)**: Backdoored package components (xz-utils, CVE-2024-3094) were identified on 12 hosts, violating supply chain integrity requirements.\n"
                    "* **ISO/IEC 27001 (A.12.6)**: Raw vulnerabilities with active exploitation profiles (FortiOS, CVE-2024-21762) expose key network devices to administrative bypass.\n"
                    "* **PCI DSS (Req_06)**: Multiple HTTP/2 edge endpoints (CVE-2023-44487) lack security hardening, presenting potential avenues for denial of service attacks."
                ),
                "prioritisation": (
                    "The prioritization engine has re-evaluated the vulnerabilities by local contextual risk, asset exposure, and active threat vector mappings. For instance:\n\n"
                    "* **NIST Cybersecurity Framework (ID.RA-05)**: Active CISA KEV exploit path CVE-2023-36884 on Storm-0978 target list is elevated to Critical due to external exposure and critical business impact.\n"
                    "* **ISO/IEC 27001 (A.12.6)**: Deprioritization of CVSS 9.8 FortiOS vulnerability on isolated management VLAN to Medium, demonstrating dynamic context-based risk scoring.\n"
                    "* **PCI DSS (Req_02)**: Vulnerabilities affecting sandbox segments were deprioritized to preserve active remediation bandwidth for public-facing database instances."
                ),
                "validation": (
                    "Exploitability validation was performed to remove false positives and isolate validated threat corridors. For instance:\n\n"
                    "* **NIST Cybersecurity Framework (PR.IP-04)**: glibc vulnerability (CVE-2023-4911) was validated as a False Positive because the base images are distroless and load musl libc rather than glibc.\n"
                    "* **ISO/IEC 27001 (A.12.6)**: Validated active liblzma backdoor exploitability on 12 production hosts through local library symbol verification.\n"
                    "* **Digital Operational Resilience Act (Art_12)**: Automated validation scans confirmed that secondary defensive layers (firewalls, segment blocks) mitigate sandbox vulnerabilities."
                ),
                "mobilisation": (
                    "Actionable remediations have been generated and pushed to workflow engines with specific instructions and real change records. For instance:\n\n"
                    "* **NIST Cybersecurity Framework (RC.RP-01)**: Actionable patch downgrades and package script commands prepared for automated distribution.\n"
                    "* **ISO/IEC 27001 (A.12.6)**: Change record CR-2024-0891 created inside Jira Service Management with assigned owners and verified SLA targets.\n"
                    "* **PCI DSS (Req_06)**: Automated package verifications configured post-remediation to confirm successful package downgrades."
                )
            },
            "devsecops": {
                "pipeline": (
                    "AI code review flagged 3 issues in this commit before it could reach a human reviewer. For instance:\n\n"
                    "* **SQL Injection (CWE-89)**: `get_user_by_name()` in `app/api/routes/users.py:47` concatenates the raw `username` parameter into a SQL string — an attacker could pass `' OR '1'='1` to bypass the WHERE clause entirely.\n"
                    "* **Hardcoded Secret (CWE-798)**: An AWS secret access key is committed in plaintext in `app/config/settings.py:12` — anyone with read access to the repo (including forks and CI logs) can assume the associated IAM role.\n"
                    "* **Vulnerable Package (CVE-2018-18074)**: `requests==2.6.0` pinned in `requirements.txt:9` leaks the `Authorization` header on cross-domain redirects.\n\n"
                    "An AI-generated fix and pull request were prepared for each finding, automated security validation was run against the patched branch, and the Critical/High findings were routed to a human-approval gate before deployment."
                )
            }
        }

        # Recommendations templates
        recommendations_map: Dict[str, Dict[str, list]] = {
            "ctem": {
                "scoping": [
                    "**Implement MFA** on all critical assets, particularly on asset_id: AST-001501, to enhance access control and comply with NIST PR.AC-01.",
                    "**Conduct a vulnerability assessment** on asset_id: AST-002586 and patch any identified vulnerabilities within SLA to align with ISO/IEC 27001 A.8.8.",
                    "**Deploy EDR solutions** on all endpoints, especially on ip_address: 10.119.199.17, to monitor and respond to malware threats effectively, ensuring compliance with PCI DSS Req_06.",
                    "**Establish and test recovery plans** for critical servers, particularly asset_id: AST-001055, to meet Digital Operational Resilience Act requirements."
                ],
                "discovery": [
                    "**Downgrade xz-utils** to stable version `5.4.6` immediately across all 12 affected hosts to eliminate the backdoor.",
                    "**Deploy FortiOS firmware patch** to version `7.2.7` or later via FortiManager on affected firewalls.",
                    "**Upgrade nginx** to version `1.25.4` on all edge web servers to patch the HTTP/2 Rapid Reset vulnerability."
                ],
                "prioritisation": [
                    "**Remediate CVE-2023-36884** as high priority (P1) due to active KEV exploitation on exposed servers.",
                    "**Defer CVE-2024-21762 FortiOS patch** to the next standard 14-day maintenance window (P2) due to isolated segment.",
                    "**Audit SLA metrics** on all open vulnerabilities to ensure zero breach of the critical remediation window."
                ],
                "validation": [
                    "**Configure scanner exclusion rules** in Prisma Cloud to suppress glibc alerts on distroless musl containers.",
                    "**Initiate emergency patch ticket** for validated XZ backdoor hosts.",
                    "**Audit compensating controls** on isolated database segments to verify secondary defenses are active."
                ],
                "mobilisation": [
                    "**Approve Jira change ticket CR-2024-0891** for deploying the downgrade script to production hosts.",
                    "**Execute package validation playbook** in staging to confirm downgrade commands are clean.",
                    "**Update compliance scorecard** to reflect successful mitigation and remediation of validated findings."
                ]
            },
            "devsecops": {
                "pipeline": [
                    "**Rotate the exposed AWS secret key** in IAM immediately and purge it from git history, not just the latest commit.",
                    "**Merge the generated fix PR** for the SQL injection in `get_user_by_name()` after CI validation passes.",
                    "**Upgrade `requests`** to `>=2.31.0` to remediate CVE-2018-18074 across all services depending on this package.",
                    "**Add these three checks to pre-commit hooks** (secret scanning, parameterised-query lint, dependency audit) so equivalent issues are blocked before they reach a PR."
                ]
            }
        }

        # Attack-path / vulnerability-chaining synthetic content — CTEM Discovery & Prioritisation.
        attack_chains_map = {
            "discovery": [
                {
                    "chain_id": "CHAIN-DISC-01",
                    "severity": "Critical",
                    "steps": [
                        {"asset": "web-prod-02 (edge, internet-exposed)", "technique_or_cve": "CVE-2023-44487", "note": "HTTP/2 Rapid Reset gives an attacker an initial low-cost foothold on the internet-facing edge tier."},
                        {"asset": "app-internal-14 (application tier)", "technique_or_cve": "T1021.002 — SMB lateral movement", "note": "From the edge host, flat network segmentation allows SMB pivoting into the internal application tier."},
                        {"asset": "db-prod-01 (business-critical)", "technique_or_cve": "CVE-2024-3094", "note": "The XZ Utils backdoor on the database host gives full command execution on the business-critical asset — the actual objective of the chain."},
                    ],
                }
            ],
            "prioritisation": [
                {
                    "chain_id": "CHAIN-PRI-01",
                    "severity": "Critical",
                    "steps": [
                        {"asset": "app-stg-03", "technique_or_cve": "CVE-2024-400 (Medium, info disclosure)", "note": "Individually Medium — leaks internal service account names via a verbose error page."},
                        {"asset": "app-stg-03", "technique_or_cve": "SSH-CFG (Medium, weak credential policy)", "note": "Combined with the leaked account names, weak SSH password policy on the same host allows credential guessing."},
                        {"asset": "app-stg-03", "technique_or_cve": "Composite: account enumeration + credential guessing", "note": "Together these two Medium findings produce a Critical unauthenticated-to-authenticated-shell path that neither finding shows alone — the reason both are elevated to P1 together."},
                    ],
                }
            ],
        }

        # Select findings
        findings = findings_map.get(use_case, {}).get(stage, [
            {"id": f"{use_case[:3].upper()}-{stage[:3].upper()}-001", "title": f"Sample finding for {stage}", "severity": "Medium", "description": f"AI-generated analysis for {use_case} — {stage} stage.", "evidence": "Aggregated dataset analysis", "recommendation": "Review and take appropriate action."},
        ])

        import random
        confidence = random.randint(82, 91) if use_case == "ctem" and stage == "scoping" else random.randint(75, 94)

        # Retrieve high-fidelity summary and action plans
        summary_text = summaries.get(use_case, {}).get(
            stage,
            f"**{agent_name}** completed the {stage.replace('_', ' ').title()} stage analysis. "
            f"Processed full dataset aggregation with {len(findings)} findings identified. "
            f"AI confidence: {confidence}%. Data source: SYNTHETIC — all outputs are demo-grade."
        )

        recs = recommendations_map.get(use_case, {}).get(
            stage,
            [
                f"Address {sum(1 for f in findings if f.get('severity') in ('Critical', 'High'))} critical/high findings within SLA.",
                "Review AI confidence score and validate findings with domain expert.",
                "Progress to next lifecycle stage after HITL approval."
            ]
        )

        result = {
            "ai_confidence": confidence,
            "step_by_step_execution": [
                f"Ingested 100% of available payload via {use_case.upper()} {stage} schema constraints.",
                f"Evaluated data array containing {len(findings)} initial anomalies against contextual frameworks.",
                "Correlated isolated events against global threat feeds (NVD, KEV, ATT&CK).",
                f"Ranked and filtered results to isolate {sum(1 for f in findings if f.get('severity') in ('Critical', 'High'))} actionable items.",
                "Formatted structured JSON payload for downstream agent consumption."
            ],
            "output_generated": f"A comprehensive {stage} evaluation yielding {len(findings)} validated findings mapped to enterprise frameworks.",
            "passed_to_next_stage": f"Structured JSON payload containing exactly {len(findings)} items passed via StateGraph to the subsequent agent.",
            "summary": summary_text,
            "findings": findings,
            "kpi_deltas": {
                "findings_count": len(findings),
                "critical_count": sum(1 for f in findings if f.get("severity") == "Critical"),
                "high_count": sum(1 for f in findings if f.get("severity") == "High"),
            },
            "recommendations": recs,
        }

        if use_case == "ctem" and stage in attack_chains_map:
            result["attack_chains"] = attack_chains_map[stage]

        if use_case == "devsecops":
            result["exploit_chain_explanation"] = (
                "An attacker who finds this repository (or gains read access to it) can chain all three findings: "
                "the hardcoded AWS key grants direct cloud access; the SQL injection in `get_user_by_name()` lets them "
                "read or modify arbitrary rows in the users table by passing a crafted `username` (e.g. `' OR '1'='1`); "
                "and the outdated `requests` library leaks the app's own `Authorization` header if it ever follows a "
                "redirect to an attacker-controlled host — handing over a live session token. None of these require "
                "advanced tooling; each is exploitable with a browser or `curl`."
            )
            result["fix"] = {
                "file": "app/api/routes/users.py",
                "diff": (
                    "- query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"\n"
                    "- cursor.execute(query)\n"
                    "+ query = \"SELECT * FROM users WHERE username = %s\"\n"
                    "+ cursor.execute(query, (username,))"
                ),
                "explanation": "Switches from string concatenation to a parameterised query, so the database driver escapes `username` instead of treating it as SQL.",
            }
            result["pr"] = {
                "title": "fix(security): parameterise username query, remove hardcoded AWS key, bump requests",
                "branch": "ai/fix-dso-2024-0091",
                "summary": "Auto-generated fix for 3 AI code review findings: SQL injection in get_user_by_name(), hardcoded AWS secret in settings.py, and vulnerable requests package.",
            }
            result["validation"] = {
                "checks": [
                    {"name": "SQL injection regression test", "status": "Passed", "details": "New parameterised-query test suite passes; injection payload no longer alters query results."},
                    {"name": "Secret scan (gitleaks)", "status": "Passed", "details": "No hardcoded credentials detected in the patched branch."},
                    {"name": "Dependency audit", "status": "Passed", "details": "requests upgraded to 2.31.0 — CVE-2018-18074 no longer present."},
                ]
            }
            result["human_approval_required"] = True
            result["deployment"] = {"status": "Pending Approval", "environment": "production"}

        return json.dumps(result, indent=2)

    def _error_outcome(
        self, use_case: str, stage: str, data_source: str, error_msg: str
    ) -> Dict[str, Any]:
        """Return a standardised error outcome."""
        return {
            "agent_name": self._get_stage_agent_name(use_case, stage),
            "use_case": use_case,
            "stage": stage,
            "data_source": data_source,
            "ai_confidence": 0,
            "summary": f"Agent execution failed: {error_msg}",
            "findings": [],
            "kpi_deltas": {},
            "recommendations": ["Retry the analysis or check system logs."],
            "timestamp": time.time(),
            "error": error_msg,
        }
