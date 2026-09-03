"""
AI Capability Demo — Session Health Telemetry
Tracks in-session LLM calls, RAG search latency and score distributions, and guardrail events.
AGENTS.md Section 2 & 11 Tab 3
"""

import streamlit as st
from datetime import datetime
from typing import Dict, Any, List, Optional

class InAppMetrics:
    """Session-scoped health metrics store stored in st.session_state."""

    def __init__(self) -> None:
        self._init_session_state()

    def _init_session_state(self) -> None:
        """Initialise lists in session state to accumulate telemetry data."""
        if "metrics_llm_calls" not in st.session_state:
            st.session_state.metrics_llm_calls = []
        if "metrics_rag_queries" not in st.session_state:
            st.session_state.metrics_rag_queries = []
        if "metrics_guardrail_events" not in st.session_state:
            st.session_state.metrics_guardrail_events = []
        if "metrics_hitl_decisions" not in st.session_state:
            st.session_state.metrics_hitl_decisions = []
        if "metrics_active_since" not in st.session_state:
            st.session_state.metrics_active_since = datetime.utcnow().isoformat()

    @property
    def llm_calls(self) -> List[Dict[str, Any]]:
        return st.session_state.metrics_llm_calls

    @property
    def rag_queries(self) -> List[Dict[str, Any]]:
        return st.session_state.metrics_rag_queries

    @property
    def guardrail_events(self) -> List[Dict[str, Any]]:
        return st.session_state.metrics_guardrail_events

    @property
    def hitl_decisions(self) -> List[Dict[str, Any]]:
        return st.session_state.metrics_hitl_decisions

    def record_llm_call(self, model: str, latency_ms: int, tokens: int, success: bool, error: Optional[str] = None) -> None:
        """Record an LLM invocation event."""
        self.llm_calls.append({
            "timestamp": datetime.utcnow().isoformat(),
            "model": model,
            "latency_ms": latency_ms,
            "tokens": tokens,
            "success": success,
            "error": error,
        })

    def record_rag_query(self, index_name: str, score: float, chunks_retrieved: int, duration_ms: int) -> None:
        """Record a RAG vector or hybrid retrieval event."""
        self.rag_queries.append({
            "timestamp": datetime.utcnow().isoformat(),
            "index": index_name,
            "score": score,
            "chunks": chunks_retrieved,
            "duration_ms": duration_ms,
        })

    def record_guardrail_event(self, event_type: str, action: str, context: str) -> None:
        """Record a content safety, prompt injection, or PII redaction block/warning."""
        self.guardrail_events.append({
            "timestamp": datetime.utcnow().isoformat(),
            "type": event_type,
            "action": action,
            "context": context,
        })

    def record_hitl_decision(self, use_case: str, stage: str, decision: str, confidence: int) -> None:
        """Record an analyst action approved/dismissed on HITL gate triggers."""
        self.hitl_decisions.append({
            "timestamp": datetime.utcnow().isoformat(),
            "use_case": use_case,
            "stage": stage,
            "decision": decision.lower(),  # approved / dismissed
            "confidence": confidence
        })

    def get_summary(self) -> Dict[str, Any]:
        """Compile and aggregate telemetry trends for rendering Plotly/KPI dashboards."""
        calls = self.llm_calls
        queries = self.rag_queries
        gates = self.hitl_decisions

        success_count = sum(1 for c in calls if c["success"])
        total_calls = len(calls)
        success_rate = (success_count / max(total_calls, 1)) * 100

        avg_latency = sum(c["latency_ms"] for c in calls) / max(total_calls, 1)
        p95_latency = 0
        if calls:
            sorted_latencies = sorted(c["latency_ms"] for c in calls)
            idx = int(len(sorted_latencies) * 0.95)
            p95_latency = sorted_latencies[min(idx, len(sorted_latencies) - 1)]

        avg_rag_score = 0.0
        if queries:
            avg_rag_score = sum(q["score"] for q in queries) / len(queries)

        approved_hitl = sum(1 for g in gates if g["decision"] == "approved")
        dismissed_hitl = sum(1 for g in gates if g["decision"] == "dismissed")
        total_hitl = len(gates)
        hitl_approval_ratio = (approved_hitl / max(total_hitl, 1)) * 100

        return {
            "total_llm_calls": total_calls,
            "success_rate": success_rate,
            "avg_latency_ms": avg_latency,
            "p95_latency_ms": p95_latency,
            "total_tokens": sum(c["tokens"] for c in calls),
            "avg_rag_score": avg_rag_score,
            "guardrail_events_count": len(self.guardrail_events),
            "hitl_approval_ratio": hitl_approval_ratio,
            "total_hitl_decisions": total_hitl,
            "active_since": st.session_state.metrics_active_since,
        }
