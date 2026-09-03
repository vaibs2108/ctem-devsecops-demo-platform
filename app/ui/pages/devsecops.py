"""
AI Capability Demo — DevSecOps Page
Implements the AI-led DevSecOps pipeline as a single lean, linear journey:
Developer commits code -> AI reviews code -> AI explains exploit chain ->
AI generates fix -> Creates PR -> Runs security validation -> Human approves -> Code deployed.
"""

import streamlit as st
import textwrap
import pandas as pd
import time
from typing import Dict, Any

from app.ui.theme import (
    ACCENT_GREEN,
    ACCENT_RED,
    ACCENT_AMBER,
    ACCENT_BLUE,
    TEXT_MUTED,
    TEXT_SECONDARY,
    TEXT_PRIMARY,
    BORDER_GLASS,
)
from app.ui.components.lifecycle_stage import render_usecase_overview_card
from app.ui.components.interactive_demo import render_progress_indicator, render_hitl_gate
from app.runtime.agent_manager import AgentManager

_SEVERITY_COLOUR = {
    "critical": "#ff4444",
    "high": "#ff6b35",
    "medium": "#ffaa00",
    "low": ACCENT_BLUE,
}


def render_devsecops_page(
    datasets: Dict[str, pd.DataFrame],
    agent_manager: AgentManager,
    kpi_engine: Any,
) -> None:
    """Render the DevSecOps lean linear pipeline workspace."""

    data_source_key = "active_data_source_devsecops"
    if data_source_key not in st.session_state:
        st.session_state[data_source_key] = "synthetic"
    data_source = st.session_state[data_source_key]
    accent = ACCENT_GREEN

    st.markdown(f'<h1 style="color: {accent}; margin-bottom: 8px;">🐙 AI-Led DevSecOps Pipeline</h1>', unsafe_allow_html=True)
    render_usecase_overview_card("devsecops")

    if "devsecops_outcome" not in st.session_state:
        st.session_state.devsecops_outcome = None
    if "devsecops_approved" not in st.session_state:
        st.session_state.devsecops_approved = False

    st.markdown('<div class="synthetic-banner">⚠️ <strong>Synthetic Data Mode</strong> — Commit shown below is from the enterprise-grade SyntheticDataEngine.</div>', unsafe_allow_html=True)

    # ── Step 1: Developer Commits Code ──
    st.markdown("### 1️⃣ Developer Commits Code")
    commits = datasets.get("code_commits")
    commit_row = commits.iloc[0] if commits is not None and not commits.empty else None

    if commit_row is not None:
        st.markdown(textwrap.dedent(f"""\
            <div class="glass-card" style="padding: 16px; border: 1px solid {BORDER_GLASS}; border-radius: 12px; background: rgba(255, 255, 255, 0.02); margin-bottom: 20px; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;">
                <strong style="color: {accent};">{commit_row['repo']}</strong> @ <span style="color: {TEXT_SECONDARY};">{commit_row['branch']}</span><br/>
                commit <span style="color: {TEXT_MUTED};">{commit_row['commit_sha']}</span> by {commit_row['author']}<br/>
                <span style="color: {TEXT_PRIMARY};">"{commit_row['commit_message']}"</span> — {commit_row['files_changed']} files changed
            </div>"""),
            unsafe_allow_html=True)

    execute_clicked = st.button("🚀 Execute AI DevSecOps Pipeline — Synthetic Data", type="primary")

    if execute_clicked:
        render_progress_indicator("AI reviewing commit for SQLi, secrets, and vulnerable packages...", 20)
        time.sleep(0.3)
        render_progress_indicator("Explaining exploit chain in plain language...", 45)
        time.sleep(0.3)
        render_progress_indicator("Generating fix and opening pull request...", 70)
        time.sleep(0.3)
        render_progress_indicator("Running automated security validation checks...", 95)
        time.sleep(0.3)

        outcome = agent_manager.run_stage("devsecops", "pipeline", datasets, data_source)
        st.session_state.devsecops_outcome = outcome
        st.session_state.devsecops_approved = False
        st.rerun()

    if st.session_state.devsecops_outcome:
        _render_pipeline_results(st.session_state.devsecops_outcome, accent)


def _render_pipeline_results(outcome: Dict[str, Any], accent: str) -> None:
    findings = outcome.get("findings", [])
    confidence = outcome.get("ai_confidence", outcome.get("confidence", 85))

    # ── Step 2: AI-Driven Code Review ──
    st.markdown("### 2️⃣ AI-Driven Code Review")
    st.markdown(f"""
    <div style="margin-bottom: 12px; font-size: 0.9rem; color: {TEXT_SECONDARY};">
        🎯 AI Confidence: <strong style="color: {accent};">{confidence}%</strong>
    </div>
    """, unsafe_allow_html=True)

    if findings:
        cards_html = ""
        for f in findings:
            sev = str(f.get("severity", "Medium")).lower()
            sev_colour = _SEVERITY_COLOUR.get(sev, "#ffaa00")
            cards_html += f"""
            <div style="
                background: rgba(255,255,255,0.02); border: 1px solid {BORDER_GLASS};
                border-left: 3px solid {sev_colour}; border-radius: 8px; padding: 14px 16px; margin-bottom: 10px;
            ">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                    <strong style="color:#ffffff;">{f.get('title', 'Finding')}</strong>
                    <span style="padding:2px 10px; border-radius:10px; font-size:0.68rem; font-weight:700; background:{sev_colour}22; color:{sev_colour}; border:1px solid {sev_colour}55;">{f.get('finding_type', f.get('severity', ''))}</span>
                </div>
                <div style="font-size:0.8rem; color:{TEXT_MUTED}; margin-bottom:6px;">{f.get('file', '')}{':' + str(f.get('line')) if f.get('line') else ''}</div>
                <div style="font-size:0.85rem; color:{TEXT_SECONDARY}; margin-bottom:8px;">{f.get('description', '')}</div>
            </div>
            """
        st.markdown(cards_html, unsafe_allow_html=True)
        evidence_snippets = [f.get("evidence") for f in findings if f.get("evidence")]
        if evidence_snippets:
            with st.expander("🔍 View flagged code"):
                for snippet in evidence_snippets:
                    st.code(snippet, language="python")

    # ── Step 3: AI-Driven Exploit Chain Analysis ──
    st.markdown("### 3️⃣ AI-Driven Exploit Chain Analysis")
    explanation = outcome.get("exploit_chain_explanation", "")
    if explanation:
        st.markdown(f"""
        <div style="background: rgba(255,107,53,0.05); border-left: 3px solid #ff6b35; border-radius: 0 8px 8px 0; padding: 14px 16px; font-size: 0.9rem; color: {TEXT_SECONDARY}; line-height: 1.6; margin-bottom: 20px;">
            {explanation}
        </div>
        """, unsafe_allow_html=True)

    # ── Step 4: AI-Driven Fix Generation ──
    st.markdown("### 4️⃣ AI-Driven Fix Generation")
    fix = outcome.get("fix", {})
    if fix:
        st.markdown(f"**File:** `{fix.get('file', '')}`")
        st.code(fix.get("diff", ""), language="diff")
        if fix.get("explanation"):
            st.caption(fix["explanation"])

    # ── Step 5: Automated Pull Request Creation ──
    st.markdown("### 5️⃣ Automated Pull Request Creation")
    pr = outcome.get("pr", {})
    if pr:
        st.markdown(textwrap.dedent(f"""\
            <div class="glass-card" style="padding: 16px; border: 1px solid {BORDER_GLASS}; border-radius: 12px; background: rgba(255,255,255,0.02); margin-bottom: 20px;">
                <div style="font-size:0.95rem; font-weight:700; color:#ffffff; margin-bottom:4px;">🔀 {pr.get('title', '')}</div>
                <div style="font-size:0.8rem; color:{TEXT_MUTED}; font-family:'JetBrains Mono', monospace; margin-bottom:8px;">branch: {pr.get('branch', '')}</div>
                <div style="font-size:0.85rem; color:{TEXT_SECONDARY};">{pr.get('summary', '')}</div>
            </div>"""),
            unsafe_allow_html=True)

    # ── Step 6: Automated Security Validation ──
    st.markdown("### 6️⃣ Automated Security Validation")
    validation = outcome.get("validation", {})
    checks = validation.get("checks", []) if isinstance(validation, dict) else []
    if checks:
        for check in checks:
            status = check.get("status", "Passed")
            status_colour = "#00ff88" if status == "Passed" else "#ff4444"
            st.markdown(f"""
            <div style="display:flex; justify-content:space-between; align-items:center; padding:10px 14px; background: rgba(255,255,255,0.02); border: 1px solid {BORDER_GLASS}; border-radius: 8px; margin-bottom: 8px;">
                <div>
                    <span style="font-weight:600; color:#ffffff;">{check.get('name', '')}</span>
                    <span style="font-size:0.8rem; color:{TEXT_MUTED}; margin-left:8px;">{check.get('details', '')}</span>
                </div>
                <span style="padding:2px 10px; border-radius:10px; font-size:0.7rem; font-weight:700; background:{status_colour}22; color:{status_colour}; border:1px solid {status_colour}55;">{'✅' if status == 'Passed' else '❌'} {status.upper()}</span>
            </div>
            """, unsafe_allow_html=True)

    # ── Step 7: Human Approves ──
    st.markdown("### 7️⃣ Human Approval Gate")
    human_approval_required = outcome.get("human_approval_required", True)

    if human_approval_required and not st.session_state.devsecops_approved:
        findings_to_approve = [
            {"id": f.get("id", "finding"), "title": f.get("title", ""), "severity": f.get("severity", "High"), "confidence": confidence}
            for f in findings
            if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")
        ]
        gate_result = render_hitl_gate("devsecops", "pipeline", findings_to_approve or [{"id": "fix", "title": "Generated fix", "severity": "High", "confidence": confidence}])
        if gate_result == "approve":
            st.session_state.devsecops_approved = True
            st.rerun()
        elif gate_result == "reject":
            st.warning("❌ Fix rejected — returned to the developer for manual review.")
    else:
        st.success("✅ Approved by analyst. Deployment gate unlocked.")

    # ── Step 8: Code Deployed ──
    st.markdown("### 8️⃣ Code Deployed")
    deployment = outcome.get("deployment", {})
    is_deployed = st.session_state.devsecops_approved or not human_approval_required

    if is_deployed:
        st.markdown(textwrap.dedent(f"""\
            <div class="glass-card" style="padding: 16px; border: 1px solid {BORDER_GLASS}; border-left: 3px solid #00ff88; border-radius: 8px; background: rgba(0,255,136,0.05);">
                <strong style="color:#00ff88;">🚀 Deployed</strong> — {deployment.get('environment', 'production')}
            </div>"""),
            unsafe_allow_html=True)

        # ── Key messaging: the headline outcome, called out on its own ──
        n_findings = len(findings)
        st.markdown(textwrap.dedent(f"""\
            <div style="
                margin-top: 24px;
                padding: 28px 32px;
                border-radius: 16px;
                text-align: center;
                background: linear-gradient(135deg, rgba(0,255,136,0.14) 0%, rgba(0,212,255,0.08) 100%);
                border: 1px solid rgba(0,255,136,0.3);
            ">
                <div style="font-size: 1.6rem; font-weight: 800; color: #00ff88; letter-spacing: -0.01em; margin-bottom: 6px;">
                    🎯 Secure code at machine speed
                </div>
                <div style="font-size: 0.95rem; color: {TEXT_SECONDARY};">
                    {n_findings} vulnerabilities caught, explained, fixed, validated, and deployed — with a human still in control of the final call.
                </div>
            </div>"""),
            unsafe_allow_html=True)
    else:
        st.info("🔒 Deployment locked until the human-approval gate above is cleared.")
