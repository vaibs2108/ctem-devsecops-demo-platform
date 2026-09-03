"""
AI Capability Demo — Executive Command Center Dashboard
Displays dynamic business and technical KPIs, AI Readiness Gauges, CVE Heatmaps,
and 30-day coverage trends across the CTEM and DevSecOps use cases.
"""

import streamlit as st
import pandas as pd
import numpy as np
import datetime
from typing import Dict, Any, Optional

from app.ui.theme import (
    ACCENT_BLUE,
    ACCENT_GREEN,
    ACCENT_RED,
    RAG_AMBER,
    RAG_GREEN,
    RAG_RED,
    TEXT_MUTED,
    TEXT_SECONDARY,
    render_glass_card,
    render_metric_card,
    render_svg_gauge,
    render_kpi_progress_card,
)
from app.ui.components.charts import (
    create_gauge_chart,
    create_radar_chart,
    create_trend_chart,
    create_donut_chart,
    create_bar_chart,
    create_severity_distribution,
)
from app.data.generator import SyntheticDataEngine
from app.kpi.engine import KPIEngine
from app.data.synthetic_banner import render_guardrail_badge

def render_executive_kpi_card(label: str, value: float, color: str, subtext: str, subtext_color: str) -> str:
    percentage = min(100.0, max(0.0, value))
    from app.ui.theme import clean_html
    card_html = f"""
    <div class="glass-card executive-kpi-card" style="
        border-radius: 12px;
        padding: 16px 20px;
        margin-bottom: 16px;
        font-family: 'Inter', sans-serif;
    ">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <span style="font-size: 0.72rem; font-weight: 700; color: #6b6b8d; text-transform: uppercase; letter-spacing: 0.05em;">{label}</span>
            <span style="font-size: 1.25rem; font-weight: 800; color: {color};">{value:.0f}%</span>
        </div>
        <div style="width: 100%; height: 6px; background: rgba(125, 125, 125, 0.2); border-radius: 3px; overflow: hidden; margin-bottom: 8px;">
            <div style="width: {percentage:.1f}%; height: 100%; background: {color}; border-radius: 3px; transition: width 0.6s ease-in-out;"></div>
        </div>
        <div style="font-size: 0.68rem; font-weight: 700; color: {subtext_color}; text-transform: uppercase; letter-spacing: 0.05em;">
            {subtext}
        </div>
    </div>
    """
    return clean_html(card_html)

def render_executive_dashboard(datasets: Optional[Dict[str, pd.DataFrame]] = None, kpi_engine: Optional[KPIEngine] = None) -> None:
    """Render the full Executive Command Center Dashboard view."""
    
    # Verify and load KPI engine into session state
    if kpi_engine is None or datasets is None:
        if "kpi_engine" not in st.session_state:
            with st.spinner("Generating security metrics engine..."):
                engine = SyntheticDataEngine(seed=42)
                datasets = engine.generate_all()
                st.session_state.kpi_datasets = datasets
                st.session_state.kpi_engine = KPIEngine(datasets)
        kpi_engine = st.session_state.kpi_engine
        datasets = st.session_state.kpi_datasets
    
    # ── Header ──
    st.markdown(
        f"""
        <div style="text-align: center; margin-top: 10px; margin-bottom: 28px; font-family: 'Inter', sans-serif;">
            <div style="font-size: 0.8rem; font-weight: 700; color: {TEXT_SECONDARY}; text-transform: uppercase; letter-spacing: 0.18em;">CTEM &amp; DEVSECOPS AI PLATFORM</div>
            <h1 style="font-size: 2.3rem; font-weight: 800; color: white; margin-top: 6px; margin-bottom: 6px; background: linear-gradient(90deg, #00d4ff, #00ff88); -webkit-background-clip: text; -webkit-text-fill-color: transparent; letter-spacing: -0.02em;">Enterprise Security Command Center</h1>
            <div style="font-size: 0.88rem; color: #a0a0c0; font-weight: 500;">AI-Led Continuous Threat Exposure Management &bull; AI-Led DevSecOps</div>
        </div>
        """,
        unsafe_allow_html=True
    )
        
    # ── ROW 1: Two SVG Radial Gauges (Use Case Scores) ──
    ctem_score = kpi_engine.get_use_case_score("ctem")
    devsecops_score = kpi_engine.get_use_case_score("devsecops")

    g_col1, g_col2 = st.columns(2)

    with g_col1:
        st.markdown(render_svg_gauge(ctem_score, "CTEM", "EXPOSURE MITIGATION", ACCENT_BLUE), unsafe_allow_html=True)
    with g_col2:
        st.markdown(render_svg_gauge(devsecops_score, "DEVSECOPS", "SECURE CODE VELOCITY", ACCENT_GREEN), unsafe_allow_html=True)

    st.markdown("---")

    # ── ROW 2: Executive KPIs (Dynamic & Relevant to Use Cases) ──
    st.markdown('<h3 style="margin-top: 16px; margin-bottom: 20px; font-weight: 700; font-size: 1.35rem;">📊 Executive KPIs</h3>', unsafe_allow_html=True)

    # 1. CTEM KPIs
    ctem_shield = 100.0 - kpi_engine.get_kpi("Vuln Exposure Coverage")
    ctem_shield_color = RAG_GREEN if ctem_shield >= 75 else RAG_AMBER
    ctem_shield_sub = "OPTIMIZED SECURITY SHIELD" if ctem_shield >= 75 else "CRITICAL ASSETS EXPOSED"

    ctem_sla = 100.0 - kpi_engine.get_kpi("P1 SLA Breach Rate")
    ctem_sla_color = RAG_GREEN if ctem_sla >= 90 else RAG_RED
    ctem_sla_sub = "SLA TARGETS MET" if ctem_sla >= 90 else "SLA BREACH RISK ACTIVE"

    ctem_kev = kpi_engine.get_kpi("KEV Collision Rate")
    ctem_kev_color = RAG_GREEN if ctem_kev <= 15 else (RAG_AMBER if ctem_kev <= 30 else RAG_RED)
    ctem_kev_sub = "LOW ACTIVE-EXPLOIT EXPOSURE" if ctem_kev <= 15 else "ACTIVE KEV EXPOSURE"

    ctem_fp = kpi_engine.get_kpi("False Positive Suppression Rate")
    ctem_fp_color = RAG_GREEN if ctem_fp >= 15 else RAG_AMBER
    ctem_fp_sub = "CLEAN VALIDATED BACKLOG" if ctem_fp >= 15 else "REVIEW FP DISCIPLINE"

    # 2. DevSecOps KPIs
    dso_fix = kpi_engine.get_kpi("Auto-Fix Success Rate")
    dso_fix_color = RAG_GREEN if dso_fix >= 80 else RAG_AMBER
    dso_fix_sub = "FIXES SHIPPING AT MACHINE SPEED" if dso_fix >= 80 else "MANUAL FIX BACKLOG GROWING"

    dso_gate = kpi_engine.get_kpi("Deployment Gate Pass Rate")
    dso_gate_color = RAG_GREEN if dso_gate >= 90 else RAG_AMBER
    dso_gate_sub = "VALIDATION GATE HEALTHY" if dso_gate >= 90 else "VALIDATION FAILURES RISING"

    dso_pr = kpi_engine.get_kpi("PR Approval Rate")
    dso_pr_color = RAG_GREEN if dso_pr >= 85 else RAG_AMBER
    dso_pr_sub = "FAST REVIEWER TRUST" if dso_pr >= 85 else "PR REVIEW FRICTION"

    dso_findings = kpi_engine.get_kpi("Findings per Commit")
    dso_findings_color = RAG_GREEN if dso_findings <= 2.0 else (RAG_AMBER if dso_findings <= 3.5 else RAG_RED)
    dso_findings_sub = "LOW DEFECT INJECTION RATE" if dso_findings <= 2.0 else "ELEVATED DEFECT INJECTION"

    kpi_col1, kpi_col2 = st.columns(2)

    with kpi_col1:
        st.markdown('<div style="font-size:0.75rem; font-weight:700; color:#a0a0c0; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:8px;">🎯 CTEM</div>', unsafe_allow_html=True)
        st.markdown(render_executive_kpi_card("CTEM EXPOSURE SHIELD", ctem_shield, ctem_shield_color, ctem_shield_sub, ctem_shield_color), unsafe_allow_html=True)
        st.markdown(render_executive_kpi_card("CTEM SLA COMPLIANCE", ctem_sla, ctem_sla_color, ctem_sla_sub, ctem_sla_color), unsafe_allow_html=True)
        st.markdown(render_executive_kpi_card("KEV COLLISION RATE", ctem_kev, ctem_kev_color, ctem_kev_sub, ctem_kev_color), unsafe_allow_html=True)
        st.markdown(render_executive_kpi_card("FALSE POSITIVE SUPPRESSION", ctem_fp, ctem_fp_color, ctem_fp_sub, ctem_fp_color), unsafe_allow_html=True)

    with kpi_col2:
        st.markdown('<div style="font-size:0.75rem; font-weight:700; color:#a0a0c0; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:8px;">🐙 DevSecOps</div>', unsafe_allow_html=True)
        st.markdown(render_executive_kpi_card("AUTO-FIX SUCCESS RATE", dso_fix, dso_fix_color, dso_fix_sub, dso_fix_color), unsafe_allow_html=True)
        st.markdown(render_executive_kpi_card("DEPLOYMENT GATE PASS RATE", dso_gate, dso_gate_color, dso_gate_sub, dso_gate_color), unsafe_allow_html=True)
        st.markdown(render_executive_kpi_card("PR APPROVAL RATE", dso_pr, dso_pr_color, dso_pr_sub, dso_pr_color), unsafe_allow_html=True)
        st.markdown(render_executive_kpi_card("FINDINGS PER COMMIT (INV.)", max(0.0, 100.0 - dso_findings * 10), dso_findings_color, dso_findings_sub, dso_findings_color), unsafe_allow_html=True)

    st.markdown("---")

    # ── ROW 3: Segregated KPIs (Executive vs. Operational) ──
    col_exec, col_ops = st.columns([1.0, 1.0])

    with col_exec:
        st.markdown('<h3 style="margin-bottom: 16px;">📈 Operational Performance Index</h3>', unsafe_allow_html=True)

        # Cyber Resilience Index (overall index)
        readiness_index = kpi_engine.get_ai_readiness_index()
        st.markdown(render_kpi_progress_card(
            label="Calculated AI Readiness Index",
            value=readiness_index,
            max_value=100.0,
            color=ACCENT_BLUE if readiness_index >= 70 else RAG_AMBER,
            subtext="Weighted computational score from live/synthetic datasets"
        ), unsafe_allow_html=True)

        # Vulnerability mitigation coverage
        exposure_cov = kpi_engine.get_kpi("Vuln Exposure Coverage")
        mitigation_rate = 100.0 - exposure_cov
        st.markdown(render_kpi_progress_card(
            label="Active Exposure Suppression Rate",
            value=mitigation_rate,
            max_value=100.0,
            color=ACCENT_BLUE if mitigation_rate >= 75 else RAG_AMBER,
            subtext=f"Proportion of systems verified safe ({exposure_cov:.1f}% exposure remains)"
        ), unsafe_allow_html=True)

        # AI Remediation SLA performance
        sla_breach = kpi_engine.get_kpi("P1 SLA Breach Rate")
        sla_compliance = 100.0 - sla_breach
        st.markdown(render_kpi_progress_card(
            label="Remediation SLA Compliance Rate",
            value=sla_compliance,
            max_value=100.0,
            color=ACCENT_BLUE if sla_compliance >= 90 else RAG_AMBER,
            subtext=f"P1 tickets resolved within target boundary ({sla_breach:.1f}% breached)"
        ), unsafe_allow_html=True)

        # DevSecOps auto-fix rate
        st.markdown(render_kpi_progress_card(
            label="DevSecOps Auto-Fix Success Rate",
            value=dso_fix,
            max_value=100.0,
            color=ACCENT_GREEN,
            subtext="AI-generated fixes that passed validation and merged"
        ), unsafe_allow_html=True)

        # DevSecOps deployment gate
        st.markdown(render_kpi_progress_card(
            label="DevSecOps Deployment Gate Pass Rate",
            value=dso_gate,
            max_value=100.0,
            color=ACCENT_GREEN,
            subtext="Security validation checks passed before the human-approval gate"
        ), unsafe_allow_html=True)

    with col_ops:
        # Build beautifully formatted technical operations table
        categories = {
            "Continuous Threat Exposure Management (CTEM)": [
                ("Vuln Exposure Coverage", "% assets with validated findings", "%"),
                ("False Positive Suppression Rate", "% findings suppressed as FPs", "%"),
                ("KEV Collision Rate", "% open CVEs on CISA KEV", "%"),
                ("MTTR", "Mean Time to Resolution", " Days"),
                ("P1 SLA Breach Rate", "% P1 past SLA due date", "%"),
            ],
            "AI-Led DevSecOps": [
                ("Findings per Commit", "Avg AI review findings per commit", ""),
                ("Auto-Fix Success Rate", "% AI-generated fixes merged", "%"),
                ("Mean Time to Fix", "Avg minutes from finding to generated fix", " Min"),
                ("PR Approval Rate", "% pull requests approved", "%"),
                ("Deployment Gate Pass Rate", "% security validation checks passed", "%"),
            ],
        }
        
        table_html = """
        <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 12px; padding: 18px; font-family: 'Inter', sans-serif;">
            <div style="font-size: 0.95rem; font-weight: 700; color: #a0a0c0; margin-bottom: 12px; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 8px;">
                📋 Operational KPIs & Technical Performance
            </div>
            <table style="width: 100%; border-collapse: collapse; font-size: 0.8rem; text-align: left;">
                <thead>
                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.06); color: #6b6b8d;">
                        <th style="padding: 6px 8px;">Metric Name</th>
                        <th style="padding: 6px 8px; text-align: right;">Value</th>
                        <th style="padding: 6px 8px; text-align: center;">Status</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for cat_name, metrics in categories.items():
            table_html += f"""
                    <tr style="background: rgba(255,255,255,0.01); font-weight: 700; color: #ffffff;">
                        <td colspan="3" style="padding: 10px 8px 4px 8px; font-size: 0.72rem; letter-spacing: 0.05em; text-transform: uppercase; color: #a0a0c0;">
                            {cat_name}
                        </td>
                    </tr>
            """
            for kpi_key, desc, unit in metrics:
                val = kpi_engine.get_kpi(kpi_key)
                
                # Dynamic RAG logic
                status_color = "#00ff88"
                status_text = "OPTIMAL"
                
                if kpi_key in ["P1 SLA Breach Rate", "MTTR", "MTTN", "Mean Time to Fix", "Findings per Commit"]:
                    # Lower is better
                    lower_is_better_limits = {
                        "P1 SLA Breach Rate": (10.0, 25.0),
                        "MTTR": (15.0, 30.0),
                        "MTTN": (2.0, 4.0),
                        "Mean Time to Fix": (10.0, 20.0),
                        "Findings per Commit": (2.0, 3.5),
                    }
                    limit_optimal, limit_warning = lower_is_better_limits[kpi_key]
                    if val <= limit_optimal:
                        status_color = "#00ff88"
                        status_text = "OPTIMAL"
                    elif val <= limit_warning:
                        status_color = "#ffaa00"
                        status_text = "WARNING"
                    else:
                        status_color = "#ff4444"
                        status_text = "CRITICAL"
                else:
                    # Higher is better
                    if val >= 80.0:
                        status_color = "#00ff88"
                        status_text = "OPTIMAL"
                    elif val >= 50.0:
                        status_color = "#ffaa00"
                        status_text = "STABLE"
                    else:
                        status_color = "#ff4444"
                        status_text = "DEFICIT"
                
                table_html += f"""
                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.02); color: #e8e8e8;">
                        <td style="padding: 6px 8px;" title="{desc}">{kpi_key}</td>
                        <td style="padding: 6px 8px; text-align: right; font-weight: 700; color: {status_color};">{val:.1f}{unit}</td>
                        <td style="padding: 6px 8px; text-align: center;">
                            <span style="display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.65rem; font-weight: bold; background: {status_color}15; color: {status_color}; border: 1px solid {status_color}30;">
                                {status_text}
                            </span>
                        </td>
                    </tr>
                """
                
        table_html += """
                </tbody>
            </table>
        </div>
        """
        
        # Use clean_html to prevent markdown interference
        from app.ui.theme import clean_html
        st.markdown(clean_html(table_html), unsafe_allow_html=True)

    # ── ROW 3: Historical Progress Trends & Severity Heatmaps ──
    st.markdown('<h2 style="margin-top: 32px;">📈 Posture Improvement & Severity Profiling</h2>', unsafe_allow_html=True)
    
    t_col1, t_col2 = st.columns([1, 1])
    
    with t_col1:
        # historical trends (30 days)
        dates = ["30 Days Ago", "20 Days Ago", "10 Days Ago", "5 Days Ago", "Current Posture"]
        trend_data = {
            "exposure_management": [55.2, 60.5, 66.8, 71.2, ctem_score],
            "devsecops": [58.0, 64.4, 70.1, 76.8, devsecops_score],
        }

        # Format the dictionary key names nicely for display
        series_dict = {
            "CTEM Exposure": trend_data["exposure_management"],
            "DevSecOps Velocity": trend_data["devsecops"],
        }
        
        fig_trend = create_trend_chart(dates, series_dict, "")
        
        with st.container(border=True):
            st.markdown('<div class="glass-card-anchor"></div>', unsafe_allow_html=True)
            st.markdown(f'<div style="font-size: 0.95rem; color: {TEXT_SECONDARY}; font-weight: 600; margin-bottom: 4px;">Optimization Vector</div><div style="font-size: 0.78rem; color: {TEXT_MUTED}; margin-bottom: 12px;">30-Day Score Optimization Timeline</div>', unsafe_allow_html=True)
            st.plotly_chart(fig_trend, use_container_width=True, key="historical_trends_line_chart")
        
    with t_col2:
        # Vulnerabilities Severity Profile
        vuln_df = datasets.get("vulnerability_findings")
        
        if vuln_df is not None and not vuln_df.empty:
            crit = len(vuln_df[vuln_df["cvss_score"] >= 9.0])
            high = len(vuln_df[(vuln_df["cvss_score"] >= 7.0) & (vuln_df["cvss_score"] < 9.0)])
            med = len(vuln_df[(vuln_df["cvss_score"] >= 4.0) & (vuln_df["cvss_score"] < 7.0)])
            low = len(vuln_df[vuln_df["cvss_score"] < 4.0])
        else:
            crit, high, med, low = 22, 104, 385, 98
            
        fig_donut = create_donut_chart(
            labels=["Critical (>=9.0)", "High (7.0-8.9)", "Medium (4.0-6.9)", "Low (<4.0)"],
            values=[crit, high, med, low],
            title="",
            colours=["#ff2222", ACCENT_RED, RAG_AMBER, ACCENT_BLUE]
        )
        
        with st.container(border=True):
            st.markdown('<div class="glass-card-anchor"></div>', unsafe_allow_html=True)
            st.markdown(f'<div style="font-size: 0.95rem; color: {TEXT_SECONDARY}; font-weight: 600; margin-bottom: 4px;">Active Vulnerabilities Profile</div><div style="font-size: 0.78rem; color: {TEXT_MUTED}; margin-bottom: 12px;">Enterprise Exposure Severity Mix</div>', unsafe_allow_html=True)
            st.plotly_chart(fig_donut, use_container_width=True, key="severity_mix_donut")
        
    # ── ROW 4: AI Operations Audit Log Snapshot ──
    st.markdown('<h2 style="margin-top: 32px;">🧾 Recent AI Operations & HITL Actions</h2>', unsafe_allow_html=True)
    
    # Retrieve recent operations from dynamic database AuditLogger
    from app.observability.audit_logger import AuditLogger
    logger = AuditLogger()
    live_logs = logger.get_logs(10)
    
    if len(live_logs) >= 2:
        audit_log = live_logs
    else:
        # Structured mock array fallback
        audit_log = [
            {
                "timestamp": (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"),
                "action": "Jira Ticket Sync",
                "target": "JIRA-48501",
                "status": "Success",
                "details": "Synchronised validated CTEM vulnerability findings ticket into developer board."
            },
            {
                "timestamp": (datetime.datetime.now() - datetime.timedelta(minutes=24)).strftime("%Y-%m-%d %H:%M:%S"),
                "action": "Host Containment Action",
                "target": "web-prod-01",
                "status": "Approved (HITL)",
                "details": "Isolate EDR agent due to anomalous beaconing signature mapped to MITRE technique T1059."
            },
            {
                "timestamp": (datetime.datetime.now() - datetime.timedelta(hours=1.5)).strftime("%Y-%m-%d %H:%M:%S"),
                "action": "Detection Rule Ingestion",
                "target": "SPL-882",
                "status": "Success",
                "details": "Compiled Chronicle Yara rule translated from Sigma gap T1078 (Active Directory enumeration)."
            },
            {
                "timestamp": (datetime.datetime.now() - datetime.timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S"),
                "action": "RAG Index Ingestion",
                "target": "FAISS Index 'hunt_events'",
                "status": "Success",
                "details": "Embedded and indexed 2,000 firewall NetFlow events mapped to active hunt workspace."
            }
        ]
    
    st.markdown('<div class="glass-card" style="padding: 20px;">', unsafe_allow_html=True)
    
    # Display table of recent operations
    audit_df = pd.DataFrame(audit_log)
    if not audit_df.empty:
        st.dataframe(
            audit_df[["timestamp", "action", "target", "status", "details"]],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No AI operations logged in the current session.")
        
    st.markdown('</div>', unsafe_allow_html=True)
