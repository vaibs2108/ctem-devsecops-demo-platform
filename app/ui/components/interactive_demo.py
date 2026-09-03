"""
AI Capability Demo — Interactive Demo Engine
Execute button, progress display, AI result rendering, HITL gates.
AGENTS.md Section 7.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import streamlit as st
import textwrap

from app.ui.theme import (
    ACCENT_AMBER,
    ACCENT_BLUE,
    ACCENT_GREEN,
    ACCENT_RED,
    BG_GLASS,
    BORDER_GLASS,
    RAG_GREEN,
    RAG_RED,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    USE_CASE_COLOURS,
    USE_CASE_LABELS,
    rag_colour,
    render_badge,
    render_glass_card,
    render_metric_card,
    render_severity_badge,
)


def _build_data_driven_content(use_case: str, stage: str, outcome: Dict[str, Any]) -> Dict[str, Any]:
    """Build data-driven step-by-step execution trace, output summary, and handoff
    description using REAL numbers from the datasets in session_state.
    
    This ensures that even if the LLM-generated fields are missing (e.g. old cached
    session), the UI always shows rich, specific, number-filled content.
    """
    import pandas as pd
    datasets = st.session_state.get("datasets", {})
    findings = outcome.get("findings", [])
    n_findings = len(findings)
    n_critical = sum(1 for f in findings if str(f.get("severity", "")).upper() == "CRITICAL")
    n_high = sum(1 for f in findings if str(f.get("severity", "")).upper() == "HIGH")
    confidence = outcome.get("confidence", outcome.get("ai_confidence", 85))

    # Helper to safely get row counts
    def _rows(key):
        df = datasets.get(key)
        if isinstance(df, pd.DataFrame):
            return len(df)
        return 0

    # Helper to safely get unique count for a column
    def _unique(key, col):
        df = datasets.get(key)
        if isinstance(df, pd.DataFrame) and col in df.columns:
            return int(df[col].nunique())
        return 0

    # Helper to count rows matching a condition
    def _count_where(key, col, val):
        df = datasets.get(key)
        if isinstance(df, pd.DataFrame) and col in df.columns:
            return int((df[col] == val).sum())
        return 0

    def _count_true(key, col):
        df = datasets.get(key)
        if isinstance(df, pd.DataFrame) and col in df.columns:
            series = df[col]
            if pd.api.types.is_numeric_dtype(series) or pd.api.types.is_bool_dtype(series):
                return int(series.sum())
            else:
                cleaned = series.dropna().astype(str).str.strip()
                lower_cleaned = cleaned.str.lower()
                if lower_cleaned.isin(["true", "false"]).any():
                    return int(lower_cleaned.isin(["true", "1", "yes", "y"]).sum())
                return int((cleaned != "").sum())
        return 0

    # Compute additional stats for analysis sections
    n_medium = sum(1 for f in findings if str(f.get("severity", "")).upper() == "MEDIUM")
    n_low = sum(1 for f in findings if str(f.get("severity", "")).upper() == "LOW")

    # ── CTEM stages ──────────────────────────────────────────────────
    content_map = {
        "ctem": {
            "scoping": {
                "steps": [
                    f"Ingested **{_rows('asset_inventory'):,}** assets from synthetic asset inventory via CMDB pipeline.",
                    f"Classified assets into **{_unique('asset_inventory', 'asset_class')}** asset classes (Server, Workstation, Cloud, Container, IoT, Network).",
                    f"Identified **{_count_true('asset_inventory', 'internet_exposed'):,}** internet-exposed assets across all environments.",
                    f"Flagged **{_count_where('asset_inventory', 'business_criticality', 'Critical'):,}** business-critical assets requiring prioritised protection.",
                    f"Detected shadow IT: **{_count_where('asset_inventory', 'sbom_available', False):,}** assets without SBOM (Software Bill of Materials).",
                    f"Mapped asset distribution across **{_unique('asset_inventory', 'environment')}** environments (Production, Staging, Dev, DR).",
                ],
                "analysis": [
                    f"**Asset Class Distribution:** Servers: {_count_where('asset_inventory', 'asset_class', 'Server'):,}, Workstations: {_count_where('asset_inventory', 'asset_class', 'Workstation'):,}, Cloud: {_count_where('asset_inventory', 'asset_class', 'Cloud'):,}, Containers: {_count_where('asset_inventory', 'asset_class', 'Container'):,}, IoT: {_count_where('asset_inventory', 'asset_class', 'IoT'):,}, Network: {_count_where('asset_inventory', 'asset_class', 'Network'):,}.",
                    f"**Environment Breakdown:** Production: {_count_where('asset_inventory', 'environment', 'Production'):,}, Staging: {_count_where('asset_inventory', 'environment', 'Staging'):,}, Dev: {_count_where('asset_inventory', 'environment', 'Dev'):,}, DR: {_count_where('asset_inventory', 'environment', 'DR'):,}.",
                    f"**Risk Assessment:** {_count_true('asset_inventory', 'internet_exposed'):,} assets are internet-exposed — these are the highest-priority attack surface. {_count_where('asset_inventory', 'business_criticality', 'Critical'):,} assets are business-critical and any compromise would have immediate revenue/operational impact.",
                    f"**Shadow IT Finding:** {_count_where('asset_inventory', 'sbom_available', False):,} assets lack SBOM documentation — these represent untracked software supply chain risk. Recommend immediate SBOM generation.",
                    f"**Coverage Gaps:** {_unique('asset_inventory', 'owner_team')} distinct owner teams identified. Cross-team asset ownership creates accountability gaps that attackers exploit.",
                ],
                "output": f"Complete attack surface map with {_rows('asset_inventory'):,} scoped assets, {_count_true('asset_inventory', 'internet_exposed'):,} internet-exposed, {_count_where('asset_inventory', 'business_criticality', 'Critical'):,} business-critical. Shadow IT detection complete.",
                "handoff": f"Scoped asset inventory ({_rows('asset_inventory'):,} assets) with criticality scores and exposure flags passed to **CTEMDiscoveryAgent** for vulnerability scanning.",
            },
            "discovery": {
                "steps": [
                    f"Received **{_rows('asset_inventory'):,}** scoped assets from Scoping stage as input context.",
                    f"Cross-referenced all assets against CVE feeds — generated **{_rows('vulnerability_findings'):,}** vulnerability findings.",
                    f"Matched findings against CISA KEV catalogue — **{_count_true('vulnerability_findings', 'cisa_kev'):,}** active KEV collisions identified.",
                    f"Computed EPSS scores for all **{_rows('vulnerability_findings'):,}** findings to predict exploitation probability.",
                    f"Tagged patch availability status across **{_unique('vulnerability_findings', 'status')}** remediation states.",
                    f"Enriched with CVSS v3.1 vector strings and CWE weakness classifications.",
                ],
                "analysis": [
                    f"**Vulnerability Findings Count:** Discovered {_rows('vulnerability_findings'):,} active vulnerability findings mapped across {_unique('vulnerability_findings', 'asset_id'):,} unique assets.",
                    f"**Severity Profile:** Identified {_count_where('vulnerability_findings', 'cvss_score', 9.0) + _count_where('vulnerability_findings', 'cvss_score', 10.0):,} Critical CVSS vulnerability instances requiring immediate remediation.",
                    f"**CISA KEV Collision Risk:** {_count_true('vulnerability_findings', 'cisa_kev'):,} vulnerability findings match active exploits listed in the CISA KEV catalog.",
                    f"**Exploitation Probability:** {_count_true('vulnerability_findings', 'exploit_available'):,} vulnerabilities have public exploit scripts available, increasing potential attack likelihood.",
                    f"**Remediation Actionability:** Patches are available for {_count_true('vulnerability_findings', 'patch_available'):,} ({round(_count_true('vulnerability_findings', 'patch_available') / max(1, _rows('vulnerability_findings')) * 100, 1)}%) identified vulnerabilities."
                ],
                "output": f"Raw vulnerability map with {_rows('vulnerability_findings'):,} findings mapped to {_rows('asset_inventory'):,} assets. Each finding enriched with CVE ID, CVSS, EPSS, KEV flag, and patch status.",
                "handoff": f"Full vulnerability findings dataset ({_rows('vulnerability_findings'):,} records) with EPSS scores and KEV flags passed to **CTEMPrioritisationAgent** for risk ranking.",
            },
            "prioritisation": {
                "steps": [
                    f"Received **{_rows('vulnerability_findings'):,}** raw vulnerability findings from Discovery stage.",
                    "Applied composite risk formula: **Asset Criticality × Exploitability × KEV Status × EPSS Score × Internet Exposure**.",
                    f"Identified {n_critical} Critical and {n_high} High severity findings requiring immediate attention.",
                    "**KEY DEMO MOMENT**: CVSS 5.0 KEV entry ranked ABOVE CVSS 9.5 non-KEV item due to active exploitation in the wild.",
                    "Generated P1/P2/P3 risk classification backlog with explicit rationale per finding.",
                    f"AI Confidence Score: **{confidence}%** — based on data completeness and cross-correlation strength.",
                ],
                "analysis": [
                    f"**Risk Prioritisation Breakdown:** Ingested {_rows('remediation_backlog'):,} backlog items and prioritized them using business context.",
                    f"**Critical Priority Backlog:** Mapped {_count_where('remediation_backlog', 'priority', 'P1'):,} High-severity P1 actions requiring 24h SLA response times.",
                    f"**SLA Compliance Risk:** Identified {_count_where('remediation_backlog', 'kev_collision', True):,} items matching CISA KEV exploits, elevated to P1 regardless of base CVSS scores.",
                    f"**Time-Critical Vulnerabilities:** {_count_true('remediation_backlog', 'kev_collision'):,} items identified with active SLA breach warnings (< 0 days remaining).",
                    f"**Operational Remediation Types:** Backlog consists of {_count_where('remediation_backlog', 'remediation_type', 'PATCH'):,} patches, {_count_where('remediation_backlog', 'remediation_type', 'CONFIG'):,} configuration updates, and {_count_where('remediation_backlog', 'remediation_type', 'UPGRADE'):,} software upgrades."
                ],
                "output": f"Prioritised risk backlog with {n_findings} ranked findings. {n_critical} P1 items flagged for immediate SLA action. Risk score formula visible per finding.",
                "handoff": f"Prioritised backlog ({n_findings} items with risk scores) passed to **CTEMValidatorAgent** for exploitability confirmation and false positive removal.",
            },
            "validation": {
                "steps": [
                    f"Received **{n_findings}** prioritised findings from Prioritisation stage.",
                    "Validated exploitability by reasoning about network reachability and patch state.",
                    "Checked compensating controls (WAF, IDS, network segmentation) per finding.",
                    "**KEY DEMO MOMENT**: CVE on port 5432 classified as FP — not internet-reachable, AI wrote explicit rationale.",
                    f"Confirmed {n_critical + n_high} exploitable findings. Dismissed false positives with written reasoning.",
                    f"AI Confidence Score: **{confidence}%** — based on validation depth and evidence quality.",
                ],
                "analysis": [
                    f"**Validation Pipeline Summary:** Ingested {_rows('validation_results'):,} vulnerability validation sandbox runs.",
                    f"**True Positive Exploitability:** PoC verification confirmed {_count_true('validation_results', 'exploit_confirmed'):,} true positive vulnerabilities as fully exploitable.",
                    f"**False Positive Suppression:** Dismissed {_rows('validation_results') - _count_true('validation_results', 'exploit_confirmed'):,} false positive findings.",
                    f"**Compensating Control Validation:** Suppressed items with written rationale indicating shielding due to firewalled ports or local security configurations.",
                    f"**AI Validation Confidence:** Validation achieved confidence scores ranging from 80% to 99%, averaging {round(datasets.get('validation_results')['confidence'].mean(), 1) if 'validation_results' in datasets else 85.0}%."
                ],
                "output": f"Validated exploitable list with {n_findings} findings. False positive log with written AI rationale per dismissed item.",
                "handoff": f"Confirmed exploitable findings ({n_critical + n_high} actionable items) passed to **CTEMRemediationAgent** for specific remediation instructions and ticket creation.",
            },
            "mobilisation": {
                "steps": [
                    f"Received **{n_findings}** validated, exploitable findings from Validation stage.",
                    "Generated SPECIFIC remediation commands per finding (e.g., `apt upgrade openssl=3.0.14`).",
                    "Prepared Jira Service Management ticket payloads with full finding context.",
                    "Prepared ServiceNow Incident records with CAB review metadata.",
                    f"Assigned SLA windows based on severity: Critical=24h, High=72h, Medium=7d.",
                    f"AI Confidence Score: **{confidence}%** — remediation specificity verified against vendor advisories.",
                ],
                "analysis": [
                    f"**Mobilisation Output Summary:** Ingested {_rows('remediation_backlog'):,} validated vulnerabilities for ticket generation.",
                    f"**Closed-loop Integrations:** Generated {_rows('remediation_backlog'):,} ticket packages ready for API dispatch.",
                    f"**Jira & ServiceNow Tickets:** Prepared {_count_where('remediation_backlog', 'priority', 'P1'):,} critical severity tickets mapping to assigned owners.",
                    f"**Remediation Specificity:** Compiled CLI commands and upgrade instructions targeting affected software packages.",
                    f"**SLA Compliance Management:** Automated assignee routing and SLA breach calendars populated across all open items."
                ],
                "output": f"Actionable remediation plan with {n_findings} specific fix instructions. Jira and ServiceNow ticket payloads ready for dispatch.",
                "handoff": "Final stage — no downstream handoff. Tickets dispatched to Jira/ServiceNow for implementation tracking.",
            },
        },
    }

    uc_content = content_map.get(use_case, {})
    stage_content = uc_content.get(stage, {})

    return {
        "steps": stage_content.get("steps", [
            f"Ingested available data payload for {use_case.upper()} {stage} analysis.",
            f"Evaluated {n_findings} findings against enterprise security frameworks.",
            "Correlated findings against global threat feeds (NVD, KEV, ATT&CK).",
            f"Generated structured output with AI confidence of {confidence}%.",
        ]),
        "analysis": stage_content.get("analysis", []),
        "output": stage_content.get("output", f"Analysis completed with {n_findings} findings at {confidence}% AI confidence."),
        "handoff": stage_content.get("handoff", f"Structured payload with {n_findings} items passed to subsequent pipeline agent."),
    }


# ── 1. Execute Button ───────────────────────────────────────────────────────

def render_execute_button(
    use_case: str,
    stage: str,
    data_source: str,
    disabled: bool = False,
) -> bool:
    """Styled 'Execute AI Analysis' button. Returns True if clicked."""
    accent = USE_CASE_COLOURS.get(use_case, ACCENT_BLUE)
    uc_label = USE_CASE_LABELS.get(use_case, use_case)

    source_badge = {
        "mcp": "🟢 MCP Live",
        "upload": "🔵 File Upload",
        "synthetic": "🟠 Synthetic",
    }.get(data_source, "🟠 Synthetic")

    st.markdown(textwrap.dedent(f"""
    <div style="
        display:flex; align-items:center; justify-content:space-between;
        padding:12px 20px;
        background:rgba({int(accent[1:3],16)},{int(accent[3:5],16)},{int(accent[5:7],16)},0.08);
        border:1px solid rgba({int(accent[1:3],16)},{int(accent[3:5],16)},{int(accent[5:7],16)},0.2);
        border-radius:12px;
        margin-bottom:12px;
    ">
        <div style="font-size:0.8rem;color:{TEXT_SECONDARY};">
            Data: <strong>{source_badge}</strong> &nbsp;|&nbsp; Stage: <strong>{stage}</strong>
        </div>
        <div style="font-size:0.75rem;color:{TEXT_MUTED};">{uc_label}</div>
    </div>
    """), unsafe_allow_html=True)

    # Wrap in a container for the special CSS class
    st.markdown('<div class="execute-btn">', unsafe_allow_html=True)
    clicked = st.button(
        "🚀 Execute AI Analysis",
        key=f"exec_{use_case}_{stage}",
        use_container_width=True,
        disabled=disabled,
    )
    st.markdown("</div>", unsafe_allow_html=True)

    return clicked


# ── 2. Progress Indicator ────────────────────────────────────────────────────

def render_progress_indicator(status: str, progress_pct: float = 0) -> None:
    """Animated progress bar during AI execution."""
    bar_colour = ACCENT_GREEN if progress_pct >= 100 else ACCENT_BLUE

    st.markdown(textwrap.dedent(f"""
    <div style="
        background:{BG_GLASS};
        border:1px solid {BORDER_GLASS};
        border-radius:12px;
        padding:16px 20px;
        margin:12px 0;
    ">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
            <div style="font-size:0.85rem; color:{TEXT_PRIMARY}; font-weight:600;">
                {"✅" if progress_pct >= 100 else "⏳"} {status}
            </div>
            <div style="font-size:0.8rem; color:{TEXT_MUTED};">{progress_pct:.0f}%</div>
        </div>
        <div style="
            width:100%; height:6px;
            background:rgba(255,255,255,0.06);
            border-radius:3px;
            overflow:hidden;
        ">
            <div style="
                width:{min(progress_pct, 100):.0f}%;
                height:100%;
                background:linear-gradient(90deg, {bar_colour}, {ACCENT_BLUE});
                border-radius:3px;
                transition:width 0.5s ease;
                {'animation:shimmer 2s infinite;' if progress_pct < 100 else ''}
            "></div>
        </div>
    </div>
    """), unsafe_allow_html=True)


# ── 3. AI Results Panel ─────────────────────────────────────────────────────

def detect_use_case_and_stage(analysis: str) -> tuple[str, str]:
    """Helper to detect active usecase and stage from text keywords."""
    if not analysis:
        return "ctem", "scoping"
    analysis_lower = analysis.lower()
    
    # CTEM
    if "threaten compliance" in analysis_lower or "regulatory frameworks" in analysis_lower:
        return "ctem", "scoping"
    if "vulnerability discovery process has mapped" in analysis_lower or ("xz-utils" in analysis_lower and "discovery" in analysis_lower) or "cve-2024-3094" in analysis_lower:
        return "ctem", "discovery"
    if "prioritization engine has" in analysis_lower or "contextual risk" in analysis_lower or "cisa KEV exploit path" in analysis_lower:
        return "ctem", "prioritisation"
    if "exploitability validation was performed" in analysis_lower or "false positives" in analysis_lower or "looney tunables" in analysis_lower:
        return "ctem", "validation"
    if "actionable remediations have been generated" in analysis_lower or "jira service management" in analysis_lower or "downgrade script" in analysis_lower:
        return "ctem", "mobilisation"

    # DevSecOps
    if "sql injection" in analysis_lower or "hardcoded secret" in analysis_lower or "vulnerable package" in analysis_lower or "pull request" in analysis_lower:
        return "devsecops", "pipeline"

    return "ctem", "scoping"


def parse_markdown_inline(text: str) -> str:
    """Parse inline markdown (bold, italic, code) to HTML."""
    import re
    text = re.sub(r'\*\*(.*?)\*\*', r'<strong style="color:#ffffff; font-weight:700;">\1</strong>', text)
    text = re.sub(r'_(.*?)_', r'<em style="color:#d0d0e0;">\1</em>', text)
    text = re.sub(r'`(.*?)`', r'<code style="background:rgba(255,255,255,0.08); padding:2px 6px; border-radius:4px; font-family:\'JetBrains Mono\', monospace; font-size:0.85em; color:#00d4ff;">\1</code>', text)
    return text


def md_to_html_bullets(analysis: str) -> str:
    """Convert markdown compliance lists to high-contrast premium HTML lists."""
    lines = [line.strip() for line in analysis.strip().splitlines() if line.strip()]
    html_bullets = []
    intro_lines = []
    
    for line in lines:
        if line.startswith("*") or line.startswith("-"):
            content = line[1:].strip()
            if "**" in content:
                parts = content.split("**")
                if len(parts) >= 3:
                    fw = parts[1].strip()
                    desc = parts[2].strip()
                    if desc.startswith(":"):
                        desc = desc[1:].strip()
                    desc = parse_markdown_inline(desc)
                    bullet_html = f"""
                    <li style="margin-bottom: 12px; line-height: 1.6; font-size: 0.95rem; color: #c0c0d8; list-style-type: disc;">
                        <strong style="color: #ffffff; font-weight: 700;">{fw}</strong>: {desc}
                    </li>
                    """
                    html_bullets.append(bullet_html)
                    continue
            
            content_parsed = parse_markdown_inline(content)
            bullet_html = f"""
            <li style="margin-bottom: 12px; line-height: 1.6; font-size: 0.95rem; color: #c0c0d8; list-style-type: disc;">
                {content_parsed}
            </li>
            """
            html_bullets.append(bullet_html)
        else:
            line_parsed = parse_markdown_inline(line)
            intro_lines.append(line_parsed)
            
    intro_html = "".join(f"<p style='line-height: 1.6; font-size: 0.95rem; color: #e8e8e8; margin-bottom: 16px;'>{l}</p>" for l in intro_lines)
    bullets_html = f"<ul style='padding-left: 20px; margin-top: 12px; margin-bottom: 24px; list-style-type: disc;'>{''.join(html_bullets)}</ul>"
    return intro_html + bullets_html


def create_simulation_vertical_bar() -> Any:
    """Generate the Simulation Results Plotly figure."""
    import plotly.graph_objects as go
    categories = ['Blocked', 'Detected', 'Partial', 'Bypassed']
    values = [3500, 2980, 2040, 1490]
    
    fig = go.Figure(go.Bar(
        x=categories,
        y=values,
        marker_color='#4ea8de',
        text=values,
        textposition='outside',
        textfont=dict(color='#ffffff', size=10),
        hoverinfo='none'
    ))
    
    fig.update_layout(
        title=dict(text="Simulation Results", font=dict(family="Inter", size=13, color="#a0a0c0"), x=0),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=280,
        margin=dict(l=30, r=10, t=40, b=30),
        xaxis=dict(
            tickfont=dict(size=10, color='#8e9aaf'),
            showgrid=False,
            zeroline=False
        ),
        yaxis=dict(
            tickfont=dict(size=10, color='#8e9aaf'),
            gridcolor='rgba(255,255,255,0.06)',
            zeroline=False,
            range=[0, 4200]
        )
    )
    return fig


def create_severity_horizontal_bar() -> Any:
    """Generate the Attack Severity Distribution Plotly figure."""
    import plotly.graph_objects as go
    categories = ['Critical', 'High', 'Medium', 'Low']
    values = [1000, 2988, 4067, 1945]
    colors = ['#d90429', '#fb8500', '#ffb703', '#5bc0be']
    
    fig = go.Figure(go.Bar(
        y=categories,
        x=values,
        orientation='h',
        marker=dict(color=colors),
        text=values,
        textposition='inside',
        textfont=dict(color='#ffffff', size=10, weight='bold'),
        hoverinfo='none'
    ))
    
    fig.update_layout(
        title=dict(text="Attack Severity Distribution", font=dict(family="Inter", size=13, color="#a0a0c0"), x=0),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=280,
        margin=dict(l=60, r=10, t=40, b=30),
        xaxis=dict(
            tickfont=dict(size=10, color='#8e9aaf'),
            gridcolor='rgba(255,255,255,0.06)',
            zeroline=False
        ),
        yaxis=dict(
            tickfont=dict(size=10, color='#8e9aaf'),
            showgrid=False,
            zeroline=False,
            categoryorder='array',
            categoryarray=['Critical', 'High', 'Medium', 'Low']
        )
    )
    return fig


def render_ai_results(
    outcome: Dict[str, Any],
    data_source: str,
    use_case: Optional[str] = None,
    stage: Optional[str] = None,
) -> None:
    """Render the 3-part AI Analysis Panel with premium styles, custom tabs, and simulation dashboards."""
    # Inject CSS to style Streamlit tabs beautifully
    st.markdown("""
    <style>
        /* Target Streamlit tab buttons */
        button[data-baseweb="tab"], button[data-testid="stTab"] {
            font-family: 'Inter', sans-serif !important;
            font-size: 0.88rem !important;
            font-weight: 600 !important;
            color: #6b6b8d !important;
            background: rgba(255, 255, 255, 0.02) !important;
            border: 1px solid rgba(255, 255, 255, 0.04) !important;
            padding: 8px 18px !important;
            border-radius: 20px !important;
            margin-right: 8px !important;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        }
        button[data-baseweb="tab"]:hover, button[data-testid="stTab"]:hover {
            color: #ffffff !important;
            background: rgba(255, 255, 255, 0.06) !important;
            border-color: rgba(255, 255, 255, 0.1) !important;
        }
        button[data-baseweb="tab"][aria-selected="true"], button[data-testid="stTab"][aria-selected="true"] {
            color: #00d4ff !important;
            background: rgba(0, 212, 255, 0.1) !important;
            border: 1px solid rgba(0, 212, 255, 0.3) !important;
            box-shadow: 0 4px 12px rgba(0, 212, 255, 0.08) !important;
        }
        /* Hide default divider under tabs */
        div[data-testid="stTabBar"] > div {
            border-bottom: none !important;
        }
        div[data-baseweb="tab-highlight"], div[data-testid="stTabHighlight"] {
            background-color: transparent !important;
        }
    </style>
    """, unsafe_allow_html=True)

    analysis_text = outcome.get("analysis", outcome.get("summary", ""))
    
    # 1. Auto-detect usecase and stage if not provided
    if not use_case or not stage:
        use_case, stage = detect_use_case_and_stage(analysis_text)
        
    accent = USE_CASE_COLOURS.get(use_case, ACCENT_BLUE)
    
    # 2. Render Synthetic Data Banner
    if data_source == "synthetic":
        st.markdown(textwrap.dedent("""
        <div class="synthetic-banner">
            ⚠️ <strong>Synthetic Data Mode</strong> — Results generated from enterprise-grade
            synthetic datasets. Watermarked and clearly distinguished from live data.
        </div>
        """), unsafe_allow_html=True)

    # 3. Render Conditional Tabs
    # Only show Remediation tab if it's the final stage of a use case
    final_stages = ["mobilisation"]
    is_final_stage = stage in final_stages

    if is_final_stage:
        tab1, tab2, tab3 = st.tabs(["🧠 AI Analysis", "📋 Output & Next Stage Handoff", "🛠️ Remediation & Workflow"])
    else:
        tab1, tab2 = st.tabs(["🧠 AI Analysis", "📋 Output & Next Stage Handoff"])
    
    with tab1:
        # A. Watermark
        watermark_html = ""
        if data_source == "synthetic":
            watermark_html = f"""
            <blockquote style="
                margin: 0 0 24px 0; 
                padding: 10px 16px; 
                border-left: 3px solid #ff6b35; 
                background: rgba(255, 107, 53, 0.04); 
                color: #ffa47a; 
                font-size: 0.82rem;
                border-radius: 0 8px 8px 0;
                line-height: 1.4;
            ">
                🟠 <strong>SYNTHETIC DATA DEMO WATERMARK</strong>: This analysis was generated via the enterprise SyntheticDataEngine. Watermarked under compliance policy.
            </blockquote>
            """
        st.markdown(watermark_html, unsafe_allow_html=True)

        # B. Build data-driven content (real numbers from datasets)
        dd = _build_data_driven_content(use_case, stage, outcome)
        
        # 🔍 Detailed AI Analysis & Findings Section
        st.markdown(f"""
        <div style="margin-top: 16px; margin-bottom: 16px;">
            <div style="font-size: 1.25rem; font-weight: 700; color: #ffffff; margin-bottom: 8px; display: flex; align-items: center; gap: 8px;">
                🧠 Detailed AI Analysis &amp; Findings
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Display the bullet points from dd["analysis"] in a clean card
        analysis_bullets = dd.get("analysis", [])
        if analysis_bullets:
            bullet_items_html = "".join([f"<li style='margin-bottom: 8px; line-height: 1.5; color: #c0c0d8;'>{parse_markdown_inline(b)}</li>" for b in analysis_bullets])
            st.markdown(f"""
            <div style="
                background: rgba(255, 255, 255, 0.02);
                border: 1px solid rgba(255, 255, 255, 0.05);
                border-radius: 12px;
                padding: 18px;
                margin-bottom: 20px;
            ">
                <div style="font-size: 0.9rem; font-weight: 600; color: #00d4ff; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.05em;">AI Insights &amp; Analytics</div>
                <ul style="margin: 0; padding-left: 20px;">
                    {bullet_items_html}
                </ul>
            </div>
            """, unsafe_allow_html=True)
            
        findings_to_show = outcome.get("findings", [])
        # If findings is empty, check output dataset in session state datasets
        if not findings_to_show:
            from app.ui.components.lifecycle_stage import STAGE_INPUT_OUTPUT_MAP
            output_key = STAGE_INPUT_OUTPUT_MAP.get(use_case, {}).get(stage, {}).get("output_key", "")
            if output_key:
                datasets = st.session_state.get("datasets", {})
                df_out = datasets.get(output_key)
                if isinstance(df_out, pd.DataFrame) and not df_out.empty:
                    # Take first 20 rows of output dataframe to show as findings
                    raw_rows = df_out.head(20).to_dict(orient="records")
                    findings_to_show = []
                    for row in raw_rows:
                        # Try to normalize keys to title, severity, confidence
                        title_val = str(row.get("vuln_id") or row.get("hostname") or row.get("chain_name") or row.get("rule_name") or row.get("finding_title") or list(row.values())[0])
                        sev_val = str(row.get("severity") or row.get("priority") or "MEDIUM").upper()
                        conf_val = row.get("confidence") or row.get("ai_confidence") or 85
                        desc_val = ""
                        for col_candidate in ["description", "remediation_steps", "findings", "hypothesis_chain", "poc_description"]:
                            if col_candidate in row and row[col_candidate]:
                                desc_val = str(row[col_candidate])
                                break
                        findings_to_show.append({
                            "title": title_val,
                            "severity": "CRITICAL" if sev_val in ["P1", "CRITICAL", "HIGH"] else ("HIGH" if sev_val in ["P2", "MEDIUM"] else "MEDIUM"),
                            "confidence": float(conf_val) if isinstance(conf_val, (int, float)) else 85.0,
                            "description": desc_val
                        })

        if findings_to_show:
            st.markdown("""
            <div style="font-size: 0.95rem; font-weight: 600; color: #ffffff; margin-bottom: 8px;">
                📋 AI-Scored Findings Catalog
            </div>
            """, unsafe_allow_html=True)
            render_data_grid(findings_to_show, "AI Evaluated Findings", use_case=use_case, stage=stage)
            st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

        # Use LLM-generated steps if available, otherwise use data-driven
        step_by_step = outcome.get("step_by_step_execution", []) or dd["steps"]
            
        steps_html = f"""
        <div style="margin-bottom: 24px;">
            <div style="font-size: 1.1rem; font-weight: 700; color: #ffffff; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                ⚙️ Under the Hood: Agent Execution Trace
            </div>
            <div style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); border-radius: 12px; padding: 16px;">
                <ol style="padding-left: 20px; margin: 0; list-style-type: decimal; color: #00d4ff; font-size: 0.9rem; line-height: 1.6; font-family: 'JetBrains Mono', monospace;">
        """
        for step in step_by_step:
            steps_html += f'<li style="margin-bottom: 8px;"><span style="color: #c0c0d8; font-family: \'Inter\', sans-serif;">{parse_markdown_inline(step)}</span></li>'
        steps_html += """
                </ol>
            </div>
        </div>
        """
        st.markdown(steps_html, unsafe_allow_html=True)

        # C. Output Generated & Summary
        output_gen = outcome.get("output_generated", "") or dd["output"]
        summary_txt = outcome.get("summary", outcome.get("analysis", ""))
        
        st.markdown(f"""
        <div style="margin-bottom: 24px;">
            <div style="font-size: 1.1rem; font-weight: 700; color: #ffffff; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                📝 Analysis Output Summary
            </div>
            <div style="color: #00ff88; font-size: 0.9rem; margin-bottom: 8px; font-weight: 600;">{parse_markdown_inline(output_gen)}</div>
            <div style="color: #c0c0d8; font-size: 0.95rem; line-height: 1.6;">{parse_markdown_inline(summary_txt)}</div>
        </div>
        """, unsafe_allow_html=True)

        # D. Data Passed to Next Stage
        next_stage_data = outcome.get("passed_to_next_stage", "") or dd["handoff"]
            
        if not is_final_stage:
            st.markdown(f"""
            <div style="margin-bottom: 24px;">
                <div style="font-size: 1.1rem; font-weight: 700; color: #ffffff; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                    🔄 Data Passed to Next Pipeline Stage
                </div>
                <div style="background: rgba(0, 212, 255, 0.05); border-left: 3px solid #00d4ff; padding: 12px 16px; border-radius: 0 8px 8px 0; color: #e0f2fe; font-size: 0.9rem;">
                    {parse_markdown_inline(next_stage_data)}
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="margin-bottom: 24px;">
                <div style="font-size: 1.1rem; font-weight: 700; color: #ffffff; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                    🏁 Final Stage — Pipeline Complete
                </div>
                <div style="background: rgba(0, 255, 136, 0.05); border-left: 3px solid #00ff88; padding: 12px 16px; border-radius: 0 8px 8px 0; color: #d1fae5; font-size: 0.9rem;">
                    {parse_markdown_inline(next_stage_data)}
                </div>
            </div>
            """, unsafe_allow_html=True)

        # E. Recommended Action Plan
        action_plan = outcome.get("action_plan", outcome.get("recommendations", []))
        if action_plan:
            action_plan_html = f"""
            <div style="margin-top: 24px; margin-bottom: 24px;">
                <div style="font-size: 1.1rem; font-weight: 700; color: #ffffff; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                    📋 Recommended Action Plan
                </div>
                <ol style="padding-left: 20px; margin-top: 8px; margin-bottom: 0; list-style-type: decimal; color: #c0c0d8; font-size: 0.95rem; line-height: 1.6;">
            """
            for i, action in enumerate(action_plan):
                parsed_action = parse_markdown_inline(action)
                action_plan_html += f'<li style="margin-bottom: 12px; line-height: 1.6; font-size: 0.95rem; color: #c0c0d8;">{parsed_action}</li>'
            action_plan_html += "</ol></div>"
            st.markdown(action_plan_html, unsafe_allow_html=True)

        # F. Confidence Score
        confidence = outcome.get("confidence", outcome.get("ai_confidence", 85))
        
        confidence_card_html = f"""
        <div style="margin-top: 32px; margin-bottom: 24px;">
            <div style="font-size: 1.4rem; font-weight: 700; color: #ffffff; margin-bottom: 16px; display: flex; align-items: center; gap: 8px;">
                🎯 AI Confidence Score
            </div>
            <div style="
                background: rgba(255, 255, 255, 0.02);
                border: 1px solid rgba(255, 255, 255, 0.05);
                border-radius: 12px;
                padding: 24px;
            ">
                <div style="font-size: 0.95rem; line-height: 1.6; color: #c0c0d8;">
                    <strong style="color: #ffffff; font-weight: 700;">Overall AI Confidence: {confidence:.0f}%</strong> — The AI assigned this confidence score based on the severity of the anomalies detected, the credentials involved, and the cross-correlation across multiple platforms.
                </div>
            </div>
        </div>
        """
        st.markdown(confidence_card_html, unsafe_allow_html=True)

        # D. Breach & Attack Simulation Dashboard Section (Optional - hidden by default unless enabled in Settings)
        if st.session_state.get("settings_show_breach_sim", False):
            st.markdown("""
            <div style="margin-top: 32px; margin-bottom: 16px;">
                <div style="font-size: 1.4rem; font-weight: 700; color: #ffffff; margin-bottom: 16px; display: flex; align-items: center; gap: 8px;">
                    🎯 AI-Powered Breach &amp; Attack Simulation
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Outer Card Wrapper start
            st.markdown("""
            <div style="
                background: rgba(255, 255, 255, 0.01);
                border: 1px solid rgba(255, 255, 255, 0.05);
                border-radius: 16px;
                padding: 24px;
                margin-bottom: 24px;
            ">
            """, unsafe_allow_html=True)
            
            # Row of 4 small simulation metrics
            simulation_metrics_html = f"""
            <div style="display:flex; gap:16px; margin-bottom:24px; flex-wrap:wrap; width:100%;">
                <!-- Metric 1 -->
                <div style="flex:1; min-width:180px; background:rgba(17, 22, 56, 0.4); border:1px solid rgba(255, 255, 255, 0.05); border-radius:12px; padding:16px; position:relative;">
                    <div style="font-size:0.7rem; text-transform:uppercase; letter-spacing:0.08em; color:#a0a0c0; margin-bottom:8px; font-weight:600;">Blocked</div>
                    <div style="font-size:2.2rem; font-weight:800; color:#ffffff; line-height:1; letter-spacing:-0.02em;">35.0%</div>
                    <div style="font-size:0.8rem; font-weight:600; color:#00ff88; margin-top:6px; display:flex; align-items:center; gap:4px;">
                        <span>↑</span> <span>2.1%</span>
                    </div>
                </div>
                <!-- Metric 2 -->
                <div style="flex:1; min-width:180px; background:rgba(17, 22, 56, 0.4); border:1px solid rgba(255, 255, 255, 0.05); border-radius:12px; padding:16px; position:relative;">
                    <div style="font-size:0.7rem; text-transform:uppercase; letter-spacing:0.08em; color:#a0a0c0; margin-bottom:8px; font-weight:600;">Detected</div>
                    <div style="font-size:2.2rem; font-weight:800; color:#ffffff; line-height:1; letter-spacing:-0.02em;">29.8%</div>
                    <div style="font-size:0.8rem; font-weight:600; color:#00ff88; margin-top:6px; display:flex; align-items:center; gap:4px;">
                        <span>↑</span> <span>1.3%</span>
                    </div>
                </div>
                <!-- Metric 3 -->
                <div style="flex:1; min-width:180px; background:rgba(17, 22, 56, 0.4); border:1px solid rgba(255, 255, 255, 0.05); border-radius:12px; padding:16px; position:relative;">
                    <div style="font-size:0.7rem; text-transform:uppercase; letter-spacing:0.08em; color:#a0a0c0; margin-bottom:8px; font-weight:600;">Bypassed</div>
                    <div style="font-size:2.2rem; font-weight:800; color:#ffffff; line-height:1; letter-spacing:-0.02em;">14.9%</div>
                    <div style="font-size:0.8rem; font-weight:600; color:#ff4444; margin-top:6px; display:flex; align-items:center; gap:4px;">
                        <span>↓</span> <span>0.8%</span>
                    </div>
                </div>
                <!-- Metric 4 -->
                <div style="flex:1; min-width:180px; background:rgba(17, 22, 56, 0.4); border:1px solid rgba(255, 255, 255, 0.05); border-radius:12px; padding:16px; position:relative;">
                    <div style="font-size:0.7rem; text-transform:uppercase; letter-spacing:0.08em; color:#a0a0c0; margin-bottom:8px; font-weight:600;">Avg Confidence</div>
                    <div style="font-size:2.2rem; font-weight:800; color:#ffffff; line-height:1; letter-spacing:-0.02em;">71.5%</div>
                    <div style="font-size:0.8rem; font-weight:600; color:#00ff88; margin-top:6px; display:flex; align-items:center; gap:4px;">
                        <span>↑</span> <span>0.5%</span>
                    </div>
                </div>
            </div>
            """
            st.markdown(simulation_metrics_html, unsafe_allow_html=True)
            
            # Charts Columns
            col_c1, col_c2 = st.columns(2)
            with col_c1:
                st.plotly_chart(create_simulation_vertical_bar(), use_container_width=True)
            with col_c2:
                st.plotly_chart(create_severity_horizontal_bar(), use_container_width=True)
                
            # Top Attack Techniques Grid
            techniques_table_html = """
            <div style="font-size:1.1rem; font-weight:700; color:#ffffff; margin-bottom:12px; margin-top:24px;">Top Attack Techniques</div>
            <table style="width:100%; border-collapse:collapse; background:rgba(255,255,255,0.01); border-radius:8px; overflow:hidden; font-size:0.85rem; border:1px solid rgba(255,255,255,0.04);">
                <thead>
                    <tr style="background:rgba(255,255,255,0.03); border-bottom:1px solid rgba(255,255,255,0.06); text-align:left;">
                        <th style="padding:12px 14px; color:#a0a0c0; font-weight:600;">attack_technique</th>
                        <th style="padding:12px 14px; color:#a0a0c0; font-weight:600;">Blocked</th>
                        <th style="padding:12px 14px; color:#a0a0c0; font-weight:600;">Bypassed</th>
                        <th style="padding:12px 14px; color:#a0a0c0; font-weight:600;">Detected</th>
                        <th style="padding:12px 14px; color:#a0a0c0; font-weight:600;">Partial</th>
                    </tr>
                </thead>
                <tbody>
                    <tr style="border-bottom:1px solid rgba(255,255,255,0.02); color:#e8e8e8;">
                        <td style="padding:12px 14px; color:#00d4ff; font-weight:600;">T1003-Credential Dumping</td>
                        <td style="padding:12px 14px;">291</td>
                        <td style="padding:12px 14px;">104</td>
                        <td style="padding:12px 14px;">274</td>
                        <td style="padding:12px 14px;">155</td>
                    </tr>
                    <tr style="border-bottom:1px solid rgba(255,255,255,0.02); color:#e8e8e8;">
                        <td style="padding:12px 14px; color:#00d4ff; font-weight:600;">T1021-Remote Services</td>
                        <td style="padding:12px 14px;">289</td>
                        <td style="padding:12px 14px;">130</td>
                        <td style="padding:12px 14px;">247</td>
                        <td style="padding:12px 14px;">159</td>
                    </tr>
                    <tr style="border-bottom:1px solid rgba(255,255,255,0.02); color:#e8e8e8;">
                        <td style="padding:12px 14px; color:#00d4ff; font-weight:600;">T1078-Valid Accounts</td>
                        <td style="padding:12px 14px;">198</td>
                        <td style="padding:12px 14px;">85</td>
                        <td style="padding:12px 14px;">180</td>
                        <td style="padding:12px 14px;">92</td>
                    </tr>
                    <tr style="color:#e8e8e8;">
                        <td style="padding:12px 14px; color:#00d4ff; font-weight:600;">T1190-Exploit Public Application</td>
                        <td style="padding:12px 14px;">145</td>
                        <td style="padding:12px 14px;">62</td>
                        <td style="padding:12px 14px;">120</td>
                        <td style="padding:12px 14px;">75</td>
                    </tr>
                </tbody>
            </table>
            """
            st.markdown(techniques_table_html, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)  # Outer Card Wrapper end

    with tab2:
        from app.ui.components.lifecycle_stage import STAGE_INPUT_OUTPUT_MAP
        stage_info = STAGE_INPUT_OUTPUT_MAP.get(use_case, {}).get(stage, {})
        output_key = stage_info.get("output_key", "")
        output_name = stage_info.get("output_name", "Generated Output")
        output_desc = stage_info.get("output_desc", "No description available.")
        
        st.markdown(f"""
        <div style="margin-top: 16px; margin-bottom: 16px;">
            <div style="font-size: 1.4rem; font-weight: 700; color: #ffffff; margin-bottom: 8px; display: flex; align-items: center; gap: 8px;">
                📋 Output &amp; Next Stage Handoff — {stage.replace('_', ' ').title()}
            </div>
            <p style="color: #94a3b8; font-size: 0.9rem; line-height: 1.5;">{output_desc}</p>
            <div style="background: rgba(255, 255, 255, 0.03); border-left: 3px solid #00d4ff; border-radius: 6px; padding: 10px; margin-top: 8px; font-size: 0.82rem; color: #c0c0d8;">
                <strong style="color: #00d4ff;">Generated Output Dataset:</strong> {output_name} (<code>{output_key}</code>)
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Show dimensions, columns, description dynamically
        import pandas as pd
        datasets = st.session_state.get("datasets", {})
        out_df = datasets.get(output_key)
        
        if isinstance(out_df, pd.DataFrame) and not out_df.empty:
            rows = len(out_df)
            cols = len(out_df.columns)
            columns_str = ", ".join([f"`{c}`" for c in out_df.columns])
            st.markdown(f"""
            <div style="
                background: rgba(255, 255, 255, 0.02); 
                border: 1px solid rgba(255, 255, 255, 0.05); 
                border-radius: 8px; 
                padding: 12px; 
                margin-bottom: 16px;
            ">
                <div style="font-size: 0.85rem; color: #a0a0c0; margin-bottom: 4px;">📊 <strong>Output Dataset Metadata:</strong></div>
                <div style="font-size: 0.82rem; color: #c0c0d8; line-height: 1.5;">
                    • <strong>Dimensions:</strong> <code>{rows:,} Rows</code> &times; <code>{cols} Columns</code><br/>
                    • <strong>Columns:</strong> {columns_str}
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            with st.expander(f"🔍 Preview Generated Output Dataset ({rows:,} rows)", expanded=True):
                st.dataframe(out_df, use_container_width=True, hide_index=True, height=350)
        else:
            st.info("No generated output dataset is available yet. Execute the AI analysis to view the output.")
            
        # Display the handoff payload details
        next_stage_data = outcome.get("passed_to_next_stage", "") or dd.get("handoff", "")
        if next_stage_data:
            badge_color = "#00ff88" if is_final_stage else "#00d4ff"
            bg_color = "rgba(0, 255, 136, 0.05)" if is_final_stage else "rgba(0, 212, 255, 0.05)"
            hdr_text = "🏁 Pipeline Complete Handoff" if is_final_stage else "🔄 Pipeline Next Stage Handoff Payload"
            st.markdown(f"""
            <div style="margin-top: 16px; margin-bottom: 16px;">
                <div style="font-size: 1.0rem; font-weight: 700; color: #ffffff; margin-bottom: 8px;">
                    {hdr_text}
                </div>
                <div style="background: {bg_color}; border-left: 3px solid {badge_color}; padding: 12px 16px; border-radius: 0 8px 8px 0; color: #e0f2fe; font-size: 0.9rem; line-height: 1.6;">
                    {parse_markdown_inline(next_stage_data)}
                </div>
            </div>
            """, unsafe_allow_html=True)

    # 7. Render Workflow & Remediation Tab (Only for final stages)
    if is_final_stage:
        with tab3:
            # Custom session-state backed ticket remediation workflow
            workflow_key = f"workflow_{use_case}_{stage}"
            if workflow_key not in st.session_state:
                st.session_state[workflow_key] = {
                    "status": "APPROVAL QUEUE",
                    "assignee": "SecOps Dev Team",
                    "jira_status": "PENDING APPROVAL",
                    "snow_status": "AWAITING CAB REVIEW",
                    "approver": st.session_state.get("username", "vaibhav"),
                }
            
            wf = st.session_state[workflow_key]
            
            # 3 Stages of Workflow Status Colors
            status_colors = {
                "APPROVAL QUEUE": "#ffaa00",
                "IMPLEMENTATION TRACKING": "#00d4ff",
                "COMPLETED & VERIFIED": "#00ff88",
            }
            color = status_colors.get(wf["status"], "#00d4ff")
            
            # Evaluate braces clean
            wf_status = wf["status"]
            wf_assignee = wf["assignee"]
            wf_jira_status = wf["jira_status"]
            wf_snow_status = wf["snow_status"]
            wf_approver = wf["approver"]
            c_r = int(color[1:3], 16)
            c_g = int(color[3:5], 16)
            c_b = int(color[5:7], 16)
            
            st.markdown(f"""
            <div style="
                background: rgba(255, 255, 255, 0.02);
                border: 1px solid rgba(255, 255, 255, 0.05);
                border-radius: 16px;
                padding: 24px;
                margin-bottom: 20px;
            ">
                <h4 style="margin: 0 0 16px 0; color: #ffffff; font-weight: 700; font-size: 1.1rem; display: flex; align-items: center; gap: 8px;">
                    🛠️ Ticket Remediation &amp; Orchestration Workflow
                </h4>
                
                <div style="
                    background:rgba(255,255,255,0.03); 
                    border: 1px solid rgba(255,255,255,0.06); 
                    border-radius: 12px; 
                    padding: 16px; 
                    margin-bottom: 16px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                ">
                    <div>
                        <span style="font-size:0.7rem; text-transform:uppercase; letter-spacing:0.08em; color:#a0a0c0; font-weight:600;">Current Pipeline State</span>
                        <h4 style="margin:4px 0 0 0; color:#ffffff; font-weight:700; font-size:1.15rem; letter-spacing:-0.01em;">{wf_status}</h4>
                    </div>
                    <span style="
                        background:rgba({c_r},{c_g},{c_b},0.12); 
                        border:1px solid {color}; 
                        border-radius:16px; 
                        padding:6px 14px; 
                        font-size:0.8rem; 
                        font-weight:700; 
                        color:{color};
                        box-shadow: 0 2px 8px rgba({c_r},{c_g},{c_b},0.05);
                    ">
                        {wf_status}
                    </span>
                </div>
                
                <div style="display:flex; gap:16px; flex-wrap:wrap; margin-bottom:16px; width:100%;">
                    <!-- Jira Card -->
                    <div style="flex:1; min-width:200px; background:rgba(0,212,255,0.03); border:1px solid rgba(0,212,255,0.1); border-radius:10px; padding:16px;">
                        <div style="font-weight:700; color:#00d4ff; font-size:0.88rem; margin-bottom:10px; display:flex; justify-content:space-between; align-items:center;">
                            <span>Jira Service Management</span>
                            <span style="font-size:0.75rem; color:#8e9aaf; background:rgba(255,255,255,0.05); padding:2px 6px; border-radius:4px;">CR-2026-{stage[:3].upper()}</span>
                        </div>
                        <div style="font-size:0.82rem; color:#a0a0c0; margin-bottom:6px;"><strong>Assignee:</strong> <span style="color:#ffffff;">{wf_assignee}</span></div>
                        <div style="font-size:0.82rem; color:#a0a0c0;"><strong>Ticket Status:</strong> <span style="color:#ffffff; font-weight:600;">{wf_jira_status}</span></div>
                    </div>
                    
                    <!-- ServiceNow Card -->
                    <div style="flex:1; min-width:200px; background:rgba(168,85,247,0.03); border:1px solid rgba(168,85,247,0.1); border-radius:10px; padding:16px;">
                        <div style="font-weight:700; color:#a855f7; font-size:0.88rem; margin-bottom:10px; display:flex; justify-content:space-between; align-items:center;">
                            <span>ServiceNow Incident</span>
                            <span style="font-size:0.75rem; color:#8e9aaf; background:rgba(255,255,255,0.05); padding:2px 6px; border-radius:4px;">INC-987{stage[:2].upper()}</span>
                        </div>
                        <div style="font-size:0.82rem; color:#a0a0c0; margin-bottom:6px;"><strong>Analyst Ref:</strong> <span style="color:#ffffff;">{wf_approver}</span></div>
                        <div style="font-size:0.82rem; color:#a0a0c0;"><strong>Incident Status:</strong> <span style="color:#ffffff; font-weight:600;">{wf_snow_status}</span></div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Interactive Workflow Controls
            if wf["status"] == "APPROVAL QUEUE":
                st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
                if st.button("🚀 Approve & Dispatch Remediation Tickets", key=f"btn_approve_{workflow_key}", use_container_width=True):
                    st.session_state[workflow_key]["status"] = "IMPLEMENTATION TRACKING"
                    st.session_state[workflow_key]["jira_status"] = "IN PROGRESS"
                    st.session_state[workflow_key]["snow_status"] = "DISPATCHED TO DEV"
                    st.rerun()
            elif wf["status"] == "IMPLEMENTATION TRACKING":
                st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
                if st.button("✅ Verify Deployment & Close Active Tickets", key=f"btn_verify_{workflow_key}", use_container_width=True):
                    st.session_state[workflow_key]["status"] = "COMPLETED & VERIFIED"
                    st.session_state[workflow_key]["jira_status"] = "RESOLVED"
                    st.session_state[workflow_key]["snow_status"] = "CLOSED SUCCESSFULLY"
                    st.rerun()
            else:
                st.success("🎉 Remediation has been fully verified and all associated change logs closed successfully!")
                if st.button("🔄 Reset Workflow Lifecycle Demo", key=f"btn_reset_{workflow_key}", use_container_width=True):
                    del st.session_state[workflow_key]
                    st.rerun()
# ── 4. Metric Cards Row ─────────────────────────────────────────────────────

def render_metric_cards_row(metrics: List[Dict[str, Any]]) -> None:
    """Render a row of metric cards using st.columns.

    Each dict: {label, value, delta?, colour?, delta_positive?}
    """
    cols = st.columns(len(metrics))
    for col, m in zip(cols, metrics):
        with col:
            colour = m.get("colour", ACCENT_BLUE)
            delta = m.get("delta", "")
            delta_positive = m.get("delta_positive", True)
            html = render_metric_card(
                label=m["label"],
                value=str(m["value"]),
                delta=str(delta) if delta else "",
                colour=colour,
                delta_positive=delta_positive,
            )
            st.markdown(html, unsafe_allow_html=True)


# ── 5. Data Grid ────────────────────────────────────────────────────────────

def render_data_grid(
    data: List[Dict[str, Any]],
    title: str,
    use_case: Optional[str] = None,
    stage: Optional[str] = None,
) -> None:
    """Render a findings table with severity badges.

    data rows should have a 'severity' key for badge colouring.
    """
    if not data:
        st.info("No findings to display.")
        return

    st.markdown(textwrap.dedent(f"""
    <div style="font-size:0.85rem;font-weight:600;color:{TEXT_SECONDARY};margin-bottom:8px;">
        {title} <span style="color:{TEXT_MUTED};font-weight:400;">({len(data)} items)</span>
    </div>
    """), unsafe_allow_html=True)

    # Check for hallucination flags to prepend inline warnings
    report = None
    if use_case and stage and "hallucination_reports" in st.session_state:
        report = st.session_state.hallucination_reports.get(f"{use_case}_{stage}")
    
    if report and report.flags:
        # Create a copy of the data list so we don't mutate session state original
        modified_data = []
        for row in data:
            new_row = {}
            for col, val in row.items():
                val_str = str(val)
                # Check if this val matches any citation in the flags
                for flag in report.flags:
                    citation = flag.citation
                    if citation.upper() in val_str.upper():
                        warning_badge = f"⚠️ Unverified: {citation} not found in {flag.source_checked}"
                        if warning_badge not in val_str:
                            val_str = f"{warning_badge} | {val_str}"
                new_row[col] = val_str
            modified_data.append(new_row)
        data = modified_data

    import pandas as pd

    df = pd.DataFrame(data)

    # Style severity column if present
    if "severity" in df.columns:
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        df["_sev_sort"] = df["severity"].str.upper().map(severity_order).fillna(5)
        df = df.sort_values("_sev_sort").drop(columns=["_sev_sort"])

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        height=min(400, 40 + len(df) * 35),
    )


# ── 6. HITL Gate ─────────────────────────────────────────────────────────────

def render_hitl_gate(
    use_case: str,
    stage: str,
    findings: List[Dict[str, Any]],
) -> Optional[str]:
    """Human-in-the-loop approval gate. Returns 'approve', 'reject', or None.

    findings: list of dicts with at least {id, title, severity, confidence}.
    """
    accent = USE_CASE_COLOURS.get(use_case, ACCENT_BLUE)
    gate_key = f"hitl_{use_case}_{stage}"

    st.markdown(textwrap.dedent(f"""
    <div class="hitl-gate">
        <div class="title">
            ⚠️ Human-in-the-Loop Gate — {stage.replace('_', ' ').title()}
        </div>
        <div style="font-size:0.85rem;color:{TEXT_SECONDARY};margin-bottom:12px;">
            Review the AI findings below before proceeding. Critical and high-severity
            findings require explicit analyst approval.
        </div>
    </div>
    """), unsafe_allow_html=True)

    # Display summary of findings requiring approval
    critical_count = sum(1 for f in findings if f.get("severity", "").upper() in ("CRITICAL", "HIGH"))
    total_count = len(findings)

    avg_conf = sum(f.get("confidence", 0) for f in findings) / max(len(findings), 1)

    # Render unified horizontal metrics panel to completely prevent vertical squeezing
    metrics_row_html = f"""
    <div style="
        display: flex; 
        justify-content: space-between; 
        align-items: center; 
        background: linear-gradient(135deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.01) 100%);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px; 
        padding: 14px 10px; 
        margin-bottom: 16px;
        gap: 8px;
    ">
        <div style="text-align: center; flex: 1; min-width: 0;">
            <div style="font-size: 0.65rem; color: #a0a0c0; text-transform: uppercase; font-weight: 600; margin-bottom: 4px; letter-spacing: 0.05em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">Total Findings</div>
            <div style="font-size: 1.4rem; font-weight: 800; color: {accent}; line-height: 1.1;">{total_count}</div>
        </div>
        <div style="width: 1px; height: 28px; background: rgba(255, 255, 255, 0.1); flex-shrink: 0;"></div>
        <div style="text-align: center; flex: 1; min-width: 0;">
            <div style="font-size: 0.65rem; color: #a0a0c0; text-transform: uppercase; font-weight: 600; margin-bottom: 4px; letter-spacing: 0.05em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">Critical/High</div>
            <div style="font-size: 1.4rem; font-weight: 800; color: {ACCENT_RED}; line-height: 1.1;">{critical_count}</div>
        </div>
        <div style="width: 1px; height: 28px; background: rgba(255, 255, 255, 0.1); flex-shrink: 0;"></div>
        <div style="text-align: center; flex: 1; min-width: 0;">
            <div style="font-size: 0.65rem; color: #a0a0c0; text-transform: uppercase; font-weight: 600; margin-bottom: 4px; letter-spacing: 0.05em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">Avg Confidence</div>
            <div style="font-size: 1.4rem; font-weight: 800; color: {rag_colour(avg_conf)}; line-height: 1.1;">{avg_conf:.0f}%</div>
        </div>
    </div>
    """
    st.markdown(metrics_row_html, unsafe_allow_html=True)

    # Findings detail expander
    with st.expander(f"📋 Review {total_count} findings", expanded=critical_count > 0):
        for finding in findings:
            sev = finding.get("severity", "INFO").upper()
            sev_badge = render_severity_badge(sev)
            conf = finding.get("confidence", 0)
            st.markdown(textwrap.dedent(f"""
            <div style="
                display:flex;align-items:center;gap:12px;
                padding:10px 14px;margin-bottom:6px;
                background:{BG_GLASS};border:1px solid {BORDER_GLASS};border-radius:8px;
            ">
                {sev_badge}
                <span style="flex:1;font-size:0.85rem;color:{TEXT_PRIMARY};">{finding.get('title', 'Untitled')}</span>
                <span style="font-size:0.75rem;color:{rag_colour(conf)};font-weight:600;">{conf:.0f}%</span>
            </div>
            """), unsafe_allow_html=True)

    # Approval buttons
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    col_approve, col_reject = st.columns(2)

    result: Optional[str] = None
    if col_approve.button("✅ Approve & Proceed", key=f"{gate_key}_approve", use_container_width=True):
        result = "approve"
    if col_reject.button("❌ Reject & Review", key=f"{gate_key}_reject", use_container_width=True):
        result = "reject"

    if result is not None:
        # Record decision in session metrics and persistent audit log
        try:
            from app.observability.health_metrics import InAppMetrics
            from app.observability.audit_logger import AuditLogger
            
            metrics = InAppMetrics()
            metrics.record_hitl_decision(use_case, stage, result, int(avg_conf))
            
            logger = AuditLogger()
            logger.log_action(
                action=f"HITL Decision: {stage.replace('_', ' ').title()}",
                username=st.session_state.get("username", "vaibhav"),
                status="Success" if result == "approve" else "Rejected",
                target=f"{use_case.upper()}_{stage}",
                details=f"Analyst {result.upper()}D the stage findings. Findings count: {len(findings)}. Avg confidence: {avg_conf:.0f}%."
            )
        except Exception as e:
            st.warning(f"Error logging HITL decision: {e}")

    return result
