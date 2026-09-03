"""
AI Capability Demo — Synthetic Data Watermark Renderer
4-location persistent indicator when synthetic data is active.
AGENTS.md Section 10.4.
"""

from __future__ import annotations

import streamlit as st


def clean_html(html_str: str) -> str:
    """Strip all leading and trailing whitespace from every line to prevent Markdown code block interpretation."""
    return "\n".join(line.strip() for line in html_str.strip().splitlines())


def render_sidebar_data_badge(data_source: str = "synthetic"):
    """
    Render data mode badge in sidebar.
    Location 1 of 4 synthetic data indicators.
    """
    badge_config = {
        "mcp": {
            "icon": "🟢",
            "label": "MCP Live",
            "bg": "rgba(0,255,136,0.08)",
            "border": "rgba(0,255,136,0.2)",
            "color": "#00ff88",
        },
        "upload": {
            "icon": "🔵",
            "label": "File Upload",
            "bg": "rgba(0,212,255,0.08)",
            "border": "rgba(0,212,255,0.2)",
            "color": "#00d4ff",
        },
        "synthetic": {
            "icon": "🟠",
            "label": "Synthetic Data",
            "bg": "rgba(255,107,53,0.08)",
            "border": "rgba(255,107,53,0.2)",
            "color": "#ff6b35",
        },
    }

    cfg = badge_config.get(data_source, badge_config["synthetic"])

    st.markdown(clean_html(f"""
    <div style="
        padding: 8px 12px;
        border-radius: 8px;
        background: {cfg['bg']};
        border: 1px solid {cfg['border']};
        font-size: 0.8rem;
        margin-bottom: 8px;
    ">
        {cfg['icon']} <strong style="color: {cfg['color']};">{cfg['label']}</strong>
    </div>
    """), unsafe_allow_html=True)


def render_pre_execution_warning():
    """
    Render amber warning strip above Execute button.
    Location 2 of 4 synthetic data indicators.
    """
    st.markdown(clean_html("""
    <div class="synthetic-banner">
        ⚠️ <strong>SYNTHETIC DATA MODE</strong> — Analysis will run on generated demonstration data.
        Results are illustrative and do not represent real security findings.
        Connect MCP tools or upload data files in Settings to use production data.
    </div>
    """), unsafe_allow_html=True)


def render_guardrail_badge(data_source: str = "synthetic"):
    """
    Render guardrail badge showing data source.
    Location 3 of 4 synthetic data indicators.
    """
    if data_source == "synthetic":
        st.markdown(clean_html("""
        <div style="
            display: inline-flex; align-items: center; gap: 6px;
            padding: 4px 12px; border-radius: 20px;
            font-size: 0.75rem; font-weight: 600;
            background: rgba(255,107,53,0.12);
            color: #ff6b35;
            border: 1px solid rgba(255,107,53,0.3);
            letter-spacing: 0.05em;
        ">
            🟠 SYNTHETIC DATA — NOT PRODUCTION
        </div>
        """), unsafe_allow_html=True)
    elif data_source == "mcp":
        st.markdown(clean_html("""
        <div style="
            display: inline-flex; align-items: center; gap: 6px;
            padding: 4px 12px; border-radius: 20px;
            font-size: 0.75rem; font-weight: 600;
            background: rgba(0,255,136,0.12);
            color: #00ff88;
            border: 1px solid rgba(0,255,136,0.3);
            letter-spacing: 0.05em;
        ">
            🟢 MCP LIVE DATA
        </div>
        """), unsafe_allow_html=True)
    else:
        st.markdown(clean_html("""
        <div style="
            display: inline-flex; align-items: center; gap: 6px;
            padding: 4px 12px; border-radius: 20px;
            font-size: 0.75rem; font-weight: 600;
            background: rgba(0,212,255,0.12);
            color: #00d4ff;
            border: 1px solid rgba(0,212,255,0.3);
            letter-spacing: 0.05em;
        ">
            🔵 FILE UPLOAD DATA
        </div>
        """), unsafe_allow_html=True)


def render_analysis_watermark(data_source: str = "synthetic"):
    """
    Render blockquote watermark on AI analysis results.
    Location 4 of 4 synthetic data indicators.
    """
    if data_source == "synthetic":
        st.markdown(clean_html("""
        <blockquote style="
            border-left: 3px solid #ff6b35;
            padding: 8px 16px;
            margin: 12px 0;
            background: rgba(255,107,53,0.06);
            border-radius: 0 8px 8px 0;
            font-size: 0.8rem;
            color: #ff6b35;
        ">
            ⚠️ <strong>SYNTHETIC DATA</strong> — This analysis was generated using
            synthetic demonstration data and does not represent real security findings.
        </blockquote>
        """), unsafe_allow_html=True)
    elif data_source == "mcp":
        st.markdown(clean_html("""
        <blockquote style="
            border-left: 3px solid #00ff88;
            padding: 8px 16px;
            margin: 12px 0;
            background: rgba(0,255,136,0.06);
            border-radius: 0 8px 8px 0;
            font-size: 0.8rem;
            color: #00ff88;
        ">
            🟢 <strong>LIVE DATA</strong> — This analysis is based on live data from connected MCP tools.
        </blockquote>
        """), unsafe_allow_html=True)

