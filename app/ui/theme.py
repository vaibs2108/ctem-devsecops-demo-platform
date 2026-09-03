"""
AI Capability Demo — UI Theme & Design System
Dark theme, glassmorphism, Inter font, RAG colour coding.
AGENTS.md Section 20.
"""

import re
import streamlit as st
import textwrap

# ── Colour Palette ──────────────────────────────────────────────────────────
BG_PRIMARY = "#0a0e27"
BG_SECONDARY = "#111638"
BG_CARD = "rgba(17, 22, 56, 0.7)"
BG_GLASS = "rgba(255, 255, 255, 0.05)"
BORDER_GLASS = "rgba(255, 255, 255, 0.08)"

ACCENT_BLUE = "#00d4ff"      # CTEM
ACCENT_RED = "#ff4444"       # Threat Hunting
ACCENT_PURPLE = "#a855f7"    # Pen Testing
ACCENT_GREEN = "#00ff88"     # Detection Engineering
ACCENT_AMBER = "#ffaa00"     # Warnings / HITL
ACCENT_ORANGE = "#ff6b35"    # Synthetic data

WHITE = "#ffffff"
DGREY = "#595959"
LGREY = "#a0a0a0"
TEXT_PRIMARY = "#e8e8e8"
TEXT_SECONDARY = "#a0a0c0"
TEXT_MUTED = "#6b6b8d"

# RAG colour coding
RAG_GREEN = "#00ff88"
RAG_AMBER = "#ffaa00"
RAG_RED = "#ff4444"

# Use case accent map
USE_CASE_COLOURS = {
    "ctem": ACCENT_BLUE,
    "devsecops": ACCENT_GREEN,
}

USE_CASE_LABELS = {
    "ctem": "🎯 CTEM",
    "devsecops": "🐙 DevSecOps",
}

USE_CASE_ICONS = {
    "ctem": "🎯",
    "devsecops": "🐙",
}

# ── Light / Dark Theme Toggle ────────────────────────────────────────────────
# The rest of the app renders colour as literal hex/rgba strings baked into
# HTML that is passed to st.markdown(..., unsafe_allow_html=True). Rather than
# threading a "current theme" value through every render function, we
# intercept every st.markdown call once (see _install_theme_markdown_patch
# below) and rewrite known dark-theme colour literals to their light-theme
# equivalents when the user has selected light mode. This works because every
# call site in this codebase uses `st.markdown(...)` (module-attribute access
# resolved at call time), never `from streamlit import markdown`.

THEME_MODE_KEY = "app_theme_mode"


def get_theme_mode() -> str:
    """Return the active theme mode: 'dark' only."""
    return "dark"


def set_theme_mode(mode: str) -> None:
    """Theme is locked to dark mode."""
    pass


def render_theme_toggle() -> None:
    """No-op: dark theme is permanent."""
    pass


def rag_colour(value: float) -> str:
    """Return RAG colour based on value (0-100 scale)."""
    if value >= 80:
        return RAG_GREEN
    elif value >= 60:
        return RAG_AMBER
    return RAG_RED


def desaturate_colour(hex_colour: str, factor: float = 0.3) -> str:
    """Desaturate a hex colour by factor (for synthetic data mode)."""
    r = int(hex_colour[1:3], 16)
    g = int(hex_colour[3:5], 16)
    b = int(hex_colour[5:7], 16)
    gray = int(0.299 * r + 0.587 * g + 0.114 * b)
    r = int(r + (gray - r) * factor)
    g = int(g + (gray - g) * factor)
    b = int(b + (gray - b) * factor)
    return f"#{r:02x}{g:02x}{b:02x}"


def apply_theme():
    """Inject global CSS theme into Streamlit app."""
    st.markdown(textwrap.dedent(f"""
    <style>
        /* ── Google Fonts ─────────────────────────────────── */
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap');

        /* ── Global Reset ─────────────────────────────────── */
        html, body, [class*="css"] {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
            color: {TEXT_PRIMARY};
        }}

        .stApp {{
            background: linear-gradient(135deg, {BG_PRIMARY} 0%, {BG_SECONDARY} 50%, #0d1235 100%);
            background-attachment: fixed;
        }}

        /* ── Sidebar ──────────────────────────────────────── */
        [data-testid="stSidebar"] {{
            background: linear-gradient(180deg, rgba(10, 14, 39, 0.95) 0%, rgba(17, 22, 56, 0.95) 100%);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-right: 1px solid {BORDER_GLASS};
        }}

        [data-testid="stSidebar"] .stMarkdown h1 {{
            font-size: 1.3rem;
            font-weight: 700;
            background: linear-gradient(135deg, {ACCENT_BLUE}, {ACCENT_GREEN});
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -0.02em;
        }}

        /* ── Glassmorphism Cards ──────────────────────────── */
        .glass-card {{
            background: {BG_GLASS};
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid {BORDER_GLASS};
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 16px;
            transition: all 0.3s ease;
        }}

        .glass-card:hover {{
            border-color: rgba(255, 255, 255, 0.15);
            box-shadow: 0 8px 32px rgba(0, 212, 255, 0.08);
            transform: translateY(-2px);
        }}

        /* ── Glassmorphism Containers ──────────────────────── */
        div[data-testid="stVerticalBlockBorderWrapper"]:has(.glass-card-anchor) {{
            background: {BG_GLASS} !important;
            backdrop-filter: blur(16px) !important;
            -webkit-backdrop-filter: blur(16px) !important;
            border: 1px solid {BORDER_GLASS} !important;
            border-radius: 16px !important;
            padding: 20px !important;
            margin-bottom: 16px !important;
            transition: all 0.3s ease !important;
        }}
        div[data-testid="stVerticalBlockBorderWrapper"]:has(.glass-card-anchor):hover {{
            border-color: rgba(255, 255, 255, 0.15) !important;
            box-shadow: 0 8px 32px rgba(0, 212, 255, 0.08) !important;
            transform: translateY(-2px) !important;
        }}
        .glass-card-anchor {{
            display: none;
        }}

        /* ── Metric Cards ─────────────────────────────────── */
        .metric-card {{
            background: linear-gradient(135deg, rgba(255,255,255,0.06) 0%, rgba(255,255,255,0.02) 100%);
            backdrop-filter: blur(12px);
            border: 1px solid {BORDER_GLASS};
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            transition: all 0.3s ease;
        }}

        .metric-card:hover {{
            transform: translateY(-4px);
            box-shadow: 0 12px 40px rgba(0, 212, 255, 0.12);
        }}

        .metric-value {{
            font-size: 2.2rem;
            font-weight: 800;
            line-height: 1.1;
            margin-bottom: 4px;
            letter-spacing: -0.03em;
        }}

        .metric-label {{
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: {TEXT_MUTED};
            font-weight: 500;
        }}

        .metric-delta {{
            font-size: 0.8rem;
            font-weight: 600;
            margin-top: 4px;
        }}

        .metric-delta.positive {{ color: {RAG_GREEN}; }}
        .metric-delta.negative {{ color: {RAG_RED}; }}

        /* ── Hero Banner ──────────────────────────────────── */
        .hero-banner {{
            background: linear-gradient(135deg, rgba(0,212,255,0.15) 0%, rgba(168,85,247,0.1) 50%, rgba(0,255,136,0.08) 100%);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(0,212,255,0.2);
            border-radius: 20px;
            padding: 32px 40px;
            margin-bottom: 24px;
            position: relative;
            overflow: hidden;
        }}

        .hero-banner::before {{
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(0,212,255,0.05) 0%, transparent 60%);
            animation: hero-glow 8s ease-in-out infinite;
        }}

        @keyframes hero-glow {{
            0%, 100% {{ transform: translate(0, 0); }}
            50% {{ transform: translate(30px, 20px); }}
        }}

        .hero-title {{
            font-size: 2rem;
            font-weight: 800;
            letter-spacing: -0.03em;
            margin-bottom: 8px;
            position: relative;
            z-index: 1;
        }}

        .hero-subtitle {{
            font-size: 1rem;
            color: {TEXT_SECONDARY};
            position: relative;
            z-index: 1;
        }}

        /* ── Stage Pills ──────────────────────────────────── */
        .stage-pill {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            border-radius: 24px;
            font-size: 0.85rem;
            font-weight: 500;
            border: 1px solid {BORDER_GLASS};
            background: {BG_GLASS};
            transition: all 0.3s ease;
            cursor: pointer;
            text-decoration: none;
            color: {TEXT_SECONDARY};
        }}

        .stage-pill.active {{
            border-color: var(--accent-colour, {ACCENT_BLUE});
            background: rgba(0, 212, 255, 0.15);
            color: {WHITE};
            box-shadow: 0 4px 16px rgba(0, 212, 255, 0.2);
        }}

        .stage-pill.completed {{
            border-color: {RAG_GREEN};
            color: {RAG_GREEN};
        }}

        /* ── Buttons ──────────────────────────────────────── */
        .stButton > button {{
            background: linear-gradient(135deg, {ACCENT_BLUE} 0%, #0099cc 100%);
            color: white;
            border: none;
            border-radius: 10px;
            padding: 8px 24px;
            font-weight: 600;
            font-family: 'Inter', sans-serif;
            transition: all 0.3s ease;
            letter-spacing: 0.02em;
        }}

        .stButton > button:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(0, 212, 255, 0.3);
        }}

        /* ── Stage Progress / Column Buttons Sizing & Alignment ── */
        div[data-testid="stHorizontalBlock"] div[data-testid="stColumn"] .stButton > button {{
            min-height: 48px !important;
            height: 48px !important;
            font-size: 0.8rem !important;
            line-height: 1.2 !important;
            padding: 4px 8px !important;
            white-space: normal !important;
            word-break: break-word !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            text-align: center !important;
        }}

        /* ── Execute Button (Special) ─────────────────────── */
        .execute-btn > button {{
            background: linear-gradient(135deg, {ACCENT_GREEN} 0%, #00cc6a 100%) !important;
            font-size: 1.1rem;
            padding: 12px 32px;
        }}

        /* ── Data Tables ──────────────────────────────────── */
        .stDataFrame {{
            border-radius: 12px;
            overflow: hidden;
        }}

        [data-testid="stDataFrame"] > div {{
            border-radius: 12px;
        }}

        /* ── Tabs ─────────────────────────────────────────── */
        .stTabs [data-baseweb="tab-list"] {{
            gap: 8px;
            background: transparent;
        }}

        .stTabs [data-baseweb="tab"] {{
            border-radius: 10px;
            padding: 8px 20px;
            font-weight: 500;
            background: {BG_GLASS};
            border: 1px solid {BORDER_GLASS};
        }}

        .stTabs [aria-selected="true"] {{
            background: rgba(0, 212, 255, 0.12);
            border-color: {ACCENT_BLUE};
        }}

        /* ── Expanders ────────────────────────────────────── */
        .streamlit-expanderHeader {{
            background: {BG_GLASS};
            border-radius: 10px;
            border: 1px solid {BORDER_GLASS};
            font-weight: 500;
        }}

        /* ── HITL Alert Box ───────────────────────────────── */
        .hitl-gate {{
            background: linear-gradient(135deg, rgba(255,170,0,0.12) 0%, rgba(255,170,0,0.05) 100%);
            border: 2px solid {ACCENT_AMBER};
            border-radius: 12px;
            padding: 20px;
            margin: 16px 0;
        }}

        .hitl-gate .title {{
            color: {ACCENT_AMBER};
            font-weight: 700;
            font-size: 1.1rem;
            margin-bottom: 8px;
        }}

        /* ── Synthetic Data Banner ────────────────────────── */
        .synthetic-banner {{
            background: linear-gradient(135deg, rgba(255,107,53,0.15) 0%, rgba(255,107,53,0.05) 100%);
            border: 1px solid rgba(255,107,53,0.3);
            border-radius: 8px;
            padding: 12px 16px;
            font-size: 0.85rem;
            color: {ACCENT_ORANGE};
            margin-bottom: 16px;
        }}

        /* ── Status Badges ────────────────────────────────── */
        .badge {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.05em;
        }}

        .badge-green {{
            background: rgba(0, 255, 136, 0.12);
            color: {RAG_GREEN};
            border: 1px solid rgba(0, 255, 136, 0.3);
        }}

        .badge-amber {{
            background: rgba(255, 170, 0, 0.12);
            color: {ACCENT_AMBER};
            border: 1px solid rgba(255, 170, 0, 0.3);
        }}

        .badge-red {{
            background: rgba(255, 68, 68, 0.12);
            color: {ACCENT_RED};
            border: 1px solid rgba(255, 68, 68, 0.3);
        }}

        .badge-blue {{
            background: rgba(0, 212, 255, 0.12);
            color: {ACCENT_BLUE};
            border: 1px solid rgba(0, 212, 255, 0.3);
        }}

        .badge-purple {{
            background: rgba(168, 85, 247, 0.12);
            color: {ACCENT_PURPLE};
            border: 1px solid rgba(168, 85, 247, 0.3);
        }}

        /* ── Severity Badges ──────────────────────────────── */
        .severity-critical {{ color: #ff2222; font-weight: 700; }}
        .severity-high {{ color: {ACCENT_RED}; font-weight: 600; }}
        .severity-medium {{ color: {ACCENT_AMBER}; font-weight: 500; }}
        .severity-low {{ color: {ACCENT_BLUE}; font-weight: 400; }}
        .severity-info {{ color: {TEXT_MUTED}; }}

        /* ── Code Blocks (Detection Rules) ────────────────── */
        .rule-block {{
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid {BORDER_GLASS};
            border-radius: 8px;
            padding: 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            overflow-x: auto;
        }}

        /* ── AI Analysis Panel ────────────────────────────── */
        .ai-panel {{
            background: linear-gradient(135deg, rgba(0,212,255,0.06) 0%, rgba(168,85,247,0.04) 100%);
            border: 1px solid rgba(0,212,255,0.15);
            border-radius: 16px;
            padding: 24px;
        }}

        .ai-panel-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid {BORDER_GLASS};
        }}

        /* ── Scrollbar ────────────────────────────────────── */
        ::-webkit-scrollbar {{
            width: 6px;
            height: 6px;
        }}

        ::-webkit-scrollbar-track {{
            background: transparent;
        }}

        ::-webkit-scrollbar-thumb {{
            background: rgba(255, 255, 255, 0.15);
            border-radius: 3px;
        }}

        ::-webkit-scrollbar-thumb:hover {{
            background: rgba(255, 255, 255, 0.25);
        }}

        /* ── Animations ───────────────────────────────────── */
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}

        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.6; }}
        }}

        @keyframes shimmer {{
            0% {{ background-position: -200% center; }}
            100% {{ background-position: 200% center; }}
        }}

        .animate-fade {{ animation: fadeIn 0.5s ease-out; }}
        .animate-pulse {{ animation: pulse 2s ease-in-out infinite; }}

        /* ── Hide Streamlit Chrome ─────────────────────────── */
        #MainMenu {{ visibility: hidden; }}
        footer {{ visibility: hidden; }}
        header {{ visibility: hidden; }}
        /* The "expand sidebar" control (shown after a user collapses the
           sidebar via the « arrow) lives INSIDE the header above, so hiding
           the header made it impossible to bring the sidebar back once
           collapsed. Explicitly re-show just that one control. */
        [data-testid="stExpandSidebarButton"] {{ visibility: visible !important; }}

        /* ── Sidebar Custom Premium Desaturated Styles ────── */
        [data-testid="stSidebar"] {{
            background: linear-gradient(180deg, #090b1e 0%, #060714 100%) !important;
            border-right: 1px solid rgba(255, 255, 255, 0.04) !important;
        }}

        [data-testid="stSidebar"] hr {{
            border: 0;
            height: 1px;
            background: rgba(255, 255, 255, 0.05) !important;
            margin: 16px 0 !important;
        }}

        [data-testid="stSidebar"] .stButton > button {{
            background: rgba(30, 36, 75, 0.35) !important;
            color: #d1d1e0 !important;
            border: 1px solid rgba(255, 255, 255, 0.05) !important;
            border-radius: 12px !important;
            padding: 10px 18px !important;
            font-weight: 500 !important;
            font-size: 0.9rem !important;
            font-family: 'Inter', sans-serif !important;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
            text-align: left !important;
            display: flex !important;
            justify-content: flex-start !important;
            align-items: center !important;
            margin-bottom: 8px !important;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15) !important;
            width: 100% !important;
        }}

        [data-testid="stSidebar"] .stButton > button:hover {{
            background: rgba(40, 48, 96, 0.6) !important;
            color: #ffffff !important;
            border-color: rgba(0, 212, 255, 0.25) !important;
            transform: translateY(-1px) !important;
            box-shadow: 0 6px 18px rgba(0, 212, 255, 0.12) !important;
        }}

        [data-testid="stSidebar"] .stButton > button:active {{
            background: rgba(0, 212, 255, 0.15) !important;
            border-color: #00d4ff !important;
        }}
    </style>
    """), unsafe_allow_html=True)


def clean_html(html_str: str) -> str:
    """Strip all leading and trailing whitespace from every line to prevent Markdown code block interpretation."""
    return "\n".join(line.strip() for line in html_str.strip().splitlines())


def render_metric_card(label: str, value: str, delta: str = "", colour: str = ACCENT_BLUE, delta_positive: bool = True) -> str:
    """Return HTML for a metric card."""
    delta_html = ""
    if delta:
        cls = "positive" if delta_positive else "negative"
        arrow = "↑" if delta_positive else "↓"
        delta_html = f'<div class="metric-delta {cls}">{arrow} {delta}</div>'

    card_html = f"""
    <div class="metric-card">
        <div class="metric-value" style="color: {colour};">{value}</div>
        <div class="metric-label">{label}</div>
        {delta_html}
    </div>
    """
    return clean_html(card_html)


def render_glass_card(content: str, accent: str = ACCENT_BLUE) -> str:
    """Return HTML for a glassmorphism card."""
    content_clean = clean_html(content)
    card_html = f"""
    <div class="glass-card" style="border-top: 2px solid {accent};">
        {content_clean}
    </div>
    """
    return clean_html(card_html)


def render_badge(text: str, variant: str = "blue") -> str:
    """Return HTML for a status badge."""
    return f'<span class="badge badge-{variant}">{text}</span>'


def render_severity_badge(severity: str) -> str:
    """Return coloured severity text."""
    s = severity.lower()
    return f'<span class="severity-{s}">{severity.upper()}</span>'


def render_hero_banner(title: str, subtitle: str, data_source: str = "synthetic") -> str:
    """Return HTML for the hero banner."""
    source_badge = {
        "mcp": '<span class="badge badge-green">🟢 MCP Live</span>',
        "upload": '<span class="badge badge-blue">🔵 File Upload</span>',
        "synthetic": '<span class="badge badge-amber">🟠 Synthetic Data</span>',
    }.get(data_source, '<span class="badge badge-amber">🟠 Synthetic</span>')

    banner_html = f"""
    <div class="hero-banner">
        <div class="hero-title">{title}</div>
        <div class="hero-subtitle">{subtitle} &nbsp; {source_badge}</div>
    </div>
    """
    return clean_html(banner_html)


def render_svg_gauge(score: float, title: str, subtext: str, color: str) -> str:
    """Return responsive premium SVG-in-HTML semi-circle gauge."""
    # Arc length of semi-circle with r=80 is pi * 80 ≈ 251.3
    arc_length = 251.3
    dashoffset = arc_length * (1 - (score / 100.0))
    gauge_html = f"""
    <div style="text-align: center; margin: 10px 0;">
        <svg width="100%" height="110" viewBox="0 0 200 120" style="display: block; margin: 0 auto;">
            <path d="M 20 105 A 80 80 0 0 1 180 105" 
                  fill="none" 
                  stroke="rgba(255, 255, 255, 0.08)" 
                  stroke-width="14" 
                  stroke-linecap="round" />
            <path d="M 20 105 A 80 80 0 0 1 180 105" 
                  fill="none" 
                  stroke="{color}" 
                  stroke-width="14" 
                  stroke-linecap="round" 
                  stroke-dasharray="{arc_length}" 
                  stroke-dashoffset="{dashoffset}" 
                  style="transition: stroke-dashoffset 0.8s ease-in-out;" />
            <text x="100" y="90" 
                  text-anchor="middle" 
                  font-family="'Inter', sans-serif" 
                  font-weight="800" 
                  font-size="28" 
                  fill="#ffffff">{score:.1f}%</text>
            <text x="100" y="115" 
                  text-anchor="middle" 
                  font-family="'Inter', sans-serif" 
                  font-weight="600" 
                  font-size="12" 
                  fill="{color}" 
                  text-transform="uppercase" 
                  letter-spacing="0.05em">{title}</text>
        </svg>
        <div style="font-family: 'Inter', sans-serif; font-size: 0.75rem; color: #a0a0c0; margin-top: 4px; min-height: 16px;">
            {subtext}
        </div>
    </div>
    """
    return clean_html(gauge_html)


def render_kpi_progress_card(label: str, value: float, max_value: float, color: str, subtext: str = "") -> str:
    """Return responsive premium horizontal gradient-colored progress-bar card."""
    percentage = min(100.0, max(0.0, (value / max_value) * 100.0))
    subtext_html = f'<div style="font-size: 0.75rem; color: #6b6b8d; margin-top: 4px;">{subtext}</div>' if subtext else ""
    card_html = f"""
    <div style="background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 10px; padding: 14px 18px; margin-bottom: 12px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <span style="font-size: 0.85rem; font-weight: 600; color: #e8e8e8;">{label}</span>
            <span style="font-size: 0.95rem; font-weight: 800; color: {color};">{value:.1f}%</span>
        </div>
        <div style="width: 100%; height: 8px; background: rgba(0, 0, 0, 0.3); border-radius: 4px; overflow: hidden;">
            <div style="width: {percentage:.1f}%; height: 100%; background: linear-gradient(90deg, {color} 0%, rgba(255,255,255,0.4) 100%); border-radius: 4px; transition: width 0.6s ease-in-out;"></div>
        </div>
        {subtext_html}
    </div>
    """
    return clean_html(card_html)

