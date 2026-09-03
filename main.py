"""
CTEM & DevSecOps AI Platform
Main entry point: page config, session state init, auth gate, sidebar, routing.
AGENTS.md v4.0
"""

from __future__ import annotations

import uuid
import streamlit as st
from dotenv import load_dotenv
import textwrap

# ── Monkeypatch textwrap.dedent for HTML ──────────────────────────────────────
# Prevents Streamlit's Markdown parser from turning indented HTML into code blocks.
_original_dedent = textwrap.dedent

def custom_dedent(text):
    result = _original_dedent(text)
    stripped = result.strip()
    if stripped.startswith("<") and (stripped.endswith(">") or "class=" in stripped or "style=" in stripped):
        return "\n".join(line.strip() for line in stripped.splitlines())
    return result

textwrap.dedent = custom_dedent

load_dotenv(override=True)

# ── Page Configuration (MUST be first Streamlit call) ────────────────────────
st.set_page_config(
    page_title="CTEM & DevSecOps AI Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Imports ──────────────────────────────────────────────────────────────────
from app.ui.theme import (
    apply_theme, USE_CASE_LABELS, USE_CASE_COLOURS,
    render_badge, rag_colour, ACCENT_BLUE, ACCENT_GREEN,
    ACCENT_RED, ACCENT_PURPLE, ACCENT_AMBER,
)
from app.ui.components.auth import (
    check_auth, render_login_page, render_profile_badge, render_logout_button,
)
from app.data.synthetic_banner import render_sidebar_data_badge
from app.memory.short_term import ShortTermMemory


def init_session_state():
    """Initialize all session state keys with defaults."""
    defaults = {
        # Auth
        "authenticated": False,
        "username": "",
        "session_id": str(uuid.uuid4()),
        "user_role": "analyst",

        # Data
        "datasets": None,
        "active_data_source_ctem": "synthetic",
        "active_data_source_devsecops": "synthetic",

        # Stage tracking
        "active_stage_ctem": 1,
        "active_stage_devsecops": 1,

        # Navigation
        "current_page": "home",

        # Copilot
        "copilot_messages": [],

        # Workflow
        "workflow_audit_log": [],

        # LLM
        "llm_router": None,
        "kpi_engine": None,
        "memory": None,
        "settings_show_breach_sim": False,
    }
    for key, default in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default

    # Initialize SQLite memory store instance
    if st.session_state.memory is None:
        try:
            st.session_state.memory = ShortTermMemory()
        except Exception as e:
            # Safe fallback if database path isn't writable or fails on startup
            pass


def load_data():
    """Load synthetic datasets on first run."""
    if st.session_state.datasets is None:
        with st.spinner("Generating enterprise-grade synthetic datasets..."):
            from app.data.generator import SyntheticDataEngine
            engine = SyntheticDataEngine(seed=42)
            st.session_state.datasets = engine.generate_all()

        # Initialize KPI engine
        from app.kpi.engine import KPIEngine
        st.session_state.kpi_engine = KPIEngine(st.session_state.datasets)


def init_llm():
    """Initialize LLM router on first run."""
    if st.session_state.llm_router is None:
        try:
            from app.llm.router import LLMRouter
            st.session_state.llm_router = LLMRouter()
        except Exception:
            pass  # LLM router may fail if API key not set


def render_sidebar():
    """Render the sidebar navigation."""
    with st.sidebar:
        # Center-aligned premium logo matching the reference UI exactly
        st.markdown("""
        <div style="text-align: center; margin-top: 15px; margin-bottom: 25px;">
            <div style="font-size: 3rem; margin-bottom: 5px; filter: drop-shadow(0 4px 12px rgba(0, 212, 255, 0.3));">🛡️</div>
            <div style="font-size: 1.25rem; font-weight: 700; color: #00d4ff; font-family: 'Inter', sans-serif; letter-spacing: -0.01em; margin-bottom: 4px;">
                CTEM &amp; DevSecOps
            </div>
            <div style="font-size: 0.65rem; font-weight: 600; color: #8c8cab; letter-spacing: 0.18em; text-transform: uppercase;">
                AI Platform
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("---")

        # Profile badge
        render_profile_badge()

        st.markdown("---")

        # Navigation
        pages = {
            "home": "🏠  Home",
            "data_explorer": "📊  Data Explorer",
            "agents": "🤖  Agents",
            "copilot": "💬  Copilot",
        }
        for key, label in pages.items():
            if st.button(label, key=f"nav_{key}", use_container_width=True):
                st.session_state.current_page = key
                st.rerun()

        st.markdown("---")

        utility_pages = {
            "settings": "⚙️  Settings",
            "token_usage": "📈  Token Usage",
            "observability": "🔭  Observability",
        }
        for key, label in utility_pages.items():
            if st.button(label, key=f"nav_{key}", use_container_width=True):
                st.session_state.current_page = key
                st.rerun()

        st.markdown("---")

        # Data Mode Badge
        render_sidebar_data_badge(
            st.session_state.get("active_data_source_ctem", "synthetic")
        )

        # LLM Badge
        llm_router = st.session_state.get("llm_router")
        if llm_router:
            info = llm_router.get_active_model_info()
            model_name = info.get("model", "GPT-4o-mini")
            st.markdown(f"""
            <div style="
                padding: 8px 12px; border-radius: 8px;
                background: rgba(0,255,136,0.08);
                border: 1px solid rgba(0,255,136,0.2);
                font-size: 0.8rem; margin-bottom: 8px;
            ">
                🟢 <strong>{model_name}</strong>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="
                padding: 8px 12px; border-radius: 8px;
                background: rgba(255,170,0,0.08);
                border: 1px solid rgba(255,170,0,0.2);
                font-size: 0.8rem; margin-bottom: 8px;
            ">
                🟡 <strong>LLM: Not configured</strong>
            </div>
            """, unsafe_allow_html=True)

        # AI Readiness Index (Resilience Index Realignment)
        kpi = st.session_state.get("kpi_engine")
        if kpi:
            readiness = kpi.get_ai_readiness_index()
            st.markdown(f"""
            <div style="text-align: center; margin-bottom: 20px; margin-top: 10px; font-family: 'Inter', sans-serif;">
                <div style="font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.18em; color: #8c8cab; font-weight: 600;">
                    AI Readiness Index
                </div>
                <div style="font-size: 2.6rem; font-weight: 800; color: #ffffff; margin: 4px 0; letter-spacing: -0.02em;">
                    {readiness:.1f}%
                </div>
                <div style="font-size: 0.68rem; color: #6b6b8d; font-weight: 500;">
                    Scoping: Complete · Status: Verified
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Use Case Scores (desaturated container cards with colored progress bars matching reference UI)
            for uc, label in USE_CASE_LABELS.items():
                score = kpi.get_use_case_score(uc)
                colour = USE_CASE_COLOURS.get(uc, "#00d4ff")
                st.markdown(f"""
                <div style="
                    background: rgba(30, 36, 75, 0.35);
                    border: 1px solid rgba(255, 255, 255, 0.05);
                    border-radius: 12px;
                    padding: 12px 16px;
                    margin-bottom: 10px;
                ">
                    <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.82rem; font-weight: 500; font-family: 'Inter', sans-serif;">
                        <span style="color: #d1d1e0;">{label}</span>
                        <span style="color: {colour}; font-weight: 700;">{score:.0f}%</span>
                    </div>
                    <div style="background: rgba(255, 255, 255, 0.05); height: 5px; border-radius: 3px; margin-top: 10px; overflow: hidden;">
                        <div style="background: {colour}; width: {score}%; height: 100%; border-radius: 3px;"></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("---")

        # Logout
        render_logout_button()


def render_page():
    """Route to the correct page based on session state."""
    page = st.session_state.get("current_page", "home")
    datasets = st.session_state.get("datasets", {})
    kpi_engine = st.session_state.get("kpi_engine")
    llm_router = st.session_state.get("llm_router")

    # Lazy import agent_manager
    agent_manager = None
    try:
        from app.runtime.agent_manager import AgentManager
        from app.llm.token_tracker import TokenUsageTracker
        tracker = TokenUsageTracker()
        agent_manager = AgentManager(llm_router, None, tracker)
    except Exception:
        pass

    if page == "home":
        _render_home(datasets, kpi_engine, agent_manager)
    elif page == "data_explorer":
        from app.ui.pages.data_explorer import render_data_explorer
        render_data_explorer(datasets)
    elif page == "agents":
        from app.ui.pages.agents_repo import render_agents_page
        render_agents_page()
    elif page == "copilot":
        from app.ui.copilots.copilot import render_copilot
        render_copilot(datasets, llm_router, kpi_engine)
    elif page == "settings":
        from app.ui.pages.settings import render_settings_page
        render_settings_page()
    elif page == "token_usage":
        from app.ui.pages.token_usage import render_token_usage_page
        from app.llm.token_tracker import TokenUsageTracker
        render_token_usage_page(TokenUsageTracker())
    elif page == "observability":
        from app.ui.pages.observability import render_observability_page
        render_observability_page()


def _render_home(datasets, kpi_engine, agent_manager):
    """Render the Home page with dashboard and use case tabs."""
    tabs = st.tabs([
        "📊 Dashboard",
        "🎯 CTEM",
        "🐙 DevSecOps",
    ])

    with tabs[0]:
        from app.ui.dashboards.executive import render_executive_dashboard
        render_executive_dashboard(datasets, kpi_engine)

    with tabs[1]:
        from app.ui.pages.ctem import render_ctem_page
        render_ctem_page(datasets, agent_manager, kpi_engine)

    with tabs[2]:
        from app.ui.pages.devsecops import render_devsecops_page
        render_devsecops_page(datasets, agent_manager, kpi_engine)


# ── Main Entry Point ────────────────────────────────────────────────────────
def main():
    # Initialize session state
    init_session_state()

    # Apply theme
    apply_theme()

    # Auth gate
    if not check_auth():
        render_login_page()
        return

    # Load data and LLM
    load_data()
    init_llm()

    # Render sidebar
    render_sidebar()

    # Render current page
    render_page()


if __name__ == "__main__":
    main()
