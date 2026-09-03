"""
AI Capability Demo — Settings Page
Configure LLM pathways and the 12 MCP vendor credentials.
AGENTS.md Section 2 & 5.1
"""

import streamlit as st
import os
from app.ui.theme import (
    render_hero_banner, render_glass_card, render_badge,
    ACCENT_BLUE, ACCENT_AMBER, ACCENT_GREEN, ACCENT_RED, BORDER_GLASS
)
from app.mcp.registry import MCPToolRegistry
from app.mcp.client import MCPClient

def render_settings_page():
    """Render the configuration settings dashboard."""
    st.markdown(
        render_hero_banner("System Settings", "Configure AI routing engines and enterprise vendor credentials"),
        unsafe_allow_html=True
    )

    tab_keys, tab_llm, tab_mcp = st.tabs([
        "🔑 API Credentials & Keys", 
        "🤖 LLM Routing & Config", 
        "🔌 MCP Integrations"
    ])

    # ── TAB 1: API Keys & Telemetry ──────────────────────────────────────────
    with tab_keys:
        st.subheader("🔑 Core API Configuration Keys")
        st.write(
            "Configure your primary language model endpoints and tracing credentials persistently. "
            "All settings are saved directly to your local `.env` configuration file."
        )
        
        if "settings_openai_api_key" not in st.session_state:
            st.session_state.settings_openai_api_key = os.getenv("OPENAI_API_KEY", "")
        if "settings_langchain_tracing" not in st.session_state:
            st.session_state.settings_langchain_tracing = os.getenv("LANGCHAIN_TRACING_V2", "false").lower() == "true"
        if "settings_langchain_api_key" not in st.session_state:
            st.session_state.settings_langchain_api_key = os.getenv("LANGCHAIN_API_KEY", "")
        if "settings_langchain_project" not in st.session_state:
            st.session_state.settings_langchain_project = os.getenv("LANGCHAIN_PROJECT", "ai-security-showcase")
            
        col_api_1, col_api_2 = st.columns(2)
        with col_api_1:
            st.text_input(
                "OpenAI API Key (OPENAI_API_KEY)",
                type="password",
                key="settings_openai_api_key",
                help="Primary LLM authorization token (required for orchestrating the demo agents)"
            )
            st.toggle(
                "Enable LangSmith Tracing (LANGCHAIN_TRACING_V2)",
                key="settings_langchain_tracing",
                help="Set to True to activate real-time prompt telemetry."
            )
        with col_api_2:
            st.text_input(
                "LangSmith API Key (LANGCHAIN_API_KEY)",
                type="password",
                key="settings_langchain_api_key",
                help="LangChain personal access key for smith.langchain.com"
            )
            st.text_input(
                "LangSmith Project Workspace (LANGCHAIN_PROJECT)",
                key="settings_langchain_project",
                help="Project workspace name under smith.langchain.com"
            )

    # ── TAB 2: LLM Settings ──────────────────────────────────────────────────
    with tab_llm:
        st.subheader("LLM Routing Framework")
        st.write(
            "Configure model tiers and parameters. The platform operates on a three-tier routing model "
            "as outlined in **AGENTS.md Section 2**."
        )

        col_left, col_right = st.columns(2)

        with col_left:
            st.markdown(
                render_glass_card(
                    f"""
                    <strong style="color:{ACCENT_BLUE}; font-size:1.1rem;">Tier 1: Primary Analysis LLM</strong><br>
                    <span style="font-size:0.85rem; color:#a0a0c0;">Used for continuous daily exposure scans, CTEM asset boundary mapping, and agent orchestration.</span>
                    """, ACCENT_BLUE
                ),
                unsafe_allow_html=True
            )
            primary_model = st.selectbox(
                "Primary LLM Model Selection",
                ["gpt-4o-mini", "gpt-3.5-turbo"],
                index=0,
                key="settings_primary_model",
                help="Recommended: gpt-4o-mini for cost/quality balance"
            )

            st.markdown(
                render_glass_card(
                    f"""
                    <strong style="color:{ACCENT_GREEN}; font-size:1.1rem;">Tier 3: Reasoning LLM</strong><br>
                    <span style="font-size:0.85rem; color:#a0a0c0;">Used for complex exploit chains, reachability validation, and automated PR patch generation.</span>
                    """, ACCENT_GREEN
                ),
                unsafe_allow_html=True
            )
            reasoning_model = st.selectbox(
                "Reasoning LLM Model Selection",
                ["gpt-4o-mini", "gpt-4o", "gpt-4-turbo"],
                index=0,
                key="settings_reasoning_model",
                help="Recommended: gpt-4o-mini for speed and general reasoning"
            )

        with col_right:
            st.markdown(
                render_glass_card(
                    f"""
                    <strong style="color:{ACCENT_AMBER}; font-size:1.1rem;">Tier 2: Local LLM (Air-Gapped Option)</strong><br>
                    <span style="font-size:0.85rem; color:#a0a0c0;">Used where strict data residency applies. Gracefully falls back when Ollama is offline.</span>
                    """, ACCENT_AMBER
                ),
                unsafe_allow_html=True
            )
            local_model = st.selectbox(
                "Local LLM Model Selection",
                ["ollama - llama3.1:8b", "ollama - mistral"],
                index=0,
                key="settings_local_model",
                help="Requires local Ollama instance running on port 11434"
            )
            
            enable_ollama = st.toggle("Enable Local LLM Option", value=False, key="settings_enable_ollama")

        st.markdown("---")
        st.subheader("Model Hyperparameters")
        col_temp, col_tokens = st.columns(2)
        with col_temp:
            st.slider("Temperature (Creativity vs. Precision)", 0.0, 1.0, 0.2, 0.05, key="settings_temperature")
        with col_tokens:
            st.slider("Max Tokens Limit per call", 500, 4000, 2000, 100, key="settings_max_tokens")

    # ── TAB 2: MCP Integrations ──────────────────────────────────────────────
    with tab_mcp:
        st.subheader("12 Model Context Protocol (MCP) Endpoints")
        st.write(
            "The platform includes deep integrations with 10 enterprise security tools "
            "plus Jira and ServiceNow ticketing platforms. If credential keys are missing, "
            "it gracefully falls back to high-fidelity synthetic vendor response simulation."
        )

        registry = MCPToolRegistry()
        client = MCPClient(registry)

        # Categorize tools
        categories = {}
        for name, tool in registry.tools.items():
            cat = tool.category.upper()
            if cat not in categories:
                categories[cat] = []
            categories[cat].append((name, tool))

        # Show tools by category
        for cat, tools in categories.items():
            st.markdown(f"#### 🏷️ {cat} Tools")
            
            # Use columns for grid layout
            cols = st.columns(2)
            for idx, (name, tool) in enumerate(tools):
                col = cols[idx % 2]
                status = client.get_connection_status(name)
                
                status_html = ""
                if status["live"]:
                    status_html = f'<span class="badge badge-green">🟢 Connected (Live)</span>'
                else:
                    status_html = f'<span class="badge badge-blue">🔵 Connected (Mock Fallback)</span>'

                with col:
                    card_content = f"""
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <strong>{tool.display_name}</strong>
                        {status_html}
                    </div>
                    <div style="font-size:0.8rem; color:#a0a0c0; margin-top:4px;">
                        <strong>Type:</strong> {tool.category} | <strong>Capabilities:</strong> {", ".join(tool.capabilities)}
                    </div>
                    """
                    st.markdown(render_glass_card(card_content, ACCENT_BLUE if status["live"] else BORDER_GLASS), unsafe_allow_html=True)
                    
                    # Expander for credentials inputs
                    with st.expander(f"⚙️ Credentials for {tool.display_name}"):
                        for var in tool.required_env_vars:
                            session_key = f"settings_mcp_{name}_{var.lower()}"
                            current_val = st.session_state.get(session_key, os.getenv(var, ""))
                            
                            is_password = "KEY" in var or "PASSWORD" in var or "TOKEN" in var or "SECRET" in var
                            new_val = st.text_input(
                                f"Required Key: {var}",
                                value=current_val,
                                type="password" if is_password else "default",
                                key=session_key,
                                help=f"Set environment credential variable {var}"
                            )
                        
                        st.caption(f"Endpoints configured: {', '.join([f'{k}: {v}' for k,v in tool.endpoints.items()])}")
            st.markdown("<br>", unsafe_allow_html=True)

        def update_dotenv(updates: dict):
            env_path = ".env"
            lines = []
            if os.path.exists(env_path):
                try:
                    with open(env_path, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                except Exception:
                    pass
            
            new_lines = []
            updated_keys = set()
            
            for line in lines:
                stripped = line.strip()
                # If comment or empty, keep it
                if not stripped or stripped.startswith("#"):
                    new_lines.append(line)
                    continue
                
                if "=" in stripped:
                    try:
                        k, v = stripped.split("=", 1)
                        key = k.strip()
                        if key in updates:
                            new_lines.append(f"{key}={updates[key]}\n")
                            updated_keys.add(key)
                        else:
                            new_lines.append(line)
                    except Exception:
                        new_lines.append(line)
                else:
                    new_lines.append(line)
            
            # Append new updates not already in the file
            for k, v in updates.items():
                if k not in updated_keys and v is not None:
                    if k.startswith("LANGCHAIN_") and not any("LangSmith" in line for line in new_lines):
                        new_lines.append("\n# LangSmith (LLM Tracing & Observability)\n")
                    new_lines.append(f"{k}={v}\n")
            
            # Write back
            try:
                with open(env_path, "w", encoding="utf-8") as f:
                    f.writelines(new_lines)
            except Exception as e:
                st.error(f"Error writing .env file: {e}")
                    
            # Also update current runtime env
            for k, v in updates.items():
                if v is not None:
                    os.environ[k] = str(v)

        if st.button("💾 Apply Settings & Reload Connectors", use_container_width=True):
            env_updates = {}
            
            # LLM & Observability
            if "settings_openai_api_key" in st.session_state:
                env_updates["OPENAI_API_KEY"] = st.session_state.settings_openai_api_key
            if "settings_langchain_tracing" in st.session_state:
                env_updates["LANGCHAIN_TRACING_V2"] = "true" if st.session_state.settings_langchain_tracing else "false"
            if "settings_langchain_api_key" in st.session_state:
                env_updates["LANGCHAIN_API_KEY"] = st.session_state.settings_langchain_api_key
            if "settings_langchain_project" in st.session_state:
                env_updates["LANGCHAIN_PROJECT"] = st.session_state.settings_langchain_project

            # MCP Credentials
            for name, tool in registry.tools.items():
                for var in tool.required_env_vars:
                    session_key = f"settings_mcp_{name}_{var.lower()}"
                    if session_key in st.session_state:
                        env_updates[var] = st.session_state[session_key]

            # Write updates to .env and os.environ
            update_dotenv(env_updates)
            
            # Clear cached LLM router so that it gets re-instantiated with new API keys
            if "llm_router" in st.session_state:
                st.session_state.llm_router = None
            
            st.success("Configuration settings successfully applied and saved persistently to .env! API registry updated.")
            st.rerun()
