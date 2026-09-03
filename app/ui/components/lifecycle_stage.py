"""
AI Capability Demo — Lifecycle Stage Renderer
Horizontal stage progress bar, stage headers, stage layout.
AGENTS.md Section 6.
"""

from __future__ import annotations

from typing import Dict, List, Optional

import streamlit as st
import textwrap

from app.ui.theme import (
    ACCENT_AMBER,
    ACCENT_BLUE,
    ACCENT_GREEN,
    ACCENT_PURPLE,
    ACCENT_RED,
    BG_GLASS,
    BORDER_GLASS,
    RAG_GREEN,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    USE_CASE_COLOURS,
    USE_CASE_ICONS,
    USE_CASE_LABELS,
    render_glass_card,
)


def _get_previous_stage_output(use_case: str, stage_key: str) -> str:
    """Return a human-readable description of what the previous stage produced
    as input for the current stage. Used in the Input & Config panel."""
    
    prev_output_map = {
        "ctem": {
            "discovery": "Scoping stage produced a complete attack surface map with scoped assets, criticality scores, environment distribution, internet-exposure flags, and shadow IT detection results.",
            "prioritisation": "Discovery stage produced a raw vulnerability map with CVE IDs, CVSS scores, EPSS exploitation probabilities, CISA KEV collision flags, and patch availability status per finding.",
            "validation": "Prioritisation stage produced a P1/P2/P3 risk-ranked backlog with composite risk scores (Asset Criticality × Exploitability × KEV × EPSS × Exposure) and explicit ranking rationale.",
            "mobilisation": "Validation stage produced a confirmed exploitable findings list with false positive dismissals (each with written AI rationale) and exploitability confidence scores.",
        },
    }
    
    return prev_output_map.get(use_case, {}).get(stage_key, "")


# ── Stage Definitions ───────────────────────────────────────────────────────

STAGE_DEFINITIONS: Dict[str, List[Dict[str, str]]] = {
    "ctem": [
        {
            "key": "scoping",
            "name": "Scoping",
            "icon": "📐",
            "description": "Ingest asset inventory, business context, and critical data classifications to establish the attack surface boundary.",
            "agent": "CTEMScopingAgent",
        },
        {
            "key": "discovery",
            "name": "Discovery",
            "icon": "🔎",
            "description": "Continuously scan all scoped assets for vulnerabilities, misconfigurations, and software weaknesses.",
            "agent": "CTEMDiscoveryAgent",
        },
        {
            "key": "prioritisation",
            "name": "Prioritisation",
            "icon": "📊",
            "description": "Rank vulnerabilities by ACTUAL risk — business context × exploitability × KEV status × EPSS score.",
            "agent": "CTEMPrioritisationAgent",
        },
        {
            "key": "validation",
            "name": "Validation",
            "icon": "✅",
            "description": "Validate exploitability of prioritised findings. Remove false positives via network reachability reasoning.",
            "agent": "CTEMValidatorAgent",
        },
        {
            "key": "mobilisation",
            "name": "Mobilisation",
            "icon": "🚀",
            "description": "Automate remediation — specific fix instructions, ownership assignment, and workflow ticketing.",
            "agent": "CTEMRemediationAgent",
        },
    ],
}


# ── Input & Output Dataset Mapping ──────────────────────────────────────────

STAGE_INPUT_OUTPUT_MAP = {
    "ctem": {
        "scoping": {
            "input_key": "asset_inventory",
            "input_name": "CMDB Asset Register",
            "input_desc": "Enterprise asset inventory containing network profiles, hostname lists, environment classifications, and owner teams.",
            "output_key": "asset_inventory",
            "output_name": "Scoped Assets Boundary Map",
            "output_desc": "A consolidated boundary map prioritizing exposed, external, and business-critical devices, ready for active security vulnerability scanning.",
        },
        "discovery": {
            "input_key": "asset_inventory",
            "input_name": "Scoped Assets Boundary Map",
            "input_desc": "Target assets defined in Scoping phase, mapped to network exposure zones and owner teams.",
            "output_key": "vulnerability_findings",
            "output_name": "Active Vulnerability Scan Results",
            "output_desc": "Raw list of active scanner findings, CVE matches, CVSS vectors, and patch availability telemetry.",
        },
        "prioritisation": {
            "input_key": "vulnerability_findings",
            "input_name": "Active Vulnerability Scan Results",
            "input_desc": "Scan results listing discovered CVEs, CVSS scores, and target assets.",
            "output_key": "remediation_backlog",
            "output_name": "Risk-Prioritised Vulnerability Backlog",
            "output_desc": "Risk-weighted vulnerability list prioritized by combining threat feeds (EPSS + CISA KEV) with business exposure contexts.",
        },
        "validation": {
            "input_key": "remediation_backlog",
            "input_name": "Risk-Prioritised Vulnerability Backlog",
            "input_desc": "Prioritized vulnerability queue awaiting exploit verification.",
            "output_key": "validation_results",
            "output_name": "Exploit-Validated Vulnerability Findings",
            "output_desc": "A validated list of true positive exploitable vulnerabilities after weeding out firewalled ports and shielded compensating controls.",
        },
        "mobilisation": {
            "input_key": "validation_results",
            "input_name": "Exploit-Validated Vulnerability Findings",
            "input_desc": "True-positive vulnerability findings with proof-of-concept verification data.",
            "output_key": "remediation_backlog",
            "output_name": "Remediation Ticket Package",
            "output_desc": "Closed-loop ticketing package containing specific, actionable remediation steps, assigned owners, and auto-generated Jira/ServiceNow credentials.",
        },
    },
}


# ── Public API ───────────────────────────────────────────────────────────────

def get_stages_for_usecase(use_case: str) -> List[Dict[str, str]]:
    """Return the ordered list of stage definitions for a use case."""
    return STAGE_DEFINITIONS.get(use_case, [])


def render_stage_progress(
    use_case: str,
    stages: List[Dict[str, str]],
    active_stage: int,
    completed_stages: List[int],
) -> Optional[int]:
    """Render horizontal pill-tab progress bar. Returns clicked stage index or None."""
    accent = USE_CASE_COLOURS.get(use_case, ACCENT_BLUE)
    total = len(stages)

    # Build the pill row HTML
    pills_html = ""
    for idx, stage in enumerate(stages):
        if idx in completed_stages:
            state_cls = "completed"
            icon = "✓"
        elif idx == active_stage:
            state_cls = "active"
            icon = stage["icon"]
        else:
            state_cls = ""
            icon = stage["icon"]

        # Dynamic accent colour for active state
        active_bg = f"rgba({int(accent[1:3],16)},{int(accent[3:5],16)},{int(accent[5:7],16)},0.15)"
        active_shadow = f"rgba({int(accent[1:3],16)},{int(accent[3:5],16)},{int(accent[5:7],16)},0.2)"

        style = ""
        if state_cls == "active":
            style = f"border-color:{accent}; background:{active_bg}; color:#ffffff; box-shadow:0 4px 16px {active_shadow};"
        elif state_cls == "completed":
            style = f"border-color:{RAG_GREEN}; color:{RAG_GREEN};"

        # Connector line between pills
        connector = ""
        if idx < total - 1:
            conn_colour = RAG_GREEN if idx in completed_stages else BORDER_GLASS
            connector = f'<span style="display:inline-block;width:24px;height:2px;background:{conn_colour};vertical-align:middle;margin:0 4px;"></span>'

        pills_html += f'<span class="stage-pill {state_cls}" style="{style}">{icon} {stage["name"]}</span>{connector}'

    st.markdown(
        f'<div style="display:flex;align-items:center;flex-wrap:wrap;gap:4px;margin-bottom:20px;">{pills_html}</div>',
        unsafe_allow_html=True,
    )

    # Streamlit buttons for actual navigation (hidden via selectbox for cleaner UX)
    cols = st.columns(total)
    clicked: Optional[int] = None
    for idx, stage in enumerate(stages):
        with cols[idx]:
            label = f"{'✓ ' if idx in completed_stages else ''}{stage['name']}"
            if st.button(label, key=f"stage_nav_{use_case}_{idx}", use_container_width=True):
                clicked = idx

    return clicked


def render_stage_header(
    stage_name: str,
    stage_number: int,
    total_stages: int,
    description: str,
    accent_colour: str = ACCENT_BLUE,
) -> None:
    """Render stage title with number badge and description."""
    badge_bg = f"rgba({int(accent_colour[1:3],16)},{int(accent_colour[3:5],16)},{int(accent_colour[5:7],16)},0.2)"

    st.markdown(textwrap.dedent(f"""
    <div style="display:flex; align-items:center; gap:16px; margin-bottom:16px;">
        <div style="
            min-width:44px; height:44px;
            background:{badge_bg};
            border:2px solid {accent_colour};
            border-radius:12px;
            display:flex; align-items:center; justify-content:center;
            font-size:1.1rem; font-weight:800; color:{accent_colour};
        ">{stage_number}</div>
        <div>
            <div style="font-size:1.3rem; font-weight:700; color:{TEXT_PRIMARY}; letter-spacing:-0.02em;">
                {stage_name}
                <span style="font-size:0.75rem; color:{TEXT_MUTED}; font-weight:400; margin-left:8px;">
                    Stage {stage_number} of {total_stages}
                </span>
            </div>
            <div style="font-size:0.85rem; color:{TEXT_SECONDARY}; margin-top:2px;">{description}</div>
        </div>
    </div>
    """), unsafe_allow_html=True)


def render_stage_layout(
    use_case: str,
    stage: Dict[str, str],
):
    """Render 3-column layout: Input (left) | Config+Remediation (centre) | Guardrails (right).

    Returns the three column objects so callers can inject content.
    """
    accent = USE_CASE_COLOURS.get(use_case, ACCENT_BLUE)

    col_left, col_centre, col_right = st.columns([3, 4, 3])

    with col_left:
        st.markdown(render_glass_card(
            f"""
            <div style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.1em;color:{TEXT_MUTED};font-weight:600;margin-bottom:8px;">
                📥 Input Data
            </div>
            <div style="font-size:0.85rem;color:{TEXT_SECONDARY};">
                Upload or connect data sources for this stage.
            </div>
            """,
            accent=accent,
        ), unsafe_allow_html=True)

    with col_centre:
        st.markdown(render_glass_card(
            f"""
            <div style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.1em;color:{TEXT_MUTED};font-weight:600;margin-bottom:8px;">
                ⚙️ Configuration & Analysis
            </div>
            <div style="font-size:0.85rem;color:{TEXT_SECONDARY};">
                Agent: <span style="color:{accent};font-weight:600;">{stage.get('agent', 'N/A')}</span>
            </div>
            """,
            accent=accent,
        ), unsafe_allow_html=True)

    with col_right:
        st.markdown(render_glass_card(
            f"""
            <div style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.1em;color:{TEXT_MUTED};font-weight:600;margin-bottom:8px;">
                🛡️ Guardrails & HITL
            </div>
            <div style="font-size:0.85rem;color:{TEXT_SECONDARY};">
                Human-in-the-loop gates for critical decisions.
            </div>
            """,
            accent=accent,
        ), unsafe_allow_html=True)

    return col_left, col_centre, col_right


def get_dataset_name_for_stage(use_case: str, stage_key: str) -> str:
    mappings = {
        "ctem": {
            "scoping": "Asset Inventory (2,000 corporate devices)",
            "discovery": "Vulnerability Findings (5,000 active scan logs)",
            "prioritisation": "Remediation Backlog (1,000 raw vulnerabilities)",
            "validation": "Validation Results (500 tested exploit paths)",
            "mobilisation": "Remediation Backlog (1,000 prioritized backlog items)",
        },
        "devsecops": {
            "pipeline": "Code Commits, Review Findings & Pull Requests (DevSecOps pipeline datasets)",
        },
    }
    return mappings.get(use_case, {}).get(stage_key, "Security Event Telemetry")


def get_agent_details_for_stage(use_case: str, stage_key: str) -> dict:
    mappings = {
        "ctem": {
            "scoping": {
                "agent": "CTEMScopingAgent",
                "analysis": "Ingests asset registers, public DNS, and Cloud resources to map external attack surface perimeter and discover unmanaged Shadow IT.",
                "output": "Classified asset boundary lists, shadow assets, and business critical environment heatmaps."
            },
            "discovery": {
                "agent": "CTEMDiscoveryAgent",
                "analysis": "Correlates CVE catalog feeds, threat bulletins, and scan results against asset classes and firmware versions.",
                "output": "Raw vulnerability map showing CVE IDs, CVSS, EPSS, CISA KEV collisions, and patch availability."
            },
            "prioritisation": {
                "agent": "CTEMPrioritisationAgent",
                "analysis": "Applies contextual business risk weights, network exposure metrics, and active exploit intelligence to score vulnerabilities.",
                "output": "Risk-ranked exposure remediation backlog prioritizing exploitable over theoretical vulnerabilities."
            },
            "validation": {
                "agent": "CTEMValidatorAgent",
                "analysis": "Determines network route connectivity and WAF shield coverage to validate true vulnerability exploitability and flag false positives.",
                "output": "Confirmed active threat list and detailed False Positive Log with machine-readable justification."
            },
            "mobilisation": {
                "agent": "CTEMRemediationAgent",
                "analysis": "Generates exact command-line syntax and patching blueprints for remediation teams and opens integrated workflow tickets.",
                "output": "Remediation playbooks, custom SLA timers, and successfully synchronized Jira/ServiceNow tickets."
            }
        },
    }
    return mappings.get(use_case, {}).get(stage_key, {
        "agent": "SecurityAgent",
        "analysis": "Analyzes ingested security data against known attack rules.",
        "output": "Findings and remediation advice."
    })


def render_agent_details_bar(use_case: str, stage_key: str):
    """Renders a beautiful, high-contrast, premium horizontal agent details bar matching Reference Image 4."""
    from app.ui.theme import clean_html, BORDER_GLASS, TEXT_SECONDARY
    accent = USE_CASE_COLOURS.get(use_case, ACCENT_BLUE)
    info = get_agent_details_for_stage(use_case, stage_key)
    agent_name = info["agent"]
    analysis = info["analysis"]
    output_text = info["output"]
    
    html = f"""
    <div style="
        background: linear-gradient(90deg, rgba(10, 14, 39, 0.95) 0%, rgba(17, 22, 56, 0.95) 100%);
        border: 1px solid {BORDER_GLASS};
        border-left: 4px solid {accent};
        border-radius: 8px;
        padding: 12px 16px;
        margin-top: 10px;
        margin-bottom: 20px;
        font-family: 'Inter', sans-serif;
        line-height: 1.5;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
    ">
        <div style="display: flex; flex-wrap: wrap; align-items: center; gap: 16px; font-size: 0.85rem;">
            <div style="font-weight: 700; color: #ffffff; display: flex; align-items: center; gap: 6px;">
                <span style="font-size: 1.1rem; color: {accent};">🤖</span> 
                @Agent Scope: <span style="color: {accent};">{agent_name}</span>
            </div>
            <div style="height: 14px; width: 1px; background: {BORDER_GLASS}; display: inline-block;"></div>
            <div style="flex: 1; min-width: 250px; color: {TEXT_SECONDARY};">
                <span style="font-weight: 600; color: #e8e8e8;">🧠 Expected AI Analysis:</span> {analysis}
            </div>
            <div style="height: 14px; width: 1px; background: {BORDER_GLASS}; display: inline-block;"></div>
            <div style="flex: 1; min-width: 250px; color: {TEXT_SECONDARY}; font-size: 0.85rem;">
                <span style="font-weight: 600; color: #e8e8e8;">📄 Expected Output:</span> {output_text}
            </div>
        </div>
    </div>
    """
    st.markdown(clean_html(html), unsafe_allow_html=True)


def render_3col_input_panel(
    use_case: str,
    stage_key: str,
    default_categories: list[str],
    frameworks_list: list[str],
    guardrail_info: dict[str, str],
    df_preview = None
):
    """Render a premium glassmorphic three-column input panel and returns the user choices.
    
    Returns: (data_source, filters_dict, selected_frameworks, custom_scenario)
    """
    import textwrap
    from app.ui.theme import USE_CASE_COLOURS, ACCENT_BLUE, BORDER_GLASS, TEXT_SECONDARY, TEXT_MUTED, render_badge
    accent = USE_CASE_COLOURS.get(use_case, ACCENT_BLUE)
    
    st.markdown('<div class="glass-card" style="padding: 24px; margin-bottom: 24px;">', unsafe_allow_html=True)
    
    col_left, col_centre, col_right = st.columns([1, 1, 1])
    
    with col_left:
        st.markdown(f'<div style="font-size:0.95rem; font-weight:700; color:{accent}; margin-bottom:12px;">📥 Column 1: Ingestion & Filtering</div>', unsafe_allow_html=True)
        
        # Display the targeted dataset indicator dynamically
        stage_info = STAGE_INPUT_OUTPUT_MAP.get(use_case, {}).get(stage_key, {})
        input_key = stage_info.get("input_key")
        input_name = stage_info.get("input_name", "Raw Security Telemetry")
        input_desc = stage_info.get("input_desc", "Security telemetry payload ingested into the pipeline.")
        
        # Get dataframe dynamically from session state
        df_in = st.session_state.get("datasets", {}).get(input_key)
        rows_count = 0
        cols_count = 0
        col_names = []
        if df_in is not None:
            rows_count = len(df_in)
            cols_count = len(df_in.columns)
            col_names = list(df_in.columns)
            
        first_stages = ["scoping", "hypothesis", "reconnaissance", "requirements"]
        is_first_stage = stage_key in first_stages
        
        header_text = "📁 Target Ingested Dataset" if is_first_stage else "🔄 Input Payload (From Previous Stage)"
        header_color = accent if is_first_stage else "#00ff88"
        
        st.markdown(f"""
        <div style="
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid {BORDER_GLASS};
            border-left: 3px solid {header_color};
            border-radius: 8px;
            padding: 12px 14px;
            margin-bottom: 12px;
            font-family: 'Inter', sans-serif;
            line-height: 1.4;
        ">
            <div style="font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; color: {header_color}; font-weight: bold; margin-bottom: 4px;">
                {header_text}
            </div>
            <div style="font-size: 0.9rem; font-weight: bold; color: #ffffff; margin-bottom: 6px;">
                {input_name}
            </div>
            <div style="font-size: 0.78rem; color: #a0a0c0; margin-bottom: 10px;">
                {input_desc}
            </div>
            <div style="display: flex; gap: 12px; font-size: 0.75rem; color: #e2e8f0; font-family: 'JetBrains Mono', monospace; background: rgba(255, 255, 255, 0.03); padding: 6px 8px; border-radius: 4px; margin-bottom: 8px;">
                <span>📊 {rows_count:,} rows</span>
                <span>🎛️ {cols_count} columns</span>
            </div>
            <div style="font-size: 0.72rem; color: #8a8aae; word-break: break-all; line-height: 1.3;">
                <strong>Schema:</strong> {', '.join(col_names[:8])}{'...' if len(col_names) > 8 else ''}
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Expander for input preview inside Column 1
        if df_in is not None and not df_in.empty:
            with st.expander(f"🔍 Preview Received Input ({rows_count:,} rows)", expanded=False):
                st.dataframe(df_in, use_container_width=True, hide_index=True)
                
        # Show what the previous stage output to THIS stage
        if not is_first_stage:
            prev_stage_output = _get_previous_stage_output(use_case, stage_key)
            if prev_stage_output:
                st.markdown(f"""
                <div style="background: rgba(0, 255, 136, 0.04); border: 1px solid rgba(0, 255, 136, 0.12); border-radius: 8px; padding: 12px; margin-bottom: 12px; font-size: 0.8rem; line-height: 1.5;">
                    <div style="color: #00ff88; font-weight: 700; margin-bottom: 6px; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em;">
                        ⬇️ Received from Previous Stage
                    </div>
                    <div style="color: #c0c0d8;">{prev_stage_output}</div>
                </div>
                """, unsafe_allow_html=True)

        data_provider = st.radio(
            "Data Source Provider",
            options=[
                "API/MCP Live Tools (Priority 1)",
                "File Upload Ingestion (Priority 2)",
                "Synthetic Data Engine (Priority 3)"
            ],
            index=2,  # Default to Synthetic
            key=f"{use_case}_{stage_key}_source_sel"
        )
        if "API/MCP" in data_provider:
            data_source = "mcp"
        elif "File Upload" in data_provider:
            data_source = "upload"
        else:
            data_source = "synthetic"
            
        uploaded_file = None
        parsed = {}
        
        if data_source == "mcp":
            from app.mcp.client import MCPClient
            mcp_client = MCPClient()
            use_case_tools = []
            if use_case == "ctem":
                use_case_tools = ["tenable_io", "qualys_vmdr", "wiz", "prisma_cloud", "aws_security_hub", "snyk"]
            elif use_case == "devsecops":
                use_case_tools = ["github", "gitlab", "semgrep", "sonarqube"]
            
            st.markdown('<div style="font-size:0.75rem; color:#a0a0c0; margin-top:8px; margin-bottom:4px;">MCP / API Connection Status</div>', unsafe_allow_html=True)
            cols = st.columns(2)
            for idx, tool_id in enumerate(use_case_tools):
                status_info = mcp_client.get_connection_status(tool_id)
                tool_meta = mcp_client.registry.get_tool(tool_id)
                disp_name = tool_meta.display_name if tool_meta else tool_id.upper()
                
                is_live = status_info.get("live", False)
                status_label = "🟢 Live" if is_live else "🟠 Mock"
                status_bg = "rgba(0, 255, 136, 0.08)" if is_live else "rgba(255, 170, 0, 0.08)"
                status_border = "rgba(0, 255, 136, 0.2)" if is_live else "rgba(255, 170, 0, 0.2)"
                status_color = "#00ff88" if is_live else "#ffaa00"
                
                with cols[idx % 2]:
                    st.markdown(
                        f'<div style="background:{status_bg}; border:1px solid {status_border}; border-radius:6px; padding:3px 6px; margin-bottom:4px; font-size:0.68rem; color:{status_color}; font-weight:bold; display:flex; justify-content:space-between; align-items:center;">'
                        f'<span>🔌 {disp_name}</span>'
                        f'<span style="font-size:0.58rem;">{status_label}</span>'
                        f'</div>',
                        unsafe_allow_html=True
                    )
                    
        elif data_source == "upload":
            allowed_ext_map = {
                "ctem": ["json", "csv", "yaml", "yml", "tf", "conf", "txt"],
                "devsecops": ["json", "diff", "patch", "txt", "yaml", "yml"],
            }
            allowed_exts = allowed_ext_map.get(use_case, ["txt", "csv", "json"])
            st.markdown('<div style="font-size:0.75rem; color:#a0a0c0; margin-top:8px; margin-bottom:4px;">Operational Data File Ingestion</div>', unsafe_allow_html=True)
            uploaded_file = st.file_uploader(
                "Upload Operational Data File",
                type=allowed_exts,
                key=f"{use_case}_{stage_key}_file_uploader",
                label_visibility="collapsed"
            )
            if uploaded_file is not None:
                from app.upload.processor import FileUploadProcessor
                processor = FileUploadProcessor()
                parsed = processor.process(uploaded_file)
                if parsed.get("type") == "error":
                    st.error(f"❌ Parser Error: {parsed.get('data')}")
                else:
                    st.success(f"✅ Successfully Parsed: {parsed.get('filename')}")
                    if parsed.get("type") == "dataframe":
                        st.markdown(
                            f"""
                            <div style="font-size:0.75rem; background:rgba(0, 255, 136, 0.05); border:1px solid rgba(0, 255, 136, 0.15); border-radius:6px; padding:6px; margin-top:4px; margin-bottom:8px;">
                                <strong>Format:</strong> {parsed.get('extension').upper()[1:]} DataFrame<br>
                                <strong>Rows:</strong> {parsed.get('rows'):,}<br>
                                <strong>Columns:</strong> {parsed.get('columns'):,}
                            </div>
                            """,
                            unsafe_allow_html=True
                        )
                        df_preview = parsed.get("data")
                    elif parsed.get("type") == "dict":
                        st.markdown(
                            f"""
                            <div style="font-size:0.75rem; background:rgba(0, 255, 136, 0.05); border:1px solid rgba(0, 255, 136, 0.15); border-radius:6px; padding:6px; margin-top:4px; margin-bottom:8px;">
                                <strong>Format:</strong> YAML Document<br>
                                <strong>Keys:</strong> {len(parsed.get('data', {}))} keys loaded
                            </div>
                            """,
                            unsafe_allow_html=True
                        )
                    else:
                        text_len = len(parsed.get('data', ''))
                        st.markdown(
                            f"""
                            <div style="font-size:0.75rem; background:rgba(0, 255, 136, 0.05); border:1px solid rgba(0, 255, 136, 0.15); border-radius:6px; padding:6px; margin-top:4px; margin-bottom:8px;">
                                <strong>Format:</strong> Document Text<br>
                                <strong>Size:</strong> {text_len:,} characters
                            </div>
                            """,
                            unsafe_allow_html=True
                        )
            else:
                st.info("ℹ️ Please upload a file to proceed.")
        
        filters = {}

    with col_centre:
        st.markdown(f'<div style="font-size:0.95rem; font-weight:700; color:{accent}; margin-bottom:12px;">🛡️ Column 2: Frameworks & Scenario</div>', unsafe_allow_html=True)
        
        selected_fws = st.multiselect(
            "Compliance & Regulatory Frameworks",
            frameworks_list,
            default=frameworks_list[:2] if len(frameworks_list) >= 2 else frameworks_list,
            key=f"{use_case}_{stage_key}_fw_sel"
        )
        
        # Render beautiful visual tags based on selection
        if selected_fws:
            badges_html = '<div style="margin-top: 8px; margin-bottom: 12px; display: flex; flex-wrap: wrap; gap: 6px;">'
            for fw in selected_fws:
                fw_l = fw.lower()
                variant = "blue"
                if "nist" in fw_l: variant = "blue"
                elif "mitre" in fw_l or "attack" in fw_l: variant = "red"
                elif "cis" in fw_l: variant = "amber"
                elif "owasp" in fw_l: variant = "purple"
                elif "sigma" in fw_l: variant = "green"
                badges_html += render_badge(fw, variant)
            badges_html += '</div>'
            st.markdown(badges_html, unsafe_allow_html=True)
            
        custom_scenario = st.text_area(
            "Custom Threat Scenario / Scope Context",
            placeholder="Enter specific asset hostnames, IP ranges, threat actors, or target logic specs to direct the agent...",
            key=f"{use_case}_{stage_key}_scenario_txt",
            height=110
        )
        
    with col_right:
        st.markdown(f'<div style="font-size:0.95rem; font-weight:700; color:{accent}; margin-bottom:12px;">👁️ Column 3: Active Guardrails</div>', unsafe_allow_html=True)
        
        # Read-only guardrail list
        st.markdown(
            textwrap.dedent(f"""\
            <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid {BORDER_GLASS}; border-radius: 12px; padding: 14px 18px; min-height: 250px;">
                <div style="font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; color: {TEXT_MUTED}; font-weight: bold; margin-bottom: 10px;">
                    Active Security Shields
                </div>
                <div style="margin-bottom: 8px;">
                    <span style="display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.68rem; font-weight: bold; background: rgba(0, 255, 136, 0.12); color: #00ff88; border: 1px solid rgba(0, 255, 136, 0.3);">
                        🟢 Pydantic v2 Schema
                    </span>
                    <div style="font-size: 0.68rem; color: #a0a0c0; margin-left: 6px; margin-top: 2px;">Ensures strictly structured agent output formats.</div>
                </div>
                <div style="margin-bottom: 8px;">
                    <span style="display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.68rem; font-weight: bold; background: rgba(0, 255, 136, 0.12); color: #00ff88; border: 1px solid rgba(0, 255, 136, 0.3);">
                        🟢 OpenAI Moderation API
                    </span>
                    <div style="font-size: 0.68rem; color: #a0a0c0; margin-left: 6px; margin-top: 2px;">Filters prompt injection and malicious payloads.</div>
                </div>
                <div style="margin-bottom: 10px;">
                    <span style="display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.68rem; font-weight: bold; background: rgba(255, 170, 0, 0.12); color: #ffaa00; border: 1px solid rgba(255, 170, 0, 0.3);">
                        🟢 {guardrail_info.get("hitl_level", "HITL Gate Threshold")}
                    </span>
                    <div style="font-size: 0.68rem; color: #a0a0c0; margin-left: 6px; margin-top: 2px;">{guardrail_info.get("hitl_desc", "Requires manual review.")}</div>
                </div>
                <div style="background: rgba(255, 107, 53, 0.05); border: 1px solid rgba(255, 107, 53, 0.2); border-radius: 6px; padding: 8px; font-size: 0.68rem; color: #ff6b35;">
                    <strong>🛡️ Safety Rule:</strong> {guardrail_info.get("safety_rule", "Containment requires strict analyst review.")}
                </div>
            </div>"""),
            unsafe_allow_html=True
        )

    # Bottom Expandable Preview Section
    if data_source == "upload" and uploaded_file is not None and parsed.get("type") != "error":
        if parsed.get("type") == "dataframe" and df_preview is not None and not df_preview.empty:
            st.markdown('<div style="margin-top: 15px;"></div>', unsafe_allow_html=True)
            with st.expander("🔍 View Filtered Input Data Preview"):
                st.dataframe(df_preview, use_container_width=True)
        elif parsed.get("type") == "dict":
            st.markdown('<div style="margin-top: 15px;"></div>', unsafe_allow_html=True)
            with st.expander("🔍 View Parsed YAML Content"):
                st.json(parsed.get("data"))
        elif parsed.get("type") == "text":
            st.markdown('<div style="margin-top: 15px;"></div>', unsafe_allow_html=True)
            with st.expander("🔍 View Raw Text Content"):
                st.code(parsed.get("data")[:5000] + ("..." if len(parsed.get("data", "")) > 5000 else ""))
    elif df_preview is not None and not df_preview.empty:
        st.markdown('<div style="margin-top: 15px;"></div>', unsafe_allow_html=True)
        with st.expander("🔍 View Filtered Input Data Preview"):
            st.dataframe(df_preview, use_container_width=True)
            
    st.markdown('</div>', unsafe_allow_html=True)
    
    return data_source, filters, selected_fws, custom_scenario


def render_usecase_overview_card(use_case: str):
    """Renders a high-fidelity executive brief, goal statement, and mapped regulatory framework badges for the active usecase. (Gap 2)"""
    from app.ui.theme import clean_html, BORDER_GLASS, TEXT_SECONDARY, TEXT_MUTED, render_badge
    
    details = {
        "ctem": {
            "title": "🎯 AI-Led Continuous Threat Exposure Management (CTEM)",
            "subtitle": "Attack Surface Visibility · Exploit Path Validation · Remediation Mobilization",
            "goal": "Establish a continuous, threat-informed, and business-aligned exposure mitigation pipeline. Dynamically discover shadow assets, assess exploitability, prioritize by actual threat risk (EPSS + CISA KEV), and trigger workflow remediation to systematically compress Mean Time to Resolution (MTTR).",
            "frameworks": ["NIST CSF 2.0", "CIS Controls", "CISA KEV", "CVSS v3.1", "EPSS"],
            "color": "#00d4ff"
        },
        "devsecops": {
            "title": "🐙 AI-Led DevSecOps Pipeline",
            "subtitle": "AI-Driven Code Review · Exploit Chain Analysis · AI-Driven Fix Generation · Gated Deployment",
            "goal": "Shift security left into the developer workflow at machine speed. Automatically review every commit for SQL injection, hardcoded secrets, and vulnerable packages, explain the exploit chain in plain language, generate a fix and open a pull request, run automated security validation, and gate deployment behind a human approval — turning a multi-day security review cycle into minutes.",
            "frameworks": ["OWASP Top 10", "CWE Top 25", "NIST SSDF"],
            "color": "#00ff88"
        }
    }
    
    info = details.get(use_case)
    if not info:
        return
        
    color = info["color"]
    badges_html = " ".join([render_badge(fw, "blue" if "nist" in fw.lower() else ("red" if "attack" in fw.lower() else ("amber" if "cis" in fw.lower() else ("purple" if "owasp" in fw.lower() or "cwe" in fw.lower() else "green")))) for fw in info["frameworks"]])
    
    html = f"""
    <div class="glass-card usecase-overview-card" style="
        border-top: 3px solid {color} !important;
        border-radius: 12px;
        padding: 20px 24px;
        margin-bottom: 24px;
        font-family: 'Inter', sans-serif;
    ">
        <div style="display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 12px;">
            <div>
                <div style="font-size: 1.25rem; font-weight: 800; color: #ffffff; letter-spacing: -0.02em;">{info["title"]}</div>
                <div style="font-size: 0.8rem; font-weight: 600; color: {color}; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 2px;">{info["subtitle"]}</div>
            </div>
            <div style="display: flex; gap: 6px; flex-wrap: wrap;">
                {badges_html}
            </div>
        </div>
        <div style="font-size: 0.88rem; color: #a0a0c0; line-height: 1.6; border-top: 1px solid {BORDER_GLASS}; padding-top: 12px;">
            <strong style="color: #e8e8e8;">🎯 STRATEGIC GOAL STATEMENT:</strong> {info["goal"]}
        </div>
    </div>
    """
    st.markdown(clean_html(html), unsafe_allow_html=True)

