"""
AI Capability Demo — CTEM (Continuous Threat Exposure Management) Page
Implements the 5-stage CTEM lifecycle: Scoping, Discovery, Prioritisation, Validation, Mobilisation.
Ensures outputs flow sequentially: Stage N -> Stage N+1.
"""

import streamlit as st
import textwrap
import pandas as pd
import time
from typing import Dict, Any, List

from app.ui.theme import (
    ACCENT_BLUE,
    ACCENT_GREEN,
    ACCENT_RED,
    ACCENT_AMBER,
    TEXT_MUTED,
    TEXT_SECONDARY,
    TEXT_PRIMARY,
    BORDER_GLASS,
    render_glass_card,
    render_metric_card,
    USE_CASE_COLOURS,
    desaturate_colour,
)
from app.ui.components.lifecycle_stage import (
    get_stages_for_usecase,
    render_stage_header,
    render_stage_progress,
    render_3col_input_panel,
    render_agent_details_bar,
    render_usecase_overview_card,
)
from app.ui.components.interactive_demo import (
    render_execute_button,
    render_progress_indicator,
    render_ai_results,
    render_hitl_gate,
)
from app.ui.components.charts import (
    create_bar_chart,
    create_donut_chart,
    create_gauge_chart,
    render_attack_chain_diagram,
)
from app.runtime.agent_manager import AgentManager
from app.workflow.remediation import RemediationWorkflowEngine, WorkflowItem

def render_ctem_page(
    datasets: Dict[str, pd.DataFrame],
    agent_manager: AgentManager,
    kpi_engine: Any,
) -> None:
    """Render the CTEM 5-stage lifecycle workspace."""
    
    # Initialize data source key
    data_source_key = "active_data_source_ctem"
    if data_source_key not in st.session_state:
        st.session_state[data_source_key] = "synthetic"
    data_source = st.session_state[data_source_key]
    accent = desaturate_colour(ACCENT_BLUE, 0.3) if data_source == "synthetic" else ACCENT_BLUE

    st.markdown(f'<h1 style="color: {accent}; margin-bottom: 8px;">🎯 Continuous Threat Exposure Management (CTEM)</h1>', unsafe_allow_html=True)
    render_usecase_overview_card("ctem")
    
    # Initialize CTEM specific session state
    if "ctem_active_stage" not in st.session_state:
        st.session_state.ctem_active_stage = 0
    if "ctem_completed_stages" not in st.session_state:
        st.session_state.ctem_completed_stages = []
    if "ctem_stage_outputs" not in st.session_state:
        st.session_state.ctem_stage_outputs = {}
    if "ctem_hitl_approved" not in st.session_state:
        st.session_state.ctem_hitl_approved = {}
        
    stages = get_stages_for_usecase("ctem")
    active_idx = st.session_state.ctem_active_stage
    completed_stages = st.session_state.ctem_completed_stages
    
    # ── Horizontal Stage Navigation ──
    clicked_stage = render_stage_progress("ctem", stages, active_idx, completed_stages)
    if clicked_stage is not None:
        st.session_state.ctem_active_stage = clicked_stage
        st.rerun()
        
    st.markdown("---")
    
    # Render stage header
    active_stage = stages[active_idx]
    render_stage_header(
        stage_name=active_stage["name"],
        stage_number=active_idx + 1,
        total_stages=len(stages),
        description=active_stage["description"],
        accent_colour=accent
    )
    
    # Define categories, frameworks, and guardrails for the 3-column input panel
    stage_key = active_stage["key"]
    
    # Load default data source from session state or fallback
    data_source_key = f"active_data_source_ctem"
    if data_source_key not in st.session_state:
        st.session_state[data_source_key] = "synthetic"
        
    if stage_key == "scoping":
        default_categories = ["Server", "Workstation", "Network", "Cloud", "Container", "IoT"]
        frameworks_list = ["NIST CSF 2.0", "CIS Controls", "CISA KEV"]
        guardrail_info = {
            "hitl_level": "HITL Gate Active",
            "hitl_desc": "P1 Vulnerabilities require manual validation.",
            "safety_rule": "Patching requires staging verification before deployment."
        }
        
        df_preview = datasets.get("asset_inventory")

        data_source, filters, selected_fws, custom_scenario = render_3col_input_panel(
            use_case="ctem",
            stage_key="scoping",
            default_categories=default_categories,
            frameworks_list=frameworks_list,
            guardrail_info=guardrail_info,
            df_preview=df_preview
        )
        st.session_state[data_source_key] = data_source
        
        # Execute button and agent output
        render_agent_details_bar("ctem", "scoping")
        execute_clicked = render_execute_button("ctem", "scoping", data_source)
        if execute_clicked:
            render_progress_indicator("Scoping Boundary Mapping Initiated...", 10)
            time.sleep(0.3)
            render_progress_indicator("Ingesting corporate CIDRs & Active Directory profiles...", 40)
            time.sleep(0.4)
            render_progress_indicator("Scanning for Shadow IT resources...", 75)
            time.sleep(0.3)
            
            outcome = agent_manager.run_stage("ctem", "scoping", datasets, data_source)
            st.session_state.ctem_stage_outputs["scoping"] = outcome
            
            if 0 not in completed_stages:
                st.session_state.ctem_completed_stages.append(0)
            st.rerun()
            
        if "scoping" in st.session_state.ctem_stage_outputs:
            outcome = st.session_state.ctem_stage_outputs["scoping"]
            
            col_results, col_side = st.columns([7, 3])
            with col_results:
                render_ai_results(outcome, data_source, use_case="ctem", stage=stage_key)
                
                # Plotly Class distribution
                st.markdown("#### Scoped Assets Breakdown")
                asset_df = datasets.get("asset_inventory")
                if asset_df is not None:
                    counts = asset_df["asset_class"].value_counts()
                    fig = create_bar_chart(counts.index.tolist(), counts.values.tolist(), "Scoped Assets by Class", accent)
                    st.plotly_chart(fig, use_container_width=True)
            
            with col_side:
                st.markdown("#### Scoping Boundaries")
                st.markdown(textwrap.dedent(f"""\
                    <div class="glass-card" style="padding: 16px; border: 1px solid {BORDER_GLASS}; border-radius: 12px; background: rgba(255, 255, 255, 0.02); margin-bottom: 12px;">
                        <span style="color: {accent}; font-weight: bold; font-size: 0.85rem;">[Active Surface Boundary]</span><br/><br/>
                        Total Scoped Assets: <strong>2,000</strong><br/>
                        Internet Exposed: <strong style="color: #ff4444;">128</strong><br/>
                        Shadow IT Assets Discovered: <strong style="color: #ffaa00;">14</strong><br/>
                        Business-Critical Heatmap Nodes: <strong>85</strong>
                    </div>"""),
                    unsafe_allow_html=True)
                st.success("Guardrail validation passed. Shadow IT flagged for validation.")
                
    elif stage_key == "discovery":
        default_categories = ["Server", "Workstation", "Network", "Cloud", "Container", "IoT"]
        frameworks_list = ["NIST CSF 2.0", "CIS Controls", "CISA KEV"]
        guardrail_info = {
            "hitl_level": "HITL Gate Active",
            "hitl_desc": "P1 Vulnerabilities require manual validation.",
            "safety_rule": "Patching requires staging verification before deployment."
        }
        
        df_preview = datasets.get("vulnerability_findings")

        data_source, filters, selected_fws, custom_scenario = render_3col_input_panel(
            use_case="ctem",
            stage_key="discovery",
            default_categories=default_categories,
            frameworks_list=frameworks_list,
            guardrail_info=guardrail_info,
            df_preview=df_preview
        )
        st.session_state[data_source_key] = data_source
        
        # Execute button and agent output
        render_agent_details_bar("ctem", "discovery")
        execute_clicked = render_execute_button("ctem", "discovery", data_source, disabled=(0 not in completed_stages))
        if execute_clicked:
            render_progress_indicator("Ingesting Tenable, Wiz, and Prisma cloud configs...", 20)
            time.sleep(0.4)
            render_progress_indicator("Correlating CVE logs against CISA KEV and EPSS indices...", 60)
            time.sleep(0.5)
            render_progress_indicator("Generating Exposure Profile...", 90)
            time.sleep(0.3)
            
            outcome = agent_manager.run_stage("ctem", "discovery", datasets, data_source)
            st.session_state.ctem_stage_outputs["discovery"] = outcome
            
            if 1 not in completed_stages:
                st.session_state.ctem_completed_stages.append(1)
            st.rerun()
            
        if "discovery" in st.session_state.ctem_stage_outputs:
            outcome = st.session_state.ctem_stage_outputs["discovery"]
            
            col_results, col_side = st.columns([7, 3])
            with col_results:
                render_ai_results(outcome, data_source, use_case="ctem", stage=stage_key)

                # 🧩 Attack Path Analysis — frontier AI reasoning demo moment
                attack_chains = outcome.get("attack_chains", [])
                if attack_chains:
                    st.markdown("#### 🧩 Attack Path Analysis")
                    st.markdown(render_attack_chain_diagram(attack_chains, accent), unsafe_allow_html=True)

                # Show top findings
                st.markdown("#### Discovered Vulnerability Grid")
                vuln_findings = datasets.get("vulnerability_findings")
                if vuln_findings is not None:
                    st.dataframe(
                        vuln_findings[["vuln_id", "asset_id", "cve_id", "cvss_score", "cisa_kev", "epss_score", "status"]].head(8),
                        hide_index=True,
                        use_container_width=True
                    )
            
            with col_side:
                st.markdown("#### Discovery Scans")
                st.markdown(textwrap.dedent(f"""\
                    <div class="glass-card" style="padding: 16px; border: 1px solid {BORDER_GLASS}; border-radius: 12px; background: rgba(255, 255, 255, 0.02); margin-bottom: 12px;">
                        <strong>Vulnerabilities Found: 5,000</strong><br/><br/>
                        Critical Severity: <span style="color: #ff2222;">24</span><br/>
                        High Severity: <span style="color: #ff8844;">180</span><br/>
                        KEV Collisions: <strong>8%</strong><br/>
                        Avg EPSS Score: <strong>0.38</strong>
                    </div>"""),
                    unsafe_allow_html=True)
                st.success("Guardrail Checks: PII Scans completed cleanly.")
                
    elif stage_key == "prioritisation":
        default_categories = ["Server", "Workstation", "Network", "Cloud", "Container", "IoT"]
        frameworks_list = ["NIST CSF 2.0", "CIS Controls", "CISA KEV"]
        guardrail_info = {
            "hitl_level": "HITL Gate Active",
            "hitl_desc": "P1 Vulnerabilities require manual validation.",
            "safety_rule": "Patching requires staging verification before deployment."
        }
        
        df_preview = datasets.get("remediation_backlog")

        data_source, filters, selected_fws, custom_scenario = render_3col_input_panel(
            use_case="ctem",
            stage_key="prioritisation",
            default_categories=default_categories,
            frameworks_list=frameworks_list,
            guardrail_info=guardrail_info,
            df_preview=df_preview
        )
        st.session_state[data_source_key] = data_source
        
        # Execute button and agent output
        render_agent_details_bar("ctem", "prioritisation")
        execute_clicked = render_execute_button("ctem", "prioritisation", data_source, disabled=(1 not in completed_stages))
        if execute_clicked:
            render_progress_indicator("Gathering business-critical asset vectors...", 20)
            time.sleep(0.3)
            render_progress_indicator("Applying weighted risk engine to findings backlog...", 55)
            time.sleep(0.4)
            render_progress_indicator("Running prioritized exposure synthesis...", 85)
            time.sleep(0.3)
            
            outcome = agent_manager.run_stage("ctem", "prioritisation", datasets, data_source)
            st.session_state.ctem_stage_outputs["prioritisation"] = outcome
            
            if 2 not in completed_stages:
                st.session_state.ctem_completed_stages.append(2)
            st.rerun()
            
        if "prioritisation" in st.session_state.ctem_stage_outputs:
            outcome = st.session_state.ctem_stage_outputs["prioritisation"]
            
            col_results, col_side = st.columns([7, 3])
            with col_results:
                render_ai_results(outcome, data_source, use_case="ctem", stage=stage_key)

                # 🔗 Vulnerability Chaining — frontier AI reasoning demo moment
                attack_chains = outcome.get("attack_chains", [])
                if attack_chains:
                    st.markdown("#### 🔗 Vulnerability Chaining")
                    st.markdown(render_attack_chain_diagram(attack_chains, accent), unsafe_allow_html=True)

                # 💥 Key Demo Moment Banner 💥
                st.markdown(textwrap.dedent(f"""\
                    <div class="glass-card" style="border-left: 4px solid #ffaa00; background: rgba(255,170,0,0.06); border-top: 1px solid {BORDER_GLASS}; border-right: 1px solid {BORDER_GLASS}; border-bottom: 1px solid {BORDER_GLASS}; border-radius: 8px; padding: 16px; margin: 16px 0;">
                        <strong style="color: #ffaa00; font-size: 0.95rem;">💥 KEY DEMO MOMENT: CONTEXTUAL PRIORITISATION</strong><br/><br/>
                        <p style="font-size: 0.85rem; color: #e8e8e8; margin-top: 4px;">
                            Notice that <strong>CVE-2023-44487</strong> (a CVSS 7.5 KEV exploit on an internet-exposed web application server) 
                            is ranked <strong>P1 (Critical Impact)</strong>. <br/><br/>
                            Meanwhile, <strong>CVE-2024-1182</strong> (a CVSS 9.8 vulnerability on an isolated dev environment server) 
                            is safely deprioritised to <strong>P3 (Low Impact)</strong>.
                        </p>
                    </div>"""),
                    unsafe_allow_html=True)
            
            with col_side:
                st.markdown("#### Risk Prioritisation Backlog")
                st.markdown(textwrap.dedent(f"""\
                    <div class="glass-card" style="padding: 16px; border: 1px solid {BORDER_GLASS}; border-radius: 12px; background: rgba(255, 255, 255, 0.02); margin-bottom: 12px;">
                        <strong>Prioritised Backlog Summary</strong><br/><br/>
                        🔴 <strong style="color: #ff4444;">P1 (Critical):</strong> 14 Items<br/>
                        🟡 <strong style="color: #ffaa00;">P2 (High):</strong> 82 Items<br/>
                        🔵 <strong style="color: {accent};">P3 (Medium/Low):</strong> 904 Items<br/><br/>
                        SLA Breach Risk: <span style="color: #00ff88; font-weight: bold;">4.2%</span>
                    </div>"""),
                    unsafe_allow_html=True)
                st.success("Prioritisation Model: Validated with Pydantic schemas.")
                
    elif stage_key == "validation":
        default_categories = ["Server", "Workstation", "Network", "Cloud", "Container", "IoT"]
        frameworks_list = ["NIST CSF 2.0", "CIS Controls", "CISA KEV"]
        guardrail_info = {
            "hitl_level": "HITL Gate Active",
            "hitl_desc": "P1 Vulnerabilities require manual validation.",
            "safety_rule": "Patching requires staging verification before deployment."
        }
        
        df_preview = datasets.get("validation_results")

        data_source, filters, selected_fws, custom_scenario = render_3col_input_panel(
            use_case="ctem",
            stage_key="validation",
            default_categories=default_categories,
            frameworks_list=frameworks_list,
            guardrail_info=guardrail_info,
            df_preview=df_preview
        )
        st.session_state[data_source_key] = data_source
        
        # Execute button and agent output
        render_agent_details_bar("ctem", "validation")
        execute_clicked = render_execute_button("ctem", "validation", data_source, disabled=(2 not in completed_stages))
        if execute_clicked:
            render_progress_indicator("Checking network reachability profiles across Firewalls...", 25)
            time.sleep(0.4)
            render_progress_indicator("Running compensating control validation graphs...", 60)
            time.sleep(0.3)
            render_progress_indicator("Filtering false positives...", 85)
            time.sleep(0.4)
            
            outcome = agent_manager.run_stage("ctem", "validation", datasets, data_source)
            st.session_state.ctem_stage_outputs["validation"] = outcome
            
            if 3 not in completed_stages:
                st.session_state.ctem_completed_stages.append(3)
            st.rerun()
            
        if "validation" in st.session_state.ctem_stage_outputs:
            outcome = st.session_state.ctem_stage_outputs["validation"]
            
            col_results, col_side = st.columns([5.5, 4.5])
            with col_results:
                render_ai_results(outcome, data_source, use_case="ctem", stage=stage_key)
                
                # Show FP log
                st.markdown("#### Reachability Analysis & False Positive Filter Log")
                st.markdown(textwrap.dedent(f"""\
                    <div class="glass-card" style="padding: 16px; border-left: 3px solid {accent}; border-top: 1px solid {BORDER_GLASS}; border-right: 1px solid {BORDER_GLASS}; border-bottom: 1px solid {BORDER_GLASS}; border-radius: 8px; font-family: monospace; font-size: 0.8rem; background: rgba(0,0,0,0.15);">
                        [FP-LOG-01] CVE-2024-3094 on db-stg-02 filtered. Reachability: PORT 5432 blocked by firewall. Status: BENIGN.<br/><br/>
                        [FP-LOG-02] CVE-2023-38545 on client-host-89 filtered. Reachability: Host isolated by EDR agent. Status: SHIELDED.<br/><br/>
                        [VAL-LOG-01] CVE-2023-44487 on web-prod-01 CONFIRMED. Reachability: Port 443 internet-exposed. Status: EXPLOITABLE.
                    </div>"""),
                    unsafe_allow_html=True)
            
            with col_side:
                st.markdown("#### Analyst Review (HITL)")
                findings_to_approve = [
                    {"id": "CVE-2023-44487", "title": "CVE-2023-44487 on web-prod-01 (HTTP/2 Rapid Reset)", "severity": "CRITICAL", "confidence": 98},
                    {"id": "CVE-2024-3094", "title": "CVE-2024-3094 on web-prod-02 (XZ Utils Backdoor)", "severity": "CRITICAL", "confidence": 96},
                    {"id": "CVE-2023-38545", "title": "CVE-2023-38545 on web-prod-05 (cURL SOCKS5 vulnerability)", "severity": "HIGH", "confidence": 88}
                ]
                
                # HITL Gate
                gate_result = render_hitl_gate("ctem", "validation", findings_to_approve)
                if gate_result == "approve":
                    st.session_state.ctem_hitl_approved["validation"] = True
                    st.success("✅ Validation results approved! Mobilisation stage unlocked.")
                elif gate_result == "reject":
                    st.session_state.ctem_hitl_approved["validation"] = False
                    st.warning("❌ Validation results rejected for further review.")
                    
    elif stage_key == "mobilisation":
        default_categories = ["Server", "Workstation", "Network", "Cloud", "Container", "IoT"]
        frameworks_list = ["NIST CSF 2.0", "CIS Controls", "CISA KEV"]
        guardrail_info = {
            "hitl_level": "HITL Gate Active",
            "hitl_desc": "P1 Vulnerabilities require manual validation.",
            "safety_rule": "Patching requires staging verification before deployment."
        }
        
        df_preview = datasets.get("remediation_backlog")

        data_source, filters, selected_fws, custom_scenario = render_3col_input_panel(
            use_case="ctem",
            stage_key="mobilisation",
            default_categories=default_categories,
            frameworks_list=frameworks_list,
            guardrail_info=guardrail_info,
            df_preview=df_preview
        )
        st.session_state[data_source_key] = data_source
        
        # Additional action selector inside page layout below 3-col panel
        st.selectbox("Default Remediation Path", ["Path A (Workflow Ticketing Queue)", "Path B (AI Auto-Remediation)"], key="ctem_mob_path")
        
        # Execute button and agent output
        render_agent_details_bar("ctem", "mobilisation")
        execute_clicked = render_execute_button("ctem", "mobilisation", data_source, disabled=(3 not in completed_stages))
        if execute_clicked:
            render_progress_indicator("Compiling remediation actions and CLI commands...", 30)
            time.sleep(0.4)
            render_progress_indicator("Syncing ticket specs for Jira & ServiceNow...", 70)
            time.sleep(0.3)
            render_progress_indicator("Creating workflow approval queues...", 95)
            time.sleep(0.3)
            
            rem_engine = RemediationWorkflowEngine()
            findings_list = [
                {"title": "Remediate CVE-2023-44487 on web-prod-01", "severity": "Critical", "id": "CVE-2023-44487"},
                {"title": "Remediate CVE-2024-3094 on web-prod-02", "severity": "Critical", "id": "CVE-2024-3094"},
                {"title": "Remediate CVE-2023-38545 on web-prod-05", "severity": "High", "id": "CVE-2023-38545"},
                {"title": "Apply Config Fix: Disable SSH on db-prod-07", "severity": "High", "id": "SSH-CFG"},
                {"title": "Patch OpenSSL on app-stg-03 to openssl=3.0.14", "severity": "Medium", "id": "CVE-2024-400"}
            ]
            outcome = rem_engine.generate_mock_remediation("ctem", findings_list)
            st.session_state.ctem_stage_outputs["mobilisation"] = outcome
            
            # Set up st.session_state items for workflow queue rendering
            rem_engine.create_workflow_items(findings_list)
            
            if 4 not in completed_stages:
                st.session_state.ctem_completed_stages.append(4)
            st.rerun()
            
        if "mobilisation" in st.session_state.ctem_stage_outputs:
            outcome = st.session_state.ctem_stage_outputs["mobilisation"]
            chosen_path = st.session_state.get("ctem_mob_path", "Path A (Workflow Ticketing Queue)")
            
            col_results, col_side = st.columns([6.5, 3.5])
            with col_results:
                rem_engine = RemediationWorkflowEngine()
                if "Path A" in chosen_path:
                    st.markdown("#### Path A: Workflow Approval Queue & Tracking")
                    sub_tabs = st.tabs(["📋 Approval Queue", "📊 Kanban Board", "📈 Metrics"])
                    with sub_tabs[0]:
                        items = [WorkflowItem.model_validate(it) if isinstance(it, dict) else it for it in st.session_state.workflow_items]
                        rem_engine.render_approval_queue(items)
                    with sub_tabs[1]:
                        items = [WorkflowItem.model_validate(it) if isinstance(it, dict) else it for it in st.session_state.workflow_items]
                        rem_engine.render_implementation_tracking(items)
                    with sub_tabs[2]:
                        items = [WorkflowItem.model_validate(it) if isinstance(it, dict) else it for it in st.session_state.workflow_items]
                        rem_engine.render_analytics(items)
                else:
                    st.markdown("#### Path B: AI Auto-Remediation Engine")
                    rem_engine.render_pre_action_assessment(outcome)
                    
            with col_side:
                st.markdown("#### Integration Status")
                st.markdown(textwrap.dedent(f"""\
                    <div class="glass-card" style="padding: 16px; border: 1px solid {BORDER_GLASS}; border-radius: 12px; background: rgba(255, 255, 255, 0.02); margin-bottom: 12px;">
                        Jira API Status: <span style="color: #00ff88; font-weight: bold;">Connected (Mock)</span><br/>
                        ServiceNow Connection: <span style="color: #00ff88; font-weight: bold;">Online (Mock)</span><br/>
                        Remediation Actions Created: <strong>5</strong><br/>
                        Tickets Generated: <strong>5</strong>
                    </div>"""),
                    unsafe_allow_html=True)
                st.success("Sync completed! Audit log stashed in data/audit_log.db.")
