"""
AI Capability Demo — Exposure Remediation Page
Same look and feel as CTEM: a 3-column input panel (ingestion, frameworks & constraints, guardrails),
one Execute button, and the result in three tabs that together cover all ten steps:

  Tab 1  AI Analysis                            steps 1-3  (signal, correlation, priority)
  Tab 2  Remediation Plan, Approval & Execution steps 4-7  (options, change package, approval, execution)
  Tab 3  Verification, Closure & Dashboard      steps 8-10 (rescan, closure evidence, dashboard update)

Success is exposure reduced, not ticket closed. There is no phase hand-off: this is a single run.
"""

import hashlib
import html
import inspect
import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import pandas as pd
import streamlit as st

from app.data.live_intel import enrich_threat
from app.exposure_remediation import reference
from app.exposure_remediation.scenarios import (
    SCENARIO_ORDER,
    build_followup_scenario,
    get_scenario,
    get_scenarios,
    raw_scanner_payload,
    with_live_threat,
)
from app.exposure_remediation.simulator import ITSM_STATES, SimulatedEnvironment, residual_exposure
from app.runtime.agent_manager import AgentManager
from app.ui.components.charts import render_attack_chain_diagram
from app.ui.components.interactive_demo import render_execute_button, render_progress_indicator
from app.ui.components.lifecycle_stage import render_agent_details_bar, render_usecase_overview_card
from app.ui.theme import (
    ACCENT_AMBER,
    ACCENT_BLUE,
    ACCENT_GREEN,
    ACCENT_PURPLE,
    ACCENT_RED,
    BORDER_GLASS,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    clean_html,
    render_badge,
)

ACCENT = ACCENT_PURPLE
TAB_ANALYSIS = "🧠 AI Analysis"
TAB_PLAN = "🛠️ Remediation Plan, Approval & Execution"
TAB_VERIFY = "🔁 Verification, Closure & Dashboard"
_TAB_KEY = "rem_tabs"
# Newer Streamlit can select a tab from code (st.tabs(key=...)); older versions cannot, so fall back to a hint.
_TABS_STATEFUL = "key" in inspect.signature(st.tabs).parameters

_TYPE_COLOUR = {"patch": ACCENT_GREEN, "config": ACCENT_BLUE, "compensating_control": ACCENT_AMBER, "exception": ACCENT_RED}
_TYPE_LABEL = {"patch": "Patch / upgrade", "config": "Configuration", "compensating_control": "Compensating control", "exception": "Risk exception"}
_OUTCOME_STYLE = {
    "remediated": (ACCENT_GREEN, "Exposure reduced and verified"),
    "mitigated": (ACCENT_AMBER, "Exposure reduced, residual risk tracked"),
    "vulnerable": (ACCENT_RED, "Closure blocked: the exposure is still there"),
}
_SELECT = "Select a basis..."
APPROVE_BASES = [
    "Backup and rollback verified with the service owner",
    "Emergency change justified: KEV-listed and internet-exposed",
    "Change window confirmed with the service owner",
    "Compensating control is non-disruptive and reversible",
]
REJECT_BASES = [
    "Defer: business-critical event this week",
    "Insufficient testing evidence for this change",
    "Prefer a different remediation option",
    "Service owner unavailable to confirm the window",
]
_REMEDIATION_TOOLS = ["jira", "servicenow", "ansible_aap", "aws_ssm"]


# ── small HTML helpers ───────────────────────────────────────────────────────

def _e(value: Any) -> str:
    return html.escape(str(value))


def _md(markup: str) -> None:
    st.markdown(clean_html(markup), unsafe_allow_html=True)


def _pill(text: str, colour: str) -> str:
    return (f'<span style="display:inline-block; padding:2px 10px; border-radius:10px; font-size:0.7rem; font-weight:700; '
            f'background:{colour}22; color:{colour}; border:1px solid {colour}55; margin-right:6px;">{_e(text)}</span>')


def _card(inner: str, colour: str = BORDER_GLASS, left: bool = False) -> str:
    border = f"border-left: 3px solid {colour};" if left else ""
    return (f'<div style="padding:14px 16px; border:1px solid {BORDER_GLASS}; {border} border-radius:10px; '
            f'background: rgba(255,255,255,0.02); margin-bottom:12px; font-size:0.85rem; color:{TEXT_SECONDARY}; line-height:1.55;">{inner}</div>')


def _label(text: str) -> str:
    return f'<div style="font-size:0.68rem; font-weight:700; letter-spacing:0.08em; text-transform:uppercase; color:{TEXT_MUTED}; margin-bottom:4px;">{_e(text)}</div>'


def _fmt_ts(iso: str) -> str:
    return iso.replace("T", " ").replace("Z", " UTC")


def _bar(value: float, max_value: float, colour: str) -> str:
    pct = max(0.0, min(100.0, value / max_value * 100.0))
    return (f'<div style="width:100%; height:6px; background:rgba(0,0,0,0.3); border-radius:3px; overflow:hidden;">'
            f'<div style="width:{pct:.0f}%; height:100%; background:{colour};"></div></div>')


def _link(url: str, text: str) -> str:
    safe = html.escape(url, quote=True)
    return f'<a href="{safe}" target="_blank" rel="noopener noreferrer" style="color:{ACCENT_BLUE};">{_e(text)}</a>'


def _heading(text: str) -> None:
    st.markdown(f"### {text}")


# ── session state ────────────────────────────────────────────────────────────

def _init_state() -> None:
    st.session_state.setdefault("remediation_run", None)
    st.session_state.setdefault("remediation_runs", [])


def _kpi_snapshot(kpi_engine: Any) -> Dict[str, float]:
    names = ("Verified Closure Rate", "Closed Without Reduction", "Exposure Reduction", "Remediation MTTR")
    snap = {n: float(kpi_engine.get_kpi(n)) for n in names}
    snap["Remediation score"] = float(kpi_engine.get_use_case_score("remediation"))
    snap["AI Readiness Index"] = float(kpi_engine.get_ai_readiness_index())
    return snap


def _new_cycle(agent_manager: AgentManager, datasets: Dict[str, pd.DataFrame], env: SimulatedEnvironment,
               scenario: Dict[str, Any], index: int) -> Dict[str, Any]:
    plan = agent_manager.run_stage("remediation", "plan", datasets, "synthetic", scenario=scenario)
    sim_change = scenario["sim"]["change"]
    pkg = plan["change_package"]
    env.open_change(sim_change, pkg, "Remediation Planner (AI)")
    env.transition(sim_change["change_id"], "Assess", "Remediation Planner (AI)", "Risk assessment and evidence attached to the change record")
    return {
        "index": index, "scenario": scenario, "plan": plan, "change_id": sim_change["change_id"],
        "rescan_before": env.rescan(deep=index > 0), "approval": None, "exception": None, "execution": None,
        "rescan_after": None, "revalidation": None, "closure": None, "exposure_before": plan["priority"]["contextual_score"],
        "exposure_after": None, "recorded": False,
    }


# ── input panel (same look as the CTEM 3-column panel) ───────────────────────

def _input_panel(datasets: Dict[str, pd.DataFrame]) -> Dict[str, Any]:
    scenarios = get_scenarios()
    catalog = {f["id"]: f for f in reference.framework_catalog()}
    constraint_labels = {c["id"]: c["label"] for c in reference.constraint_catalog()}

    with st.container(border=True):
        st.markdown('<div class="glass-card-anchor"></div>', unsafe_allow_html=True)
        c1, c2, c3 = st.columns(3)

        with c1:
            st.markdown(f'<div style="font-size:0.95rem; font-weight:700; color:{ACCENT}; margin-bottom:12px;">📥 Column 1: Exposure & Ingestion</div>', unsafe_allow_html=True)
            key = st.radio("Exposure to remediate", SCENARIO_ORDER, format_func=lambda k: scenarios[k]["label"], key="rem_scenario_radio")
            sc = scenarios[key]
            df = datasets.get("exposure_signals")
            rows, cols = (len(df), len(df.columns)) if df is not None else (0, 0)
            schema = ", ".join(list(df.columns)[:8]) + ("..." if df is not None and len(df.columns) > 8 else "") if df is not None else ""
            _md(f'<div style="background:rgba(255,255,255,0.02); border:1px solid {BORDER_GLASS}; border-left:3px solid {ACCENT}; border-radius:8px; padding:12px 14px; margin-bottom:12px; line-height:1.4;">'
                f'<div style="font-size:0.72rem; text-transform:uppercase; letter-spacing:0.05em; color:{ACCENT}; font-weight:bold; margin-bottom:4px;">📁 Target Ingested Dataset</div>'
                f'<div style="font-size:0.9rem; font-weight:bold; color:#ffffff; margin-bottom:6px;">Exposure Signals (scanner findings with threat context)</div>'
                f'<div style="font-size:0.78rem; color:{TEXT_SECONDARY}; margin-bottom:8px;">{_e(sc["tagline"])}</div>'
                f'<div style="display:flex; gap:12px; font-size:0.75rem; color:#e2e8f0; font-family:\'JetBrains Mono\', monospace; background:rgba(255,255,255,0.03); padding:6px 8px; border-radius:4px; margin-bottom:8px;">'
                f'<span>📊 {rows:,} rows</span><span>🎛️ {cols} columns</span></div>'
                f'<div style="font-size:0.72rem; color:#8a8aae; word-break:break-all;"><strong>Schema:</strong> {_e(schema)}</div></div>')
            if df is not None and not df.empty:
                with st.expander(f"🔍 Preview Received Input ({rows:,} rows)"):
                    st.dataframe(df, use_container_width=True, hide_index=True)
            provider = st.radio("Data Source Provider", ["API/MCP Live Tools (Priority 1)", "File Upload Ingestion (Priority 2)", "Synthetic Data Engine (Priority 3)"],
                                index=2, key="rem_source_sel")
            data_source = "mcp" if "API/MCP" in provider else ("upload" if "File Upload" in provider else "synthetic")
            if data_source == "mcp":
                from app.mcp.client import MCPClient
                mcp = MCPClient()
                st.markdown(f'<div style="font-size:0.75rem; color:{TEXT_SECONDARY}; margin-top:8px; margin-bottom:4px;">MCP / API Connection Status (execution tools)</div>', unsafe_allow_html=True)
                chip_cols = st.columns(2)
                for i, tool_id in enumerate(_REMEDIATION_TOOLS):
                    live = mcp.get_connection_status(tool_id).get("live", False)
                    meta = mcp.registry.get_tool(tool_id)
                    colour = ACCENT_GREEN if live else ACCENT_AMBER
                    chip_cols[i % 2].markdown(
                        f'<div style="background:{colour}14; border:1px solid {colour}33; border-radius:6px; padding:3px 6px; margin-bottom:4px; font-size:0.68rem; color:{colour}; font-weight:bold; display:flex; justify-content:space-between;">'
                        f'<span>🔌 {_e(meta.display_name if meta else tool_id)}</span><span style="font-size:0.58rem;">{"🟢 Live" if live else "🟠 Mock"}</span></div>',
                        unsafe_allow_html=True)
            if data_source != "synthetic":
                st.info("Execution and rescan run against the simulated customer environment in this demo, so the curated synthetic exposure is used.")
            live_intel = st.toggle("Enrich with live CISA KEV + FIRST EPSS", value=True, key="rem_live_intel",
                                   help="Falls back to a saved snapshot of the real KEV entries if the feeds are unreachable.")

        with c2:
            st.markdown(f'<div style="font-size:0.95rem; font-weight:700; color:{ACCENT}; margin-bottom:12px;">🛡️ Column 2: Frameworks & Constraints</div>', unsafe_allow_html=True)
            defaults = reference.default_framework_ids(sc)
            fw_ids = st.multiselect("Regulations, standards & references", list(catalog), default=defaults,
                                    format_func=lambda i: catalog[i]["name"], key=f"rem_fw_{key}",
                                    help="Defaults are the frameworks that apply to this service. Obligations come from regulations.yaml.")
            if fw_ids:
                variants = {"regulation": "red", "standard": "blue"}
                _md('<div style="margin:8px 0 12px 0; display:flex; flex-wrap:wrap; gap:6px;">' + "".join(
                    render_badge(catalog[i]["name"], variants.get(catalog[i]["kind"], "blue")) for i in fw_ids) + "</div>")
            con_ids = st.multiselect("Operational constraints", list(constraint_labels), default=sc["default_constraints"],
                                     format_func=lambda i: constraint_labels[i], key=f"rem_con_{key}",
                                     help="Constraints inform the AI and flag conflicts on the options. They do not change the recommended plan.")
            st.caption("Always shown as authoritative reference data: CISA KEV record, MITRE ATT&CK techniques and FIRST EPSS.")

        with c3:
            st.markdown(f'<div style="font-size:0.95rem; font-weight:700; color:{ACCENT}; margin-bottom:12px;">👁️ Column 3: Active Guardrails</div>', unsafe_allow_html=True)
            shield = lambda text, colour: (f'<span style="display:inline-block; padding:2px 8px; border-radius:10px; font-size:0.68rem; font-weight:bold; '
                                           f'background:{colour}1f; color:{colour}; border:1px solid {colour}4d;">{text}</span>')
            _md(f'<div style="background:rgba(255,255,255,0.02); border:1px solid {BORDER_GLASS}; border-radius:12px; padding:14px 18px; min-height:250px;">'
                f'<div style="font-size:0.72rem; text-transform:uppercase; letter-spacing:0.05em; color:{TEXT_MUTED}; font-weight:bold; margin-bottom:10px;">Active Security Shields</div>'
                f'<div style="margin-bottom:8px;">{shield("🟢 Pydantic v2 Schema", ACCENT_GREEN)}<div style="font-size:0.68rem; color:{TEXT_SECONDARY}; margin:2px 0 0 6px;">Strictly structured agent output; facts are fixed ground truth.</div></div>'
                f'<div style="margin-bottom:8px;">{shield("🟢 OpenAI Moderation API", ACCENT_GREEN)}<div style="font-size:0.68rem; color:{TEXT_SECONDARY}; margin:2px 0 0 6px;">Filters prompt injection and malicious payloads.</div></div>'
                f'<div style="margin-bottom:10px;">{shield("🟢 HITL: approval always required", ACCENT_AMBER)}<div style="font-size:0.68rem; color:{TEXT_SECONDARY}; margin:2px 0 0 6px;">No change executes until a human approves it.</div></div>'
                f'<div style="background:rgba(255,107,53,0.05); border:1px solid rgba(255,107,53,0.2); border-radius:6px; padding:8px; font-size:0.68rem; color:#ff6b35;">'
                f'<strong>🛡️ Safety Rule:</strong> Execution happens only in the customer\'s own tooling (simulated here); the platform orchestrates and verifies.</div></div>')

    return {"key": key, "data_source": data_source, "live_intel": live_intel, "frameworks": fw_ids, "constraints": con_ids}


# ── tab 1: AI analysis ───────────────────────────────────────────────────────

def _render_signal(scenario: Dict[str, Any]) -> None:
    sig, asset = scenario["signal"], scenario["asset"]
    _md(_card(
        f'<div style="display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px;">'
        f'<div style="color:{TEXT_PRIMARY}; font-weight:700; font-size:0.95rem;">{_e(sig["title"])}</div>'
        f'<div>{_pill(sig["scanner_severity"], ACCENT_RED)}{_pill("CVSS " + str(sig["cvss"]), ACCENT_AMBER)}</div></div>'
        f'<div style="font-family:\'JetBrains Mono\', monospace; font-size:0.78rem; margin:6px 0;">'
        f'{_e(sig["signal_id"])} &middot; {_e(sig["cve"])} &middot; {_e(asset["hostname"])} ({_e(asset["ip_address"])}) &middot; '
        f'{_e(sig["installed_version"])} &middot; {sig["protocol"]}/{sig["port"]}</div>'
        f'<div>Source: {_e(sig["source"])} &middot; Detected {_fmt_ts(sig["detected_at"])}</div>'
        f'<div style="margin-top:6px;">{_e(sig["evidence_output"])}</div>',
        ACCENT, left=True))
    with st.expander("View raw scanner payload (vendor-neutral JSON)"):
        st.json(raw_scanner_payload(scenario))


def _render_kev_card(threat: Dict[str, Any], cve: str) -> None:
    rec, src = threat.get("kev_record"), threat.get("kev_source") or {}
    if not rec:
        _md(_card(f'{_label("CISA KEV catalog")}{_pill("NOT LISTED", ACCENT_AMBER)} {_e(cve)} is not in the CISA Known Exploited Vulnerabilities catalog.'))
        return
    live = src.get("mode") == "live"
    badge = _pill("LIVE FEED", ACCENT_GREEN) if live else _pill("SAVED SNAPSHOT", ACCENT_AMBER)
    provenance = (f'CISA KEV catalog v{_e(src.get("catalog_version", ""))} &middot; {"fetched" if live else "snapshot as of"} {_e(src.get("as_of", ""))}')
    notes = [u for u in re.split(r"[;\s]+", str(rec.get("notes", ""))) if u.startswith("http")]
    note_links = " &middot; ".join(_link(u, u.split("//", 1)[1][:48]) for u in notes[:3])
    cwes = ", ".join(rec.get("cwes") or []) or "none listed"
    cells = [("CVE", rec.get("cveID", cve)), ("Vendor / product", f'{rec.get("vendorProject", "")} / {rec.get("product", "")}'),
             ("Date added", rec.get("dateAdded", "")), ("Due date", rec.get("dueDate", "")),
             ("Ransomware use", rec.get("knownRansomwareCampaignUse", "")), ("Forensic triage", rec.get("forensicTriage", "")), ("CWEs", cwes)]
    grid = "".join(f'<div><div style="font-size:0.65rem; color:{TEXT_MUTED}; text-transform:uppercase;">{_e(k)}</div>'
                   f'<div style="color:{TEXT_PRIMARY}; font-weight:600;">{_e(v)}</div></div>' for k, v in cells)
    _md(f'<div style="padding:16px 18px; border:1px solid {ACCENT_RED}66; border-left:4px solid {ACCENT_RED}; border-radius:10px; background:rgba(255,68,68,0.05); margin-bottom:12px; font-size:0.85rem; color:{TEXT_SECONDARY}; line-height:1.55;">'
        f'<div style="display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px; margin-bottom:8px;">'
        f'<div style="color:{ACCENT_RED}; font-weight:800; letter-spacing:0.04em;">🛡️ CISA KNOWN EXPLOITED VULNERABILITY (authoritative record)</div><div>{badge}</div></div>'
        f'<div style="color:{TEXT_PRIMARY}; font-weight:700; margin-bottom:8px;">{_e(rec.get("vulnerabilityName", ""))}</div>'
        f'<div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(150px, 1fr)); gap:10px; margin-bottom:10px;">{grid}</div>'
        f'<div><strong style="color:{TEXT_PRIMARY};">Required action:</strong> {_e(rec.get("requiredAction", ""))}</div>'
        f'<div style="margin-top:6px;">{_e(rec.get("shortDescription", ""))}</div>'
        f'<div style="margin-top:8px; font-size:0.75rem;">{provenance}' + (f' &middot; {note_links}' if note_links else "") + '</div></div>')


def _render_attack_cards(exposure_path: List[Dict[str, Any]]) -> None:
    cards = reference.attack_cards(exposure_path)
    if not cards:
        return
    meta = reference.attack_meta()
    items = ""
    for t in cards:
        tactics = "".join(_pill(x, ACCENT_PURPLE) for x in t["tactics"])
        items += (f'<div style="padding:12px 14px; border:1px solid {ACCENT_PURPLE}55; border-radius:10px; background:rgba(168,85,247,0.05); font-size:0.8rem; color:{TEXT_SECONDARY}; line-height:1.5;">'
                  f'<div style="margin-bottom:4px;">{_link(t["url"], t["id"])} {tactics}</div>'
                  f'<div style="color:{TEXT_PRIMARY}; font-weight:700; margin-bottom:4px;">{_e(t["name"])}</div>'
                  f'<div>{_e(t["description"])}</div></div>')
    _md(f'<div style="margin-bottom:6px;">{_label("MITRE ATT&CK techniques in this path (authoritative records)")}'
        f'{_pill("ATT&CK Enterprise v" + str(meta["version"]), ACCENT_PURPLE)}</div>'
        f'<div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(260px, 1fr)); gap:10px; margin-bottom:12px;">{items}</div>')


def _render_correlation(plan: Dict[str, Any], cve: str) -> None:
    corr = plan["correlation"]
    asset, svc, ident, threat = corr["asset"], corr["service"], corr["identity"], corr["threat"]
    status = threat.get("intel_status", "snapshot")
    intel = {"live": ("Live intel: CISA KEV + FIRST EPSS", ACCENT_GREEN), "partial": ("Partly live intel", ACCENT_AMBER)}.get(
        status, (f"Snapshot as of {threat.get('epss_as_of', '')}", TEXT_SECONDARY))
    _md(_card(f'{_label("AI correlation insight")}<div style="color:{TEXT_PRIMARY};">{_e(corr["insight"])}</div>', ACCENT, left=True))
    cols = st.columns(4)
    blocks = [
        ("Asset", [asset["hostname"], asset["os"], asset["location"], f'Owner: {asset["owner_team"]}',
                   "Internet exposed" if asset["internet_exposed"] else "Internal only", asset["exposure_via"]]),
        ("Business service", [svc["name"], f'{svc["tier"]} · RTO {svc["rto_hours"]}h', ", ".join(svc["regulatory_scope"]),
                              f'Data: {svc["data_classification"]}', svc["users"]]),
        ("Identity", [ident["account"], ident["type"], ident["privilege"], ident["credential_exposure"]]),
        ("Threat context", [("In CISA KEV since " + threat["kev_date_added"]) if threat["kev"] else "Not in CISA KEV",
                            f'Ransomware use: {threat["ransomware_use"]}', f'EPSS {threat["epss"]:.3f} ({threat["epss_percentile"] * 100:.1f}th pct)',
                            threat["exploit_maturity"], threat["attack_technique"]]),
    ]
    for col, (title, lines) in zip(cols, blocks):
        body = "".join(f'<div style="margin-bottom:3px;">{_e(line)}</div>' for line in lines)
        col.markdown(clean_html(_card(f'{_label(title)}{body}')), unsafe_allow_html=True)
    _md(f'<div style="margin:-4px 0 10px 0;">{_pill(intel[0], intel[1])}'
        f'{_pill("FIRST EPSS " + format(threat["epss"], ".3f") + " as of " + str(threat.get("epss_as_of", "")), ACCENT_BLUE)}</div>')
    _render_kev_card(threat, cve)
    st.markdown("**Exposure path** (how an attacker gets from the internet to business impact)")
    chain = [{"chain_id": corr["signal_id"], "severity": "Critical", "steps": corr["exposure_path"]}]
    _md(render_attack_chain_diagram(chain, ACCENT))
    _render_attack_cards(corr["exposure_path"])
    _md(_card(f'{_label("Blast radius")}' + "".join(f"<div>&bull; {_e(b)}</div>" for b in corr["blast_radius"])))


def _render_compliance(plan: Dict[str, Any], scenario: Dict[str, Any]) -> None:
    inputs = scenario.get("analyst_inputs") or {}
    fw_ids = inputs.get("frameworks") or reference.default_framework_ids(scenario)
    rows = reference.evaluate_controls(scenario, fw_ids)
    if plan.get("compliance_insight"):
        _md(_card(f'{_label("AI compliance insight")}<div style="color:{TEXT_PRIMARY};">{_e(plan["compliance_insight"])}</div>', ACCENT, left=True))
    if not rows:
        st.info("No frameworks selected in the input panel.")
        return
    body = ""
    current = None
    for r in rows:
        if r["framework"] != current:
            current = r["framework"]
            body += (f'<tr><td colspan="4" style="padding:10px 8px 4px 8px; font-size:0.72rem; letter-spacing:0.05em; text-transform:uppercase; color:{TEXT_SECONDARY}; font-weight:700;">'
                     f'{_e(current)} &middot; {_link(r["source"], "source")}</td></tr>')
        applies = r["status"] == "applies"
        chip = _pill("APPLIES", ACCENT_GREEN) if applies else _pill("NOT APPLICABLE", TEXT_MUTED)
        text = r["obligation"] if applies else f'<span style="color:{TEXT_MUTED};">{_e(r["reason"])}</span>'
        body += (f'<tr style="border-bottom:1px solid rgba(255,255,255,0.04);"><td style="padding:6px 8px; white-space:nowrap; color:{TEXT_PRIMARY};">{_e(r["control_id"])}</td>'
                 f'<td style="padding:6px 8px;">{chip}</td>'
                 f'<td style="padding:6px 8px;"><strong style="color:{TEXT_PRIMARY};">{_e(r["title"])}</strong><br/>{text if not applies else _e(text)}</td>'
                 f'<td style="padding:6px 8px; font-size:0.78rem;">{_e(r["evidence"]) if applies else ""}</td></tr>')
    _md(f'<div style="overflow-x:auto; border:1px solid {BORDER_GLASS}; border-radius:10px; padding:6px;"><table style="width:100%; border-collapse:collapse; font-size:0.82rem; color:{TEXT_SECONDARY}; text-align:left;">'
        f'<thead><tr style="color:{TEXT_MUTED}; font-size:0.7rem; text-transform:uppercase;"><th style="padding:6px 8px;">Control</th><th style="padding:6px 8px;">Status</th>'
        f'<th style="padding:6px 8px;">What it requires</th><th style="padding:6px 8px;">Evidence this run produces</th></tr></thead><tbody>{body}</tbody></table></div>')
    st.caption("Wording for CISA BOD 26-04 and NIST SP 800-40r4 was checked against the publishers' pages; PCI DSS, ISO 27001, SOX and ITIL entries are paraphrases to be confirmed by compliance before external use.")


def _render_priority(plan: Dict[str, Any]) -> None:
    pr = plan["priority"]
    colour = ACCENT_RED if pr["contextual_score"] >= 85 else ACCENT_AMBER
    _md(
        f'<div style="display:flex; flex-wrap:wrap; gap:12px; margin-bottom:12px;">'
        f'<div style="flex:1; min-width:150px; padding:14px; text-align:center; border:1px solid {BORDER_GLASS}; border-radius:10px;">'
        f'<div style="font-size:2rem; font-weight:800; color:{colour};">{pr["contextual_score"]}<span style="font-size:0.9rem;">/100</span></div>'
        f'<div style="font-size:0.72rem; color:{TEXT_MUTED}; text-transform:uppercase;">Contextual risk</div></div>'
        f'<div style="flex:1; min-width:150px; padding:14px; text-align:center; border:1px solid {BORDER_GLASS}; border-radius:10px;">'
        f'<div style="font-size:1.6rem; font-weight:800; color:{TEXT_PRIMARY};">{_e(pr["priority_label"])}</div>'
        f'<div style="font-size:0.72rem; color:{TEXT_MUTED}; text-transform:uppercase;">Fix within {pr["sla_hours"]}h</div></div>'
        f'<div style="flex:1; min-width:150px; padding:14px; text-align:center; border:1px solid {BORDER_GLASS}; border-radius:10px;">'
        f'<div style="font-size:1.6rem; font-weight:800; color:{TEXT_PRIMARY};">#{pr["cvss_rank"]} &rarr; #{pr["contextual_rank"]}</div>'
        f'<div style="font-size:0.72rem; color:{TEXT_MUTED}; text-transform:uppercase;">CVSS rank &rarr; contextual rank (of {pr["total"]})</div></div></div>')
    _md(_card(f'{_label("Why this matters here, not merely CVSS")}<div style="color:{TEXT_PRIMARY};">{_e(pr["rationale"])}</div>', ACCENT, left=True))
    left, right = st.columns(2)
    factor_rows = "".join(
        f'<div style="margin-bottom:9px;"><div style="display:flex; justify-content:space-between;"><span style="color:{TEXT_PRIMARY};">{_e(f["factor"])}</span>'
        f'<span style="color:{ACCENT_GREEN if f["impact"] >= 0 else ACCENT_AMBER}; font-weight:700;">{f["impact"]:+d}</span></div>'
        f'{_bar(abs(f["impact"]), 20, ACCENT)}<div style="font-size:0.75rem; color:{TEXT_MUTED};">{_e(f["evidence"])}</div></div>'
        for f in pr["factors"])
    left.markdown(clean_html(_card(f'{_label("Score factors (base = CVSS x 5)")}{factor_rows}')), unsafe_allow_html=True)
    peer_rows = ""
    for r in pr["ranked"]:
        mark = f' {_pill("this exposure", ACCENT)}' if r["self"] else ""
        peer_rows += (
            f'<div style="margin-bottom:9px;"><div style="display:flex; justify-content:space-between;"><span style="color:{TEXT_PRIMARY};">{_e(r["cve"])}{mark}</span>'
            f'<span style="font-weight:700; color:{TEXT_PRIMARY};">{r["contextual"]} &middot; {_e(r["label"][:2])}</span></div>'
            f'<div style="font-size:0.72rem; color:{TEXT_MUTED};">{_e(r["asset"])} &middot; CVSS {r["cvss"]}</div>'
            f'<div style="display:flex; gap:6px; align-items:center;"><span style="width:52px; font-size:0.65rem;">CVSS</span>{_bar(r["cvss"], 10, TEXT_MUTED)}</div>'
            f'<div style="display:flex; gap:6px; align-items:center;"><span style="width:52px; font-size:0.65rem;">Context</span>{_bar(r["contextual"], 100, ACCENT if r["self"] else ACCENT_AMBER)}</div>'
            f'<div style="font-size:0.75rem; color:{TEXT_MUTED};">{_e(r["note"]) if not r["self"] else ""}</div></div>')
    right.markdown(clean_html(_card(f'{_label("Against peer findings")}{peer_rows}')), unsafe_allow_html=True)


def _render_trace(plan: Dict[str, Any]) -> None:
    steps = "".join(f'<li style="margin-bottom:6px; color:{TEXT_SECONDARY};">{_e(s)}</li>' for s in plan.get("step_by_step_execution", []))
    _md(_card(f'{_label("Under the hood: agent execution trace")}<ol style="margin:0; padding-left:20px;">{steps}</ol>'))
    src = plan.get("narrative_source")
    note = ("Narrative written by the model from the ground-truth facts above." if src == "llm"
            else "Narrative from the deterministic fallback (no live model response was used).")
    _md(_card(f'<strong style="color:{TEXT_PRIMARY};">Overall AI confidence: {plan["ai_confidence"]}%</strong>. {note} '
              f'Scores, ranks, versions and windows are computed from fixed facts and never taken from the model.'))


def _tab_analysis(run: Dict[str, Any], cycle: Dict[str, Any]) -> None:
    scenario, plan = cycle["scenario"], cycle["plan"]
    _heading("1️⃣ Exposure Arrives")
    _render_signal(scenario)
    _heading("2️⃣ AI Correlates Vulnerability, Identity, Business Service and Threat Context")
    _render_correlation(plan, scenario["signal"]["cve"])
    _heading("📜 Regulatory & Reference Mapping")
    _render_compliance(plan, scenario)
    _heading("3️⃣ AI Explains Priority")
    _render_priority(plan)
    _heading("🧠 Agent Execution Trace & Confidence")
    _render_trace(plan)


# ── tab 2: plan, approval, execution ─────────────────────────────────────────

def _render_options(plan: Dict[str, Any]) -> None:
    cards = ""
    for opt in plan["remediation_options"]:
        rec = opt["id"] == plan["recommended_option"]
        colour = _TYPE_COLOUR.get(opt["type"], ACCENT_BLUE)
        flags = ""
        if opt.get("not_viable"):
            flags += f'<div style="color:{ACCENT_RED}; font-weight:700; margin-top:6px;">Not viable: {_e(opt["not_viable"])}</div>'
        elif opt.get("blocked_reason"):
            flags += f'<div style="color:{ACCENT_AMBER}; font-weight:700; margin-top:6px;">Blocked: {_e(opt["blocked_reason"])}</div>'
        if opt.get("constraint_conflicts"):
            flags += f'<div style="color:{ACCENT_AMBER}; margin-top:6px;">⚠️ Constraint conflict: {_e("; ".join(opt["constraint_conflicts"]))}</div>'
        badge = _pill("AI RECOMMENDED", ACCENT_GREEN) if rec else ""
        border = f"2px solid {ACCENT_GREEN}" if rec else f"1px solid {BORDER_GLASS}"
        cards += (
            f'<div style="padding:14px 16px; border:{border}; border-radius:10px; background:rgba(255,255,255,{0.05 if rec else 0.02}); font-size:0.82rem; color:{TEXT_SECONDARY};">'
            f'<div style="margin-bottom:6px;">{_pill(_TYPE_LABEL.get(opt["type"], opt["type"]), colour)}{badge}</div>'
            f'<div style="color:{TEXT_PRIMARY}; font-weight:700; margin-bottom:8px;">{_e(opt["title"])}</div>'
            f'<div style="display:flex; justify-content:space-between;"><span>Risk reduction</span><strong style="color:{TEXT_PRIMARY};">{opt["risk_reduction_pct"]}%</strong></div>'
            f'{_bar(opt["risk_reduction_pct"], 100, colour)}'
            f'<div style="margin-top:6px;">Change risk: <strong>{_e(opt["change_risk"])}</strong> &middot; Downtime: <strong>{_e(opt["downtime"])}</strong> &middot; Effort: {_e(opt["effort"])}</div>'
            f'<div style="margin-top:6px;">{_e(opt.get("ai_assessment", opt["tradeoff"]))}</div>{flags}</div>')
    _md(f'<div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(300px, 1fr)); gap:12px; margin-bottom:12px;">{cards}</div>')
    if plan.get("recommended_reason"):
        _md(_card(f'{_label("Why this path")}<div style="color:{TEXT_PRIMARY};">{_e(plan["recommended_reason"])}</div>', ACCENT_GREEN, left=True))


def _render_change_package(plan: Dict[str, Any], change_id: str) -> None:
    pkg = plan["change_package"]
    win = pkg["maintenance_window"]
    lists = lambda items: "".join(f"<div>&bull; {_e(i)}</div>" for i in items)
    header = (
        f'<div style="color:{TEXT_PRIMARY}; font-weight:700; font-size:0.95rem;">{_e(pkg["title"])}</div>'
        f'<div style="margin:6px 0;">{_pill(change_id, ACCENT)}{_pill(pkg["change_type"], ACCENT_AMBER)}{_pill("Owner: " + pkg["owner_team"], ACCENT_BLUE)}'
        f'{_pill("Approver: " + pkg["approver_role"], ACCENT_GREEN)}</div>'
        f'<div>Window: <strong>{_e(win["label"])}</strong> &middot; {_fmt_ts(win["start"])} to {_fmt_ts(win["end"])}</div>')
    _md(_card(header, ACCENT, left=True))
    left, right = st.columns(2)
    left.markdown(clean_html(_card(f'{_label("Risk assessment")}{_e(pkg["risk_assessment"])}<br/><br/>{_label("Evidence")}{lists(pkg["evidence"])}'
                                   f'<br/>{_label("Rollback plan")}{_e(pkg["rollback_plan"])}')), unsafe_allow_html=True)
    right.markdown(clean_html(_card(f'{_label("Proposed mitigation")}{lists(pkg["mitigation_steps"])}<br/>{_label("Validation criteria")}{lists(pkg["validation_criteria"])}')),
                   unsafe_allow_html=True)


def _approver_name() -> str:
    return st.session_state.get("username", "analyst")


def _log(action: str, status: str, target: str, details: str) -> None:
    try:
        from app.observability.audit_logger import AuditLogger
        AuditLogger().log_action(action=action, username=_approver_name(), status=status, target=target, details=details)
    except Exception as exc:  # audit failures must not break the demo
        st.warning(f"Audit log write failed: {exc}")


def _render_approval(run: Dict[str, Any], cycle: Dict[str, Any]) -> None:
    plan, env = cycle["plan"], run["env"]
    pkg = plan["change_package"]
    idx = cycle["index"]
    if cycle["approval"] is None:
        _md(_card(
            f'<div style="color:{ACCENT_AMBER}; font-weight:700; margin-bottom:6px;">Human approval required before anything is executed</div>'
            f'Approver role: <strong>{_e(pkg["approver_role"])}</strong> &middot; Change type: <strong>{_e(pkg["change_type"])}</strong> &middot; '
            f'Rollback: {_e(pkg["rollback_plan"])}', ACCENT_AMBER, left=True))
        c1, c2 = st.columns(2)
        with c1:
            approve_basis = st.selectbox("Basis for approval", [_SELECT] + APPROVE_BASES, key=f"rem_abasis_{idx}")
            approve = st.button("✅ Approve and schedule change", key=f"rem_approve_{idx}", type="primary", use_container_width=True)
        with c2:
            reject_basis = st.selectbox("Basis for rejection", [_SELECT] + REJECT_BASES, key=f"rem_rbasis_{idx}")
            reject = st.button("⛔ Reject and raise a risk-acceptance exception", key=f"rem_reject_{idx}", use_container_width=True)
        if approve or reject:
            basis = approve_basis if approve else reject_basis
            if basis == _SELECT:
                st.warning("Select a basis for your decision first.")
                return
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            decision = "approve" if approve else "reject"
            name = _approver_name()
            cycle["approval"] = {"decision": decision, "approver": f"{name} ({pkg['approver_role']})", "reason": basis, "at": now}
            try:
                from app.observability.health_metrics import InAppMetrics
                InAppMetrics().record_hitl_decision("remediation", "plan", decision, int(plan["ai_confidence"]))
            except Exception:
                pass
            _log("HITL Decision: Exposure Remediation", "Success" if approve else "Rejected", f"REMEDIATION_{cycle['change_id']}",
                 f"{decision.upper()} by {name}: {basis}")
            if approve:
                env.transition(cycle["change_id"], "Authorize", cycle["approval"]["approver"], basis)
                env.transition(cycle["change_id"], "Scheduled", "Change manager", env.enter_window(pkg["maintenance_window"]))
            else:
                exp_days = 14 if plan["priority"]["priority_label"].startswith("P1") else 30
                cycle["exception"] = {
                    "exception_id": f"EXC-{cycle['change_id'][-5:]}", "owner": name, "reason": basis,
                    "expires": (datetime.now(timezone.utc) + timedelta(days=exp_days)).strftime("%Y-%m-%d"),
                    "monitoring": "Daily rescan + alert on exploit attempts against the exposed service",
                }
                cycle["exposure_after"] = cycle["exposure_before"]
            st.rerun()
        return

    appr = cycle["approval"]
    colour = ACCENT_GREEN if appr["decision"] == "approve" else ACCENT_RED
    verb = "Approved" if appr["decision"] == "approve" else "Rejected"
    _md(_card(f'<strong style="color:{colour};">{verb}</strong> by {_e(appr["approver"])} at {_fmt_ts(appr["at"])}<br/>Basis: {_e(appr["reason"])}', colour, left=True))


def _render_exception(cycle: Dict[str, Any]) -> None:
    exc = cycle["exception"]
    _md(_card(
        f'<div style="color:{ACCENT_RED}; font-weight:700; margin-bottom:6px;">Risk-acceptance exception raised: exposure NOT reduced</div>'
        f'{_pill(exc["exception_id"], ACCENT_RED)} Owner: {_e(exc["owner"])} &middot; Expires {exc["expires"]}<br/>'
        f'Basis: {_e(exc["reason"])}<br/>Compensating monitoring: {_e(exc["monitoring"])}<br/>'
        f'The exposure stays on the dashboard at {cycle["exposure_before"]}/100 until it is fixed or the exception expires.', ACCENT_RED, left=True))


def _stream_log(lines: List) -> None:
    holder = st.empty()
    shown: List[str] = []
    for _, text in lines:
        shown.append(text)
        holder.code("\n".join(shown), language="bash")
        time.sleep(0.07)


def _render_itsm(env: SimulatedEnvironment, change_id: str, closure: str = "") -> None:
    rec = env.changes[change_id]
    reached = {h["state"] for h in rec["history"]}
    chips = []
    for state in ITSM_STATES:
        on = state in reached
        style = f"background:{ACCENT}33; color:{ACCENT}; border:1px solid {ACCENT}88;" if on else f"color:{TEXT_MUTED}; border:1px solid {BORDER_GLASS};"
        chips.append(f'<span style="padding:3px 9px; border-radius:10px; font-size:0.7rem; font-weight:700; {style}">{state}</span>')
    if closure == "blocked":
        chips[-1] = f'<span style="padding:3px 9px; border-radius:10px; font-size:0.7rem; font-weight:700; background:{ACCENT_RED}22; color:{ACCENT_RED}; border:1px solid {ACCENT_RED}77;">Closure blocked</span>'
    rows = "".join(f'<div style="font-size:0.75rem;"><span style="color:{TEXT_MUTED};">{_fmt_ts(h["at"])}</span> &middot; <strong>{h["state"]}</strong> &middot; {_e(h["actor"])} &middot; {_e(h["note"])}</div>' for h in rec["history"])
    _md(_card(
        f'<div style="display:flex; justify-content:space-between; flex-wrap:wrap;"><div style="color:{TEXT_PRIMARY}; font-weight:700;">ITSM change {change_id}</div>'
        f'<div>{_pill("Simulated ITSM", ACCENT_BLUE)}{_pill(rec["cab"], ACCENT_AMBER)}</div></div>'
        f'<div style="display:flex; flex-wrap:wrap; gap:6px; margin:8px 0;">{"".join(chips)}</div>{rows}'))


def _hours_to_result(run: Dict[str, Any], cycle: Dict[str, Any]) -> Any:
    """Hours from the ORIGINAL detection (not a re-detection) to this cycle's verification rescan."""
    if not cycle["rescan_after"]:
        return None
    origin = run["cycles"][0]["scenario"]["signal"]["detected_at"]
    first_seen = datetime.strptime(origin, "%Y-%m-%dT%H:%M:%SZ")
    scanned = datetime.strptime(cycle["rescan_after"]["scanned_at"], "%Y-%m-%dT%H:%M:%SZ")
    return max(0.0, (scanned - first_seen).total_seconds() / 3600)


def _record_run(run: Dict[str, Any], cycle: Dict[str, Any], jump_to: str = "") -> None:
    """Record the finished cycle for the KPIs, then rerun so the sidebar and Dashboard tab pick it up."""
    if cycle["recorded"]:
        return
    status = cycle["rescan_after"]["status"] if cycle["rescan_after"] else "vulnerable"
    st.session_state.remediation_runs.append({
        "hours": _hours_to_result(run, cycle),
        "signal_id": cycle["scenario"]["signal"]["signal_id"], "cve": cycle["scenario"]["signal"]["cve"], "host": cycle["scenario"]["asset"]["hostname"],
        "change_id": cycle["change_id"], "status": status, "exposure_before": cycle["exposure_before"], "exposure_after": cycle["exposure_after"],
        "ticket_closed": cycle["approval"]["decision"] == "approve", "exposure_reduced": status in ("remediated", "mitigated"),
        "approver": cycle["approval"]["approver"], "approved_at": cycle["approval"]["at"],
        "verdict": cycle["revalidation"]["verdict"] if cycle["revalidation"] else "Risk accepted - exposure unchanged",
        "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
    cycle["recorded"] = True
    if jump_to:
        run["pending_tab"] = jump_to
    st.rerun()


def _run_pipeline(run: Dict[str, Any], cycle: Dict[str, Any], agent_manager: AgentManager, datasets: Dict[str, pd.DataFrame]) -> None:
    """Steps 7-9 after approval: execute, rescan, write closure evidence. All progress is visible in this tab."""
    env: SimulatedEnvironment = run["env"]
    scenario, chg = cycle["scenario"], cycle["change_id"]
    st.caption("Execution runs in the customer's own ITSM, configuration-management and scanning tools. This demo simulates that environment; the platform orchestrates and verifies, it does not replace it.")
    if cycle["execution"] is None:
        env.transition(chg, "Implement", "Config management (simulated)", "Playbook started")
        result = env.execute(chg, scenario["sim"]["tasks"])
        _stream_log(result["lines"])
        env.transition(chg, "Review", "Config management (simulated)", f"Playbook finished: ok={result['ok']} changed={result['changed']} failed={result['failed']}")
        cycle["execution"] = result
        _log("Change Executed (simulated)", "Success" if not result["failed"] else "Failed", chg, f"{result['changed']} tasks changed on {scenario['asset']['hostname']}")
    else:
        with st.expander("Execution log (Ansible-style)", expanded=False):
            st.code("\n".join(t for _, t in cycle["execution"]["lines"]), language="bash")

    if cycle["rescan_after"] is None:
        with st.spinner("Step 8: verification rescan in progress..."):
            time.sleep(0.6)
            cycle["rescan_after"] = env.rescan()
        status = cycle["rescan_after"]["status"]
        cycle["exposure_after"] = residual_exposure(cycle["exposure_before"], status)
        cycle["closure"] = {"remediated": "closed", "mitigated": "closed_residual", "vulnerable": "blocked"}[status]
        if status == "remediated":
            env.transition(chg, "Closed", "Revalidation Agent", "Closed - Successful: rescan verified the exposure is gone")
        elif status == "mitigated":
            env.transition(chg, "Closed", "Revalidation Agent", "Closed - Successful with residual risk: follow-up change tracked")
        _log("Verification Rescan", "Success" if status != "vulnerable" else "Failed", chg, cycle["rescan_after"]["headline"])

    if cycle["revalidation"] is None:
        ticket_state = {"closed": "Closed - Successful", "closed_residual": "Closed - Residual Risk (follow-up tracked)",
                        "blocked": "Closure blocked (ITSM default would have closed)"}[cycle["closure"]]
        facts = {"change_id": chg, "approver": cycle["approval"]["approver"], "approved_at": cycle["approval"]["at"],
                 "executed_at": cycle["execution"]["finished_at"], "rescan": cycle["rescan_after"], "exposure_before": cycle["exposure_before"],
                 "exposure_after": cycle["exposure_after"], "ticket_state": ticket_state}
        with st.spinner("Step 9: RevalidationAgent writing closure evidence..."):
            cycle["revalidation"] = agent_manager.run_stage("remediation", "revalidate", datasets, "synthetic", scenario={**scenario, "revalidation_facts": facts})
    _render_itsm(env, chg, cycle["closure"] or "")
    if not cycle["recorded"]:
        _record_run(run, cycle, jump_to=TAB_VERIFY)


def _tab_plan(run: Dict[str, Any], cycle: Dict[str, Any], agent_manager: AgentManager, datasets: Dict[str, pd.DataFrame]) -> None:
    plan = cycle["plan"]
    _heading("4️⃣ Agent Identifies the Remediation Path")
    _render_options(plan)
    _heading("5️⃣ AI Generates the Change Package")
    _render_change_package(plan, cycle["change_id"])
    _heading("6️⃣ Human Approval")
    _render_approval(run, cycle)
    if cycle["approval"] is None:
        return
    if cycle["approval"]["decision"] == "reject":
        _render_exception(cycle)
        _record_run(run, cycle)
        return
    _heading("7️⃣ Native Tooling Executes")
    _run_pipeline(run, cycle, agent_manager, datasets)


# ── tab 3: verification, closure, dashboard ──────────────────────────────────

def _render_rescan_table(cycle: Dict[str, Any]) -> None:
    before, after = cycle["rescan_before"], cycle["rescan_after"]

    def col(title: str, scan: Dict[str, Any]) -> str:
        colour = {"remediated": ACCENT_GREEN, "mitigated": ACCENT_AMBER, "vulnerable": ACCENT_RED}[scan["status"]]
        state = {"FIXED": "FIXED", "MITIGATED": "MITIGATED", "OPEN": "STILL VULNERABLE"}[scan["finding_state"]]
        ev = "".join(f"<div>&bull; {_e(x)}</div>" for x in scan["evidence"])
        return (f'<div style="flex:1; min-width:280px;">{_label(title)}<div style="margin-bottom:6px;">{_pill(state, colour)}</div>'
                f'<div style="color:{TEXT_PRIMARY};">{_e(scan["headline"])}</div>{ev}'
                f'<div style="font-size:0.72rem; color:{TEXT_MUTED}; margin-top:6px;">{_e(scan["method"])} &middot; {_fmt_ts(scan["scanned_at"])}</div></div>')
    _md(_card(f'<div style="display:flex; flex-wrap:wrap; gap:18px;">{col("Before the change", before)}{col("After the change (verification rescan)", after)}</div>'))


def _evidence_bundle(run: Dict[str, Any], cycle: Dict[str, Any]) -> Dict[str, Any]:
    s, env = cycle["scenario"], run["env"]
    body = {
        "signal": s["signal"], "asset": s["asset"]["hostname"], "service": s["service"]["name"], "change": env.changes[cycle["change_id"]],
        "approval": cycle["approval"], "execution_summary": {k: cycle["execution"][k] for k in ("ok", "changed", "failed", "finished_at")},
        "task_log": [t for _, t in cycle["execution"]["lines"]], "rescan_before": cycle["rescan_before"], "rescan_after": cycle["rescan_after"],
        "exposure_before": cycle["exposure_before"], "exposure_after": cycle["exposure_after"], "verdict": cycle["revalidation"]["verdict"],
        "narrative": cycle["revalidation"]["closure_evidence"]["narrative"],
    }
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
    return {"evidence_id": f"EVD-{cycle['change_id'][-5:]}", "sha256": digest, **body}


def _render_outcome_banner(cycle: Dict[str, Any]) -> None:
    status = cycle["rescan_after"]["status"]
    colour, headline = _OUTCOME_STYLE[status]
    s, b, a = cycle["scenario"], cycle["exposure_before"], cycle["exposure_after"]
    detail = {
        "remediated": f"{s['signal']['cve']} on {s['asset']['hostname']}: exposure {b} to {a}. The ticket closes because the exposure is gone, not because the task finished.",
        "mitigated": f"{s['signal']['cve']} on {s['asset']['hostname']}: exposure {b} to {a}. The vulnerable build is still installed, so the fix stays open as a tracked follow-up.",
        "vulnerable": f"{s['signal']['cve']} on {s['asset']['hostname']}: exposure is still {a}. A conventional ITSM flow would have closed this ticket; the loop is re-opened instead.",
    }[status]
    _md(f'<div style="margin-top:20px; padding:26px 30px; border-radius:16px; text-align:center; background: linear-gradient(135deg, {colour}22 0%, rgba(168,85,247,0.10) 100%); border:1px solid {colour}66;">'
        f'<div style="font-size:1.6rem; font-weight:800; color:{colour}; letter-spacing:-0.01em; margin-bottom:6px;">🎯 Exposure reduced, not ticket closed</div>'
        f'<div style="font-size:1rem; font-weight:700; color:{TEXT_PRIMARY}; margin-bottom:6px;">{headline}</div>'
        f'<div style="font-size:0.92rem; color:{TEXT_SECONDARY};">{_e(detail)}</div></div>')


def _render_kpi_deltas(run: Dict[str, Any], kpi_engine: Any) -> None:
    now = _kpi_snapshot(kpi_engine)
    before = run.get("kpi_before", now)
    lower_better = {"Closed Without Reduction", "Remediation MTTR"}
    unit = {"Verified Closure Rate": "%", "Closed Without Reduction": "%", "Exposure Reduction": "%", "Remediation MTTR": " h",
            "Remediation score": "%", "AI Readiness Index": "%"}
    cards = ""
    for name in ("Remediation score", "AI Readiness Index", "Verified Closure Rate", "Closed Without Reduction", "Exposure Reduction", "Remediation MTTR"):
        delta = now[name] - before[name]
        good = (delta <= 0) if name in lower_better else (delta >= 0)
        colour = TEXT_MUTED if abs(delta) < 0.05 else (ACCENT_GREEN if good else ACCENT_AMBER)
        cards += (f'<div style="padding:12px 14px; border:1px solid {BORDER_GLASS}; border-radius:10px;">'
                  f'<div style="font-size:1.35rem; font-weight:800; color:{TEXT_PRIMARY};">{now[name]:.1f}{unit[name]}</div>'
                  f'{_label(name)}<div style="font-size:0.75rem; color:{colour};">{delta:+.1f}{unit[name]} since this run started</div></div>')
    _md(f'<div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(170px, 1fr)); gap:10px; margin-bottom:12px;">{cards}</div>')
    st.caption("These are the same live KPIs shown on the Dashboard tab and the sidebar.")


def _render_cycle_history(cycle: Dict[str, Any]) -> None:
    status = cycle["rescan_after"]["status"] if cycle["rescan_after"] else "n/a"
    label = _OUTCOME_STYLE.get(status, ("", "No execution"))[1]
    with st.expander(f"Cycle {cycle['index'] + 1} history: {cycle['change_id']} — {label}"):
        if cycle["rescan_after"]:
            _render_rescan_table(cycle)
            if cycle["revalidation"]:
                st.write(cycle["revalidation"]["closure_evidence"]["narrative"])


def _tab_verify(run: Dict[str, Any], cycle: Dict[str, Any], agent_manager: AgentManager, datasets: Dict[str, pd.DataFrame], kpi_engine: Any) -> None:
    for earlier in run["cycles"][:-1]:
        _render_cycle_history(earlier)
    if cycle["approval"] is None:
        st.info("Waiting for the human approval in the previous tab. Verification starts after the change is executed.")
        return
    if cycle["approval"]["decision"] == "reject":
        _heading("🔟 Dashboard Updates")
        st.warning(f"Change rejected and a risk-acceptance exception raised. Exposure is unchanged at {cycle['exposure_before']}/100 and counts against the remediation KPIs.")
        if cycle["recorded"]:
            _render_kpi_deltas(run, kpi_engine)
        return
    if cycle["revalidation"] is None or not cycle["rescan_after"]:
        st.info("Execution and verification are in progress in the previous tab.")
        return

    _heading("8️⃣ Agent Rescans and Revalidates")
    _render_rescan_table(cycle)
    _render_itsm(run["env"], cycle["change_id"], cycle["closure"] or "")

    _heading("9️⃣ Closure Evidence")
    reval = cycle["revalidation"]
    colour = _OUTCOME_STYLE[cycle["rescan_after"]["status"]][0]
    ce = reval["closure_evidence"]
    next_actions = "".join(f"<div>&bull; {_e(a)}</div>" for a in reval["next_actions"])
    _md(_card(f'<div style="color:{colour}; font-weight:700; margin-bottom:6px;">{_e(reval["verdict"])}</div>{_e(ce["narrative"])}<br/><br/>'
              f'{_label("Residual risk")}{_e(reval["residual_risk"])}<br/><br/>{_label("Next actions")}{next_actions}', colour, left=True))
    bundle = _evidence_bundle(run, cycle)
    with st.expander(f'Evidence bundle {bundle["evidence_id"]} (SHA-256 {bundle["sha256"][:16]}...)'):
        st.json(bundle)
    st.download_button("⬇️ Download evidence bundle (JSON)", json.dumps(bundle, indent=2, default=str), file_name=f'{bundle["evidence_id"]}.json',
                       mime="application/json", key=f"rem_dl_{cycle['index']}")

    _heading("🔟 Dashboard Updates")
    b, a = cycle["exposure_before"], cycle["exposure_after"]
    hours = _hours_to_result(run, cycle) or 0.0
    ticket_closed = "Closed" if cycle["closure"] != "blocked" else "Would auto-close"
    c1, c2, c3, c4 = st.columns(4)
    for col, label, value, sub in (
        (c1, "Exposure before", f"{b}/100", cycle["scenario"]["signal"]["cve"]),
        (c2, "Exposure after", f"{a}/100", f"{b - a} points removed" if b != a else "no reduction"),
        (c3, "Signal to verified result", f"{hours:.1f} h", "simulated clock"),
        (c4, "Ticket vs reality", ticket_closed, "Exposure " + ("reduced" if cycle["rescan_after"]["status"] != "vulnerable" else "NOT reduced")),
    ):
        col.markdown(clean_html(_card(f'<div style="font-size:1.5rem; font-weight:800; color:{TEXT_PRIMARY};">{value}</div>{_label(label)}<div style="font-size:0.75rem;">{_e(sub)}</div>')), unsafe_allow_html=True)
    _render_kpi_deltas(run, kpi_engine)
    _render_outcome_banner(cycle)

    if cycle["closure"] == "blocked" and cycle["index"] == len(run["cycles"]) - 1:
        if st.button("🔁 Re-plan with AI using the rescan evidence", key=f"rem_replan_{cycle['index']}", type="primary"):
            follow = build_followup_scenario(cycle["scenario"], cycle["rescan_after"])
            follow["analyst_inputs"] = cycle["scenario"].get("analyst_inputs", {})
            with st.spinner("Planner re-evaluating with the rescan evidence..."):
                run["cycles"].append(_new_cycle(agent_manager, datasets, run["env"], follow, cycle["index"] + 1))
            run["pending_tab"] = TAB_ANALYSIS
            st.rerun()


# ── tabs styling + page ──────────────────────────────────────────────────────

def _inject_tab_css() -> None:
    st.markdown(f"""
    <style>
        button[data-baseweb="tab"], button[data-testid="stTab"] {{
            font-family: 'Inter', sans-serif !important; font-size: 0.88rem !important; font-weight: 600 !important;
            color: #6b6b8d !important; background: rgba(255, 255, 255, 0.02) !important; border: 1px solid rgba(255, 255, 255, 0.04) !important;
            padding: 8px 18px !important; border-radius: 20px !important; margin-right: 8px !important; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        }}
        button[data-baseweb="tab"]:hover, button[data-testid="stTab"]:hover {{
            color: #ffffff !important; background: rgba(255, 255, 255, 0.06) !important; border-color: rgba(255, 255, 255, 0.1) !important;
        }}
        button[data-baseweb="tab"][aria-selected="true"], button[data-testid="stTab"][aria-selected="true"] {{
            color: {ACCENT} !important; background: rgba(168, 85, 247, 0.12) !important; border: 1px solid rgba(168, 85, 247, 0.35) !important;
        }}
        div[data-testid="stTabBar"] > div {{ border-bottom: none !important; }}
        div[data-baseweb="tab-highlight"], div[data-testid="stTabHighlight"] {{ background-color: transparent !important; }}
    </style>
    """, unsafe_allow_html=True)


def _start_run(panel: Dict[str, Any], datasets: Dict[str, pd.DataFrame], agent_manager: AgentManager, kpi_engine: Any) -> None:
    scenario = get_scenario(panel["key"])
    if panel["live_intel"]:
        with st.spinner("Fetching live CISA KEV and FIRST EPSS data..."):
            scenario = with_live_threat(scenario, enrich_threat(scenario["signal"]["cve"], scenario["threat"]))
    scenario["threat"] = reference.attach_kev_reference(scenario["threat"], scenario["signal"]["cve"])
    scenario["analyst_inputs"] = {"frameworks": panel["frameworks"], "constraints": panel["constraints"]}
    render_progress_indicator("Correlating vulnerability, identity, business service and threat context...", 25)
    time.sleep(0.3)
    render_progress_indicator("Explaining priority, mapping obligations and evaluating remediation paths...", 60)
    time.sleep(0.3)
    render_progress_indicator("Drafting the change package for approval...", 90)
    time.sleep(0.3)
    env = SimulatedEnvironment(scenario)
    run = {"key": panel["key"], "env": env, "cycles": [], "pending_tab": TAB_ANALYSIS, "kpi_before": _kpi_snapshot(kpi_engine)}
    run["cycles"].append(_new_cycle(agent_manager, datasets, env, scenario, 0))
    st.session_state.remediation_run = run
    st.rerun()


def render_remediation_page(datasets: Dict[str, pd.DataFrame], agent_manager: AgentManager, kpi_engine: Any) -> None:
    _init_state()
    st.markdown(f'<h1 style="color: {ACCENT}; margin-bottom: 8px;">🛠️ AI-Led Exposure Remediation</h1>', unsafe_allow_html=True)
    render_usecase_overview_card("remediation")
    st.markdown('<div class="synthetic-banner">⚠️ <strong>Simulated customer environment</strong> — the scanner signal, ITSM, configuration management and hosts below are simulated. CVEs, versions, the CISA KEV records and the MITRE ATT&CK techniques are real.</div>', unsafe_allow_html=True)

    panel = _input_panel(datasets)
    render_agent_details_bar("remediation", "analysis")
    if render_execute_button("remediation", "analysis", panel["data_source"]):
        _start_run(panel, datasets, agent_manager, kpi_engine)

    run = st.session_state.remediation_run
    if not run:
        return
    cycle = run["cycles"][-1]
    _inject_tab_css()
    pending = run.pop("pending_tab", None)
    if pending and _TABS_STATEFUL:
        st.session_state[_TAB_KEY] = pending
    elif pending and pending != TAB_ANALYSIS:
        st.success(f"Done. Open the **{pending}** tab below to see the result.")
    if cycle["index"] > 0:
        st.markdown(f'<h3 style="color:{ACCENT_AMBER}; margin-top:20px;">↻ Loop re-opened (cycle {cycle["index"] + 1})</h3>', unsafe_allow_html=True)
    st.caption(f"Showing run for scenario {run['key']}. Press Execute again to start a fresh run.")
    labels = [TAB_ANALYSIS, TAB_PLAN, TAB_VERIFY]
    tab_a, tab_b, tab_c = st.tabs(labels, key=_TAB_KEY) if _TABS_STATEFUL else st.tabs(labels)
    with tab_a:
        _tab_analysis(run, cycle)
    with tab_b:
        _tab_plan(run, cycle, agent_manager, datasets)
    with tab_c:
        _tab_verify(run, cycle, agent_manager, datasets, kpi_engine)
