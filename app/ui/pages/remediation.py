"""
AI Capability Demo — Exposure Remediation Page
Closed-loop remediation of ONE exposure, end to end:
signal -> AI correlation -> AI priority explanation -> remediation path -> change package ->
human approval -> execution in the customer's native tooling (simulated) -> rescan ->
closure evidence -> dashboard update.  Success = exposure reduced, not ticket closed.
"""

import hashlib
import html
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import pandas as pd
import streamlit as st

from app.data.live_intel import enrich_threat
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
from app.ui.components.interactive_demo import render_progress_indicator
from app.ui.components.lifecycle_stage import render_usecase_overview_card
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
)

ACCENT = ACCENT_PURPLE
_TYPE_COLOUR = {"patch": ACCENT_GREEN, "config": ACCENT_BLUE, "compensating_control": ACCENT_AMBER, "exception": ACCENT_RED}
_TYPE_LABEL = {"patch": "Patch / upgrade", "config": "Configuration", "compensating_control": "Compensating control", "exception": "Risk exception"}
_STEP_NAMES = ["Signal", "Correlate", "Prioritise", "Plan", "Package", "Approve", "Execute", "Rescan", "Evidence", "Dashboard"]
_OUTCOME_STYLE = {
    "remediated": (ACCENT_GREEN, "Exposure reduced and verified"),
    "mitigated": (ACCENT_AMBER, "Exposure reduced, residual risk tracked"),
    "vulnerable": (ACCENT_RED, "Closure blocked: the exposure is still there"),
}


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


# ── session state ────────────────────────────────────────────────────────────

def _init_state() -> None:
    st.session_state.setdefault("remediation_run", None)
    st.session_state.setdefault("remediation_runs", [])


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


# ── step renderers ───────────────────────────────────────────────────────────

def _render_progress_strip(cycle: Dict[str, Any]) -> None:
    done = 5
    if cycle["approval"]:
        done = 6
    if cycle["execution"]:
        done = 7
    if cycle["rescan_after"]:
        done = 8
    if cycle["revalidation"]:
        done = 9
    if cycle["recorded"]:
        done = 10
    pills = []
    for i, name in enumerate(_STEP_NAMES, start=1):
        if i <= done:
            style = f"background:{ACCENT}33; color:{ACCENT}; border:1px solid {ACCENT}88;"
        elif i == done + 1:
            style = f"background:{ACCENT_AMBER}22; color:{ACCENT_AMBER}; border:1px solid {ACCENT_AMBER}66;"
        else:
            style = f"background:rgba(255,255,255,0.03); color:{TEXT_MUTED}; border:1px solid {BORDER_GLASS};"
        pills.append(f'<span style="padding:4px 10px; border-radius:12px; font-size:0.72rem; font-weight:700; {style}">{i}. {name}</span>')
    _md(f'<div style="display:flex; flex-wrap:wrap; gap:6px; margin:6px 0 18px 0;">{"".join(pills)}</div>')


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


def _render_correlation(plan: Dict[str, Any]) -> None:
    corr = plan["correlation"]
    asset, svc, ident, threat = corr["asset"], corr["service"], corr["identity"], corr["threat"]
    status = threat.get("intel_status", "snapshot")
    intel = {"live": ("Live intel: CISA KEV + FIRST EPSS", ACCENT_GREEN), "partial": ("Partly live intel", ACCENT_AMBER)}.get(
        status, (f"Snapshot as of {threat.get('epss_as_of', '')}", TEXT_SECONDARY))
    _md(_card(f'{_label("AI correlation insight")}<div style="color:{TEXT_PRIMARY};">{_e(corr["insight"])}</div>', ACCENT, left=True))
    cols = st.columns(4)
    blocks = [
        ("Asset", [asset["hostname"], f'{asset["os"]}', asset["location"], f'Owner: {asset["owner_team"]}',
                   "Internet exposed" if asset["internet_exposed"] else "Internal only", asset["exposure_via"]]),
        ("Business service", [svc["name"], f'{svc["tier"]} &middot; RTO {svc["rto_hours"]}h', ", ".join(svc["regulatory_scope"]),
                              f'Data: {svc["data_classification"]}', svc["users"]]),
        ("Identity", [ident["account"], ident["type"], ident["privilege"], ident["credential_exposure"]]),
        ("Threat context", [("In CISA KEV since " + threat["kev_date_added"]) if threat["kev"] else "Not in CISA KEV",
                            f'Ransomware use: {threat["ransomware_use"]}', f'EPSS {threat["epss"]:.3f} ({threat["epss_percentile"] * 100:.1f}th pct)',
                            threat["exploit_maturity"], threat["attack_technique"]]),
    ]
    for col, (title, lines) in zip(cols, blocks):
        body = "".join(f'<div style="margin-bottom:3px;">{line if "&middot;" in line else _e(line)}</div>' for line in lines)
        col.markdown(clean_html(_card(f'{_label(title)}{body}')), unsafe_allow_html=True)
    _md(f'<div style="margin:-4px 0 10px 0;">{_pill(intel[0], intel[1])}</div>')
    st.markdown("**Exposure path** (how an attacker gets from the internet to business impact)")
    chain = [{"chain_id": plan["correlation"]["signal_id"], "severity": "Critical", "steps": corr["exposure_path"]}]
    _md(render_attack_chain_diagram(chain, ACCENT))
    _md(_card(f'{_label("Blast radius")}' + "".join(f"<div>&bull; {_e(b)}</div>" for b in corr["blast_radius"])))


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
        f'<div style="font-size:0.72rem; color:{TEXT_MUTED}; text-transform:uppercase;">CVSS rank &rarr; real rank (of {pr["total"]})</div></div></div>')
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


def _render_options(plan: Dict[str, Any]) -> None:
    cards = ""
    for opt in plan["remediation_options"]:
        rec = opt["id"] == plan["recommended_option"]
        colour = _TYPE_COLOUR.get(opt["type"], ACCENT_BLUE)
        blocker = ""
        if opt.get("not_viable"):
            blocker = f'<div style="color:{ACCENT_RED}; font-weight:700; margin-top:6px;">Not viable: {_e(opt["not_viable"])}</div>'
        elif opt.get("blocked_reason"):
            blocker = f'<div style="color:{ACCENT_AMBER}; font-weight:700; margin-top:6px;">Blocked: {_e(opt["blocked_reason"])}</div>'
        badge = _pill("AI RECOMMENDED", ACCENT_GREEN) if rec else ""
        border = f"2px solid {ACCENT_GREEN}" if rec else f"1px solid {BORDER_GLASS}"
        cards += (
            f'<div style="padding:14px 16px; border:{border}; border-radius:10px; background:rgba(255,255,255,{0.05 if rec else 0.02}); font-size:0.82rem; color:{TEXT_SECONDARY};">'
            f'<div style="margin-bottom:6px;">{_pill(_TYPE_LABEL.get(opt["type"], opt["type"]), colour)}{badge}</div>'
            f'<div style="color:{TEXT_PRIMARY}; font-weight:700; margin-bottom:8px;">{_e(opt["title"])}</div>'
            f'<div style="display:flex; justify-content:space-between;"><span>Risk reduction</span><strong style="color:{TEXT_PRIMARY};">{opt["risk_reduction_pct"]}%</strong></div>'
            f'{_bar(opt["risk_reduction_pct"], 100, colour)}'
            f'<div style="margin-top:6px;">Change risk: <strong>{_e(opt["change_risk"])}</strong> &middot; Downtime: <strong>{_e(opt["downtime"])}</strong> &middot; Effort: {_e(opt["effort"])}</div>'
            f'<div style="margin-top:6px;">{_e(opt.get("ai_assessment", opt["tradeoff"]))}</div>{blocker}</div>')
    _md(f'<div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(300px, 1fr)); gap:12px; margin-bottom:12px;">{cards}</div>')
    if plan.get("recommended_reason"):
        _md(_card(f'{_label("Why this path")}<div style="color:{TEXT_PRIMARY};">{_e(plan["recommended_reason"])}</div>', ACCENT_GREEN, left=True))


def _render_change_package(plan: Dict[str, Any], env: SimulatedEnvironment, change_id: str) -> None:
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
    src = plan.get("narrative_source")
    if src:
        st.caption("Narrative: AI-generated from the ground-truth facts above." if src == "llm" else "Narrative: deterministic fallback (no live model response was used).")


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
        reason = st.text_input("Reviewer comment (required)", key=f"rem_reason_{idx}",
                               placeholder="e.g. Confirmed with the service owner; backup verified; window agreed")
        c1, c2 = st.columns(2)
        approve = c1.button("✅ Approve and schedule change", key=f"rem_approve_{idx}", type="primary", use_container_width=True)
        reject = c2.button("⛔ Reject and raise a risk-acceptance exception", key=f"rem_reject_{idx}", use_container_width=True)
        if approve or reject:
            if not reason.strip():
                st.warning("A reviewer comment is required for both decisions.")
                return
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            decision = "approve" if approve else "reject"
            name = _approver_name()
            cycle["approval"] = {"decision": decision, "approver": f"{name} ({pkg['approver_role']})", "reason": reason.strip(), "at": now}
            try:
                from app.observability.health_metrics import InAppMetrics
                InAppMetrics().record_hitl_decision("remediation", "plan", decision, int(plan["ai_confidence"]))
            except Exception:
                pass
            _log("HITL Decision: Exposure Remediation", "Success" if approve else "Rejected", f"REMEDIATION_{cycle['change_id']}",
                 f"{decision.upper()} by {name}: {reason.strip()}")
            if approve:
                env.transition(cycle["change_id"], "Authorize", cycle["approval"]["approver"], reason.strip())
                env.transition(cycle["change_id"], "Scheduled", "Change manager", env.enter_window(pkg["maintenance_window"]))
            else:
                exp_days = 14 if plan["priority"]["priority_label"].startswith("P1") else 30
                cycle["exception"] = {
                    "exception_id": f"EXC-{cycle['change_id'][-5:]}", "owner": name, "reason": reason.strip(),
                    "expires": (datetime.now(timezone.utc) + timedelta(days=exp_days)).strftime("%Y-%m-%d"),
                    "monitoring": "Daily rescan + alert on exploit attempts against the exposed service",
                }
                cycle["exposure_after"] = cycle["exposure_before"]
            st.rerun()
        return

    appr = cycle["approval"]
    colour = ACCENT_GREEN if appr["decision"] == "approve" else ACCENT_RED
    verb = "Approved" if appr["decision"] == "approve" else "Rejected"
    _md(_card(f'<strong style="color:{colour};">{verb}</strong> by {_e(appr["approver"])} at {_fmt_ts(appr["at"])}<br/>Comment: {_e(appr["reason"])}', colour, left=True))


def _render_exception(cycle: Dict[str, Any]) -> None:
    exc = cycle["exception"]
    _md(_card(
        f'<div style="color:{ACCENT_RED}; font-weight:700; margin-bottom:6px;">Risk-acceptance exception raised: exposure NOT reduced</div>'
        f'{_pill(exc["exception_id"], ACCENT_RED)} Owner: {_e(exc["owner"])} &middot; Expires {exc["expires"]}<br/>'
        f'Rationale: {_e(exc["reason"])}<br/>Compensating monitoring: {_e(exc["monitoring"])}<br/>'
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


def _hours_to_result(run: Dict[str, Any], cycle: Dict[str, Any]) -> Any:
    """Hours from the ORIGINAL detection (not a re-detection) to this cycle's verification rescan."""
    if not cycle["rescan_after"]:
        return None
    origin = run["cycles"][0]["scenario"]["signal"]["detected_at"]
    first_seen = datetime.strptime(origin, "%Y-%m-%dT%H:%M:%SZ")
    scanned = datetime.strptime(cycle["rescan_after"]["scanned_at"], "%Y-%m-%dT%H:%M:%SZ")
    return max(0.0, (scanned - first_seen).total_seconds() / 3600)


def _record_run(run: Dict[str, Any], cycle: Dict[str, Any]) -> None:
    if cycle["recorded"]:
        return
    status = cycle["rescan_after"]["status"] if cycle["rescan_after"] else "vulnerable"
    hours = _hours_to_result(run, cycle)
    st.session_state.remediation_runs.append({
        "hours": hours,
        "signal_id": cycle["scenario"]["signal"]["signal_id"], "cve": cycle["scenario"]["signal"]["cve"], "host": cycle["scenario"]["asset"]["hostname"],
        "change_id": cycle["change_id"], "status": status, "exposure_before": cycle["exposure_before"], "exposure_after": cycle["exposure_after"],
        "ticket_closed": cycle["approval"]["decision"] == "approve", "exposure_reduced": status in ("remediated", "mitigated"),
        "approver": cycle["approval"]["approver"], "approved_at": cycle["approval"]["at"],
        "verdict": cycle["revalidation"]["verdict"] if cycle["revalidation"] else "Risk accepted - exposure unchanged",
        "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
    cycle["recorded"] = True
    # The sidebar and Dashboard tab were drawn earlier in this run; rerun so they pick up the new KPIs.
    st.rerun()


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


def _render_cycle(run: Dict[str, Any], cycle: Dict[str, Any], agent_manager: AgentManager, datasets: Dict[str, pd.DataFrame]) -> None:
    env: SimulatedEnvironment = run["env"]
    scenario, plan = cycle["scenario"], cycle["plan"]
    if cycle["index"] > 0:
        _md(f'<h3 style="color:{ACCENT_AMBER}; margin-top:28px;">↻ Loop re-opened (cycle {cycle["index"] + 1})</h3>')
    _render_progress_strip(cycle)

    st.markdown("### 1️⃣ Exposure Arrives")
    _render_signal(scenario)
    st.markdown("### 2️⃣ AI Correlates Vulnerability, Identity, Business Service and Threat Context")
    _render_correlation(plan)
    st.markdown("### 3️⃣ AI Explains Priority")
    _render_priority(plan)
    st.markdown("### 4️⃣ Agent Identifies the Remediation Path")
    _render_options(plan)
    st.markdown("### 5️⃣ AI Generates the Change Package")
    _render_change_package(plan, env, cycle["change_id"])
    st.markdown("### 6️⃣ Human Approval")
    _render_approval(run, cycle)
    if cycle["approval"] is None:
        return
    if cycle["approval"]["decision"] == "reject":
        _render_exception(cycle)
        _record_run(run, cycle)
        return

    chg = cycle["change_id"]
    st.markdown("### 7️⃣ Native Tooling Executes")
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

    st.markdown("### 8️⃣ Agent Rescans and Revalidates")
    if cycle["rescan_after"] is None:
        with st.spinner("Verification rescan in progress..."):
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
    _render_rescan_table(cycle)
    _render_itsm(env, chg, cycle["closure"])

    st.markdown("### 9️⃣ Closure Evidence")
    if cycle["revalidation"] is None:
        ticket_state = {"closed": "Closed - Successful", "closed_residual": "Closed - Residual Risk (follow-up tracked)",
                        "blocked": "Closure blocked (ITSM default would have closed)"}[cycle["closure"]]
        facts = {"change_id": chg, "approver": cycle["approval"]["approver"], "approved_at": cycle["approval"]["at"],
                 "executed_at": cycle["execution"]["finished_at"], "rescan": cycle["rescan_after"], "exposure_before": cycle["exposure_before"],
                 "exposure_after": cycle["exposure_after"], "ticket_state": ticket_state}
        with st.spinner("RevalidationAgent writing closure evidence..."):
            cycle["revalidation"] = agent_manager.run_stage("remediation", "revalidate", datasets, "synthetic", scenario={**scenario, "revalidation_facts": facts})
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

    st.markdown("### 🔟 Dashboard Updates")
    _record_run(run, cycle)
    b, a = cycle["exposure_before"], cycle["exposure_after"]
    hours = _hours_to_result(run, cycle) or 0.0
    ticket_closed = "Closed" if cycle["closure"] != "blocked" else "Would auto-close"
    c1, c2, c3, c4 = st.columns(4)
    for col, label, value, sub in (
        (c1, "Exposure before", f"{b}/100", scenario["signal"]["cve"]),
        (c2, "Exposure after", f"{a}/100", f"{b - a} points removed" if b != a else "no reduction"),
        (c3, "Signal to verified result", f"{hours:.1f} h", "simulated clock"),
        (c4, "Ticket vs reality", ticket_closed, "Exposure " + ("reduced" if cycle["rescan_after"]["status"] != "vulnerable" else "NOT reduced")),
    ):
        col.markdown(clean_html(_card(f'<div style="font-size:1.5rem; font-weight:800; color:{TEXT_PRIMARY};">{value}</div>{_label(label)}<div style="font-size:0.75rem;">{_e(sub)}</div>')), unsafe_allow_html=True)
    _render_outcome_banner(cycle)

    if cycle["closure"] == "blocked" and cycle["index"] == len(run["cycles"]) - 1:
        if st.button("🔁 Re-plan with AI using the rescan evidence", key=f"rem_replan_{cycle['index']}", type="primary"):
            follow = build_followup_scenario(scenario, cycle["rescan_after"])
            with st.spinner("Planner re-evaluating with the rescan evidence..."):
                run["cycles"].append(_new_cycle(agent_manager, datasets, env, follow, cycle["index"] + 1))
            st.rerun()


# ── page ─────────────────────────────────────────────────────────────────────

def render_remediation_page(datasets: Dict[str, pd.DataFrame], agent_manager: AgentManager, kpi_engine: Any) -> None:
    _init_state()
    st.markdown(f'<h1 style="color: {ACCENT}; margin-bottom: 8px;">🛠️ AI-Led Exposure Remediation</h1>', unsafe_allow_html=True)
    render_usecase_overview_card("remediation")
    st.markdown('<div class="synthetic-banner">⚠️ <strong>Simulated customer environment</strong> — the scanner signal, ITSM, configuration management and hosts below are simulated. CVEs, versions and mitigations are real.</div>', unsafe_allow_html=True)

    scenarios = get_scenarios()
    labels = {k: scenarios[k]["label"] for k in SCENARIO_ORDER}
    key = st.radio("Choose a real-world scenario", SCENARIO_ORDER, format_func=lambda k: labels[k], horizontal=True, key="rem_scenario_radio")
    st.caption(scenarios[key]["tagline"])
    live = st.toggle("Enrich threat context with live CISA KEV + FIRST EPSS (falls back to a snapshot if offline)", value=True, key="rem_live_intel")

    run = st.session_state.remediation_run
    if run is None:
        st.markdown("### 1️⃣ Exposure Arrives (preview)")
        _render_signal(scenarios[key])

    if st.button("🚀 Run Closed-Loop Remediation", type="primary", key="rem_execute"):
        scenario = get_scenario(key)
        if live:
            with st.spinner("Fetching live threat intelligence..."):
                scenario = with_live_threat(scenario, enrich_threat(scenario["signal"]["cve"], scenario["threat"]))
        render_progress_indicator("Correlating vulnerability, identity, business service and threat context...", 25)
        time.sleep(0.3)
        render_progress_indicator("Explaining priority and evaluating remediation paths...", 60)
        time.sleep(0.3)
        render_progress_indicator("Drafting the change package for approval...", 90)
        time.sleep(0.3)
        env = SimulatedEnvironment(scenario)
        run = {"key": key, "env": env, "cycles": []}
        run["cycles"].append(_new_cycle(agent_manager, datasets, env, scenario, 0))
        st.session_state.remediation_run = run
        st.rerun()

    if run:
        st.caption(f"Showing run for scenario {run['key']}. Press the button again to start a fresh run.")
        for cycle in run["cycles"]:
            _render_cycle(run, cycle, agent_manager, datasets)
