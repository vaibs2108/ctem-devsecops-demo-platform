"""
AI Capability Demo — Remediation Workflow Engine
Path A (Workflow/Ticketing) + Path B (AI Auto-Remediate).
Pydantic models from AGENTS.md Section 10 and 13.3.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import streamlit as st
from pydantic import BaseModel, Field

from app.ui.theme import (
    ACCENT_AMBER,
    ACCENT_BLUE,
    ACCENT_GREEN,
    ACCENT_RED,
    RAG_GREEN,
    RAG_RED,
    TEXT_MUTED,
    TEXT_SECONDARY,
    render_glass_card,
    render_metric_card,
)

# ── Pydantic Models — AGENTS.md §10 / §13.3 ─────────────────────────────────


class RemediationAction(BaseModel):
    """A single remediation action to be executed."""

    action_type: str = Field(
        ...,
        description="PATCH|CREATE|CONFIG|BLOCK|DEPLOY|SUPPRESS",
    )
    target_tool: str = Field(..., description="Target security tool / platform")
    target_object: str = Field(..., description="Asset or object being remediated")
    api_endpoint: str = Field(..., description="API endpoint for the action")
    api_payload: dict = Field(default_factory=dict)
    reversible: bool = Field(default=True)
    blast_radius: str = Field(
        default="Low", description="Low|Medium|High"
    )
    blast_description: str = Field(default="")


class KPIImpactItem(BaseModel):
    """Projected KPI impact of a remediation action."""

    kpi_name: str
    before_value: str
    after_value: str
    delta_pct: float
    direction: str = Field(
        default="improved", description="improved|degraded|neutral"
    )


class RemediationTicketSpec(BaseModel):
    """Specification for a remediation ticket (Jira / ServiceNow)."""

    title: str
    description: str
    ticket_type: str = Field(
        default="vulnerability",
        description="vulnerability|incident|change|task",
    )
    use_case: str
    priority: str = Field(default="P2", description="P1|P2|P3")
    severity: str = Field(default="High")
    assignee_team: str = Field(default="Security Engineering")
    due_date: str = Field(default="")
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    technique_id: Optional[str] = None
    ai_confidence: int = Field(default=75, ge=40, le=99)
    remediation_steps: List[str] = Field(default_factory=list)
    tool_source: str = Field(default="synthetic")


class RemediationOutcome(BaseModel):
    """Complete output of a remediation stage."""

    summary: str
    actions_taken: List[RemediationAction] = Field(default_factory=list)
    kpi_impact: List[KPIImpactItem] = Field(default_factory=list)
    tickets: List[RemediationTicketSpec] = Field(default_factory=list)


class WorkflowItem(BaseModel):
    """A single item in the remediation workflow / approval queue."""

    item_id: str = Field(default_factory=lambda: f"WF-{uuid.uuid4().hex[:8].upper()}")
    finding_title: str
    severity: str
    owner: str
    due_date: str
    status: str = Field(
        default="pending_approval",
        description="pending_approval|approved|in_progress|completed|rejected",
    )
    ticket_ref: Optional[str] = None
    audit_entries: List[str] = Field(default_factory=list)


# ── Remediation Workflow Engine ──────────────────────────────────────────────


class RemediationWorkflowEngine:
    """Manages remediation for both Path A (Workflow) and Path B (AI Auto-Remediate)."""

    def __init__(self) -> None:
        if "workflow_items" not in st.session_state:
            st.session_state.workflow_items = []
        if "remediation_authorised" not in st.session_state:
            st.session_state.remediation_authorised = False

    # ── Path A: Workflow / Ticketing ─────────────────────────────────────

    def create_workflow_items(
        self, findings: List[Dict[str, Any]]
    ) -> List[WorkflowItem]:
        """Create WorkflowItems from validated findings."""
        items: List[WorkflowItem] = []
        owner_rotation = [
            "Security Engineering",
            "Platform Team",
            "DevOps",
            "Application Security",
            "Cloud Infrastructure",
        ]

        for i, finding in enumerate(findings):
            severity = finding.get("severity", "Medium")
            sla_days = {"Critical": 3, "High": 7, "Medium": 14, "Low": 30}.get(
                severity, 14
            )
            due = (datetime.now() + timedelta(days=sla_days)).strftime("%Y-%m-%d")
            owner = owner_rotation[i % len(owner_rotation)]

            item = WorkflowItem(
                finding_title=finding.get("title", f"Finding {i + 1}"),
                severity=severity,
                owner=owner,
                due_date=due,
                status="pending_approval",
                ticket_ref=f"JIRA-{2024_000 + i + 1}",
                audit_entries=[
                    f"{datetime.now().isoformat()} — Item created by AI agent",
                ],
            )
            items.append(item)

        st.session_state.workflow_items = [
            it.model_dump() for it in items
        ]
        return items

    def render_approval_queue(self, items: List[WorkflowItem]) -> None:
        """Render the approval queue UI (Path A — Step 1)."""
        st.markdown("### 📋 Approval Queue")
        st.markdown(
            '<div class="synthetic-banner">⚠️ HITL Gate — Review and approve '
            "each remediation item before execution.</div>",
            unsafe_allow_html=True,
        )

        if not items:
            st.info("No items in the approval queue. Run analysis first.")
            return

        for idx, item in enumerate(items):
            sev_colour = {
                "Critical": ACCENT_RED,
                "High": "#ff8844",
                "Medium": ACCENT_AMBER,
                "Low": ACCENT_BLUE,
            }.get(item.severity, ACCENT_BLUE)

            with st.container():
                st.markdown(
                    f"""<div class="glass-card" style="border-left: 4px solid {sev_colour}; padding: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <strong style="color: {sev_colour};">[{item.severity}]</strong>
                            &nbsp; {item.finding_title}
                        </div>
                        <div style="color: {TEXT_MUTED}; font-size: 0.8rem;">
                            {item.item_id} &nbsp;|&nbsp; Owner: {item.owner} &nbsp;|&nbsp;
                            Due: {item.due_date} &nbsp;|&nbsp; Ticket: {item.ticket_ref or 'N/A'}
                        </div>
                    </div>
                </div>""",
                    unsafe_allow_html=True,
                )

                col1, col2, col3 = st.columns([2.2, 2.2, 5.6])
                with col1:
                    if st.button(
                        "✅ Approve", key=f"approve_{item.item_id}_{idx}"
                    ):
                        self._update_item_status(
                            item.item_id, "approved"
                        )
                        st.rerun()
                with col2:
                    if st.button(
                        "❌ Reject", key=f"reject_{item.item_id}_{idx}"
                    ):
                        self._update_item_status(
                            item.item_id, "rejected"
                        )
                        st.rerun()

    def render_implementation_tracking(
        self, items: List[WorkflowItem]
    ) -> None:
        """Render Kanban-style implementation tracking (Path A — Step 2)."""
        st.markdown("### 📊 Implementation Tracking")

        statuses = {
            "pending_approval": ("⏳ Pending", "#666"),
            "approved": ("✅ Approved", ACCENT_BLUE),
            "in_progress": ("🔄 In Progress", ACCENT_AMBER),
            "completed": ("✔️ Completed", ACCENT_GREEN),
            "rejected": ("❌ Rejected", ACCENT_RED),
        }

        cols = st.columns(len(statuses))

        for col, (status_key, (label, colour)) in zip(cols, statuses.items()):
            with col:
                st.markdown(
                    f'<div style="text-align: center; color: {colour}; '
                    f'font-weight: 700; margin-bottom: 12px;">{label}</div>',
                    unsafe_allow_html=True,
                )

                matching = [it for it in items if it.status == status_key]
                if not matching:
                    st.markdown(
                        f'<div style="text-align: center; color: {TEXT_MUTED}; '
                        f'font-size: 0.8rem;">No items</div>',
                        unsafe_allow_html=True,
                    )
                for it in matching:
                    sev_c = {
                        "Critical": ACCENT_RED,
                        "High": "#ff8844",
                        "Medium": ACCENT_AMBER,
                        "Low": ACCENT_BLUE,
                    }.get(it.severity, ACCENT_BLUE)
                    st.markdown(
                        f"""<div class="glass-card" style="padding: 10px; margin-bottom: 8px;">
                        <div style="font-size: 0.75rem; color: {sev_c}; font-weight: 600;">
                            [{it.severity}]
                        </div>
                        <div style="font-size: 0.85rem; margin-top: 4px;">
                            {it.finding_title[:50]}{'...' if len(it.finding_title) > 50 else ''}
                        </div>
                        <div style="font-size: 0.7rem; color: {TEXT_MUTED}; margin-top: 4px;">
                            {it.owner} — {it.due_date}
                        </div>
                    </div>""",
                        unsafe_allow_html=True,
                    )

    def render_analytics(self, items: List[WorkflowItem]) -> None:
        """Render velocity, SLA compliance, and MTTR charts (Path A — Step 3)."""
        st.markdown("### 📈 Remediation Analytics")

        if not items:
            st.info("No workflow items to analyse.")
            return

        total = len(items)
        completed = sum(1 for it in items if it.status == "completed")
        approved = sum(1 for it in items if it.status == "approved")
        in_progress = sum(1 for it in items if it.status == "in_progress")
        rejected = sum(1 for it in items if it.status == "rejected")
        pending = sum(1 for it in items if it.status == "pending_approval")

        # Summary cards
        cols = st.columns(5)
        cards = [
            ("Total Items", str(total), ACCENT_BLUE),
            ("Completed", str(completed), ACCENT_GREEN),
            ("In Progress", str(in_progress + approved), ACCENT_AMBER),
            ("Pending", str(pending), TEXT_SECONDARY),
            ("Rejected", str(rejected), ACCENT_RED),
        ]
        for col, (label, val, colour) in zip(cols, cards):
            with col:
                st.markdown(
                    render_metric_card(label, val, colour=colour),
                    unsafe_allow_html=True,
                )

        # SLA compliance
        st.markdown("#### SLA Compliance")
        sla_met = sum(
            1
            for it in items
            if it.status in ("completed", "in_progress", "approved")
        )
        sla_pct = int((sla_met / total) * 100) if total > 0 else 0
        st.progress(sla_pct / 100, text=f"SLA Compliance: {sla_pct}%")

        # Severity distribution
        st.markdown("#### Severity Distribution")
        import plotly.express as px
        import pandas as pd

        sev_data = pd.DataFrame(
            [{"severity": it.severity} for it in items]
        )
        if not sev_data.empty:
            fig = px.pie(
                sev_data,
                names="severity",
                color="severity",
                color_discrete_map={
                    "Critical": ACCENT_RED,
                    "High": "#ff8844",
                    "Medium": ACCENT_AMBER,
                    "Low": ACCENT_BLUE,
                    "Info": TEXT_MUTED,
                },
                hole=0.4,
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e8e8e8",
                height=300,
                margin=dict(t=20, b=20, l=20, r=20),
            )
            st.plotly_chart(fig, use_container_width=True)

    # ── Path B: AI Auto-Remediate ────────────────────────────────────────

    def render_pre_action_assessment(
        self, outcome: RemediationOutcome
    ) -> None:
        """Render the pre-action impact assessment (amber-bordered card)."""
        st.markdown("### ⚠️ Pre-Action Impact Assessment")

        # Amber-bordered assessment card
        st.markdown(
            f"""<div class="hitl-gate">
            <div class="title">🔍 AI Auto-Remediation — Pre-Action Assessment</div>
            <p style="color: {TEXT_SECONDARY}; font-size: 0.9rem;">
                Review the projected impact before authorising AI-driven remediation.
                All actions are logged and auditable.
            </p>
        </div>""",
            unsafe_allow_html=True,
        )

        # Summary
        st.markdown(f"**Summary:** {outcome.summary}")

        # Actions table
        if outcome.actions_taken:
            st.markdown("#### Planned Actions")
            for i, action in enumerate(outcome.actions_taken):
                blast_colour = {
                    "Low": ACCENT_GREEN,
                    "Medium": ACCENT_AMBER,
                    "High": ACCENT_RED,
                }.get(action.blast_radius, ACCENT_AMBER)

                st.markdown(
                    f"""<div class="glass-card" style="padding: 12px; border-left: 3px solid {blast_colour};">
                    <div style="display: flex; justify-content: space-between;">
                        <strong>{action.action_type}</strong>
                        <span style="color: {blast_colour}; font-size: 0.8rem; font-weight: 600;">
                            Blast Radius: {action.blast_radius}
                        </span>
                    </div>
                    <div style="margin-top: 6px; font-size: 0.85rem; color: {TEXT_SECONDARY};">
                        Target: {action.target_object} via {action.target_tool}<br/>
                        Endpoint: <code>{action.api_endpoint}</code><br/>
                        Reversible: {'✅ Yes' if action.reversible else '❌ No'}<br/>
                        {f'Impact: {action.blast_description}' if action.blast_description else ''}
                    </div>
                </div>""",
                    unsafe_allow_html=True,
                )

        # KPI impact projection
        if outcome.kpi_impact:
            st.markdown("#### Projected KPI Impact")
            import pandas as pd

            kpi_df = pd.DataFrame(
                [
                    {
                        "KPI": k.kpi_name,
                        "Before": k.before_value,
                        "After": k.after_value,
                        "Delta %": f"{k.delta_pct:+.1f}%",
                        "Direction": k.direction,
                    }
                    for k in outcome.kpi_impact
                ]
            )
            st.dataframe(kpi_df, use_container_width=True, hide_index=True)

        # Tickets
        if outcome.tickets:
            st.markdown("#### Auto-Generated Tickets")
            for ticket in outcome.tickets:
                pri_colour = {
                    "P1": ACCENT_RED,
                    "P2": ACCENT_AMBER,
                    "P3": ACCENT_BLUE,
                }.get(ticket.priority, ACCENT_BLUE)
                st.markdown(
                    f"""<div class="glass-card" style="padding: 12px;">
                    <span style="color: {pri_colour}; font-weight: 700;">[{ticket.priority}]</span>
                    &nbsp; {ticket.title}<br/>
                    <span style="font-size: 0.8rem; color: {TEXT_MUTED};">
                        Type: {ticket.ticket_type} | Team: {ticket.assignee_team} | Due: {ticket.due_date}
                        {f' | CVE: {ticket.cve_id}' if ticket.cve_id else ''}
                        {f' | CVSS: {ticket.cvss_score}' if ticket.cvss_score else ''}
                    </span>
                </div>""",
                    unsafe_allow_html=True,
                )

        # Authorise button
        st.markdown("---")
        col1, col2, col3 = st.columns([2, 2, 4])
        with col1:
            if st.button(
                "🚀 Authorise Auto-Remediation",
                key="authorise_auto_rem",
                type="primary",
            ):
                st.session_state.remediation_authorised = True
                try:
                    from app.observability.audit_logger import AuditLogger
                    logger = AuditLogger()
                    logger.log_action(
                        action="Auto-Remediation Authorized",
                        username="vaibhav",
                        status="Success",
                        target="Remediation Engine",
                        details=f"Analyst authorized AI auto-remediation plan containing {len(outcome.actions_taken)} planned actions."
                    )
                except Exception:
                    pass
                st.success(
                    "✅ Auto-remediation authorised. Execution logged to audit trail."
                )
        with col2:
            if st.button("🚫 Reject", key="reject_auto_rem"):
                st.session_state.remediation_authorised = False
                try:
                    from app.observability.audit_logger import AuditLogger
                    logger = AuditLogger()
                    logger.log_action(
                        action="Auto-Remediation Rejected",
                        username="vaibhav",
                        status="Success",
                        target="Remediation Engine",
                        details="Analyst rejected AI auto-remediation plan."
                    )
                except Exception:
                    pass
                st.warning("❌ Auto-remediation rejected by analyst.")

    def generate_mock_remediation(
        self,
        use_case: str,
        findings: List[Dict[str, Any]],
    ) -> RemediationOutcome:
        """Create demo remediation output for the given use case and findings."""
        actions: List[RemediationAction] = []
        kpi_impact: List[KPIImpactItem] = []
        tickets: List[RemediationTicketSpec] = []

        for i, finding in enumerate(findings[:5]):
            severity = finding.get("severity", "Medium")
            title = finding.get("title", f"Finding {i + 1}")
            cve_id = finding.get("id", "")

            # Action
            actions.append(
                RemediationAction(
                    action_type="PATCH" if "CVE" in cve_id else "CONFIG",
                    target_tool="Tenable.io" if use_case == "ctem" else "Splunk",
                    target_object=f"asset-{i + 1:03d}",
                    api_endpoint=f"/api/v1/remediate/{cve_id or f'item-{i}'}",
                    api_payload={"action": "apply_fix", "target": title[:50]},
                    reversible=severity != "Critical",
                    blast_radius=(
                        "High" if severity == "Critical" else
                        "Medium" if severity == "High" else "Low"
                    ),
                    blast_description=(
                        f"Affects {2 + i} production {'servers' if use_case == 'ctem' else 'rules'}."
                    ),
                )
            )

            # KPI impact
            kpi_impact.append(
                KPIImpactItem(
                    kpi_name=f"{'Vuln' if use_case == 'ctem' else 'Detection'} Exposure Score",
                    before_value=f"{85 - i * 5}%",
                    after_value=f"{70 - i * 5}%",
                    delta_pct=-(15.0 + i * 2),
                    direction="improved",
                )
            )

            # Ticket
            sla_days = {"Critical": 3, "High": 7, "Medium": 14, "Low": 30}.get(
                severity, 14
            )
            tickets.append(
                RemediationTicketSpec(
                    title=f"Remediate: {title[:80]}",
                    description=finding.get(
                        "description", "AI-generated remediation ticket."
                    ),
                    ticket_type="vulnerability" if use_case == "ctem" else "change",
                    use_case=use_case,
                    priority=(
                        "P1" if severity == "Critical" else
                        "P2" if severity == "High" else "P3"
                    ),
                    severity=severity,
                    assignee_team=[
                        "Security Engineering",
                        "Platform Team",
                        "DevOps",
                        "Application Security",
                        "Cloud Infrastructure",
                    ][i % 5],
                    due_date=(
                        datetime.now() + timedelta(days=sla_days)
                    ).strftime("%Y-%m-%d"),
                    cvss_score=finding.get("cvss_score"),
                    cve_id=cve_id if "CVE" in cve_id else None,
                    technique_id=finding.get("technique_id"),
                    ai_confidence=finding.get("ai_confidence", 78),
                    remediation_steps=finding.get(
                        "recommendation", "Apply recommended fix."
                    ).split(". ") if isinstance(finding.get("recommendation"), str) else [],
                    tool_source="synthetic",
                )
            )

        return RemediationOutcome(
            summary=(
                f"AI auto-remediation plan for {use_case.upper()} — "
                f"{len(actions)} actions planned across {len(tickets)} tickets. "
                f"Projected reduction in exposure score across all affected KPIs. "
                f"All actions are reversible where blast radius permits."
            ),
            actions_taken=actions,
            kpi_impact=kpi_impact,
            tickets=tickets,
        )

    # ── Internal helpers ─────────────────────────────────────────────────

    def _update_item_status(self, item_id: str, new_status: str) -> None:
        """Update status of a workflow item in session state."""
        items = st.session_state.get("workflow_items", [])
        finding_title = ""
        severity = ""
        for item in items:
            if item.get("item_id") == item_id:
                item["status"] = new_status
                item.setdefault("audit_entries", []).append(
                    f"{datetime.now().isoformat()} — Status changed to {new_status}"
                )
                finding_title = item.get("finding_title", "")
                severity = item.get("severity", "")
                break
        st.session_state.workflow_items = items
        
        # Log to AuditLogger
        try:
            from app.observability.audit_logger import AuditLogger
            logger = AuditLogger()
            logger.log_action(
                action=f"Workflow Status Change: {new_status.title()}",
                username="vaibhav",
                status="Success",
                target=item_id,
                details=f"HITL Decision: Finding '{finding_title}' ({severity}) status updated to {new_status}."
            )
        except Exception:
            pass
