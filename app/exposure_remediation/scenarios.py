"""
Curated, fact-checked scenarios for the Exposure Remediation use case.

CVE ids, CVSS vectors, fixed versions and mitigation guidance are real (checked against
NVD, CISA KEV and vendor advisories). The customer environment (hosts, services, owners,
change numbers) is fictional. KEV/EPSS values are a snapshot; live_intel can refresh them.

Each scenario is the *ground truth* handed to the AI (minus the "sim" block) and the source
for the deterministic fallback payload builders at the bottom of this module.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

SCENARIO_ORDER = ["A", "B", "C"]
_PROMPT_STRIP = ("sim", "expected")
_SLA_HOURS = {"P1": 24, "P2": 72, "P3": 240, "P4": 720}


# ── helpers ───────────────────────────────────────────────────────────────────

def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def priority_label(score: int) -> str:
    if score >= 85:
        return "P1 - Critical"
    if score >= 65:
        return "P2 - High"
    if score >= 40:
        return "P3 - Medium"
    return "P4 - Low"


def sla_hours(label: str) -> int:
    return _SLA_HOURS[label[:2]]


def contextual_score(cvss: float, adjustments: List[int]) -> int:
    return int(max(0, min(100, round(cvss * 5) + sum(adjustments))))


def _now_utc(now: Optional[datetime]) -> datetime:
    base = now or datetime.now(timezone.utc)
    return base.replace(microsecond=0, tzinfo=timezone.utc) if base.tzinfo is None else base.replace(microsecond=0)


# ── scenario A: clean patch -> verified closure ──────────────────────────────

def _scenario_a(now: datetime) -> Dict[str, Any]:
    win_start = now.replace(minute=0, second=0) + timedelta(hours=2)
    return {
        "id": "A",
        "label": "A - Patch available: clean closure",
        "tagline": "Internet-facing Confluence, vendor fix available. Patch, rescan, verified closure.",
        "expected_outcome": "reduced_verified",
        "cycle": 1,
        "confidence": 93,
        "default_constraints": ["maintenance_window_only"],
        "signal": {
            "signal_id": f"EXP-{now:%y%m%d}-0042",
            "source": "Vulnerability scanner (authenticated)",
            "scan_id": "SCN-88213",
            "detected_at": _iso(now - timedelta(hours=3)),
            "cve": "CVE-2023-22515",
            "title": "Atlassian Confluence Data Center and Server - broken access control (unauthenticated admin account creation)",
            "scanner_severity": "Critical",
            "cvss": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "installed_version": "8.4.1",
            "port": 8090,
            "protocol": "tcp",
            "evidence_output": "Confluence 8.4.1 identified from the login page banner and /status endpoint. Affected: 8.0.0-8.5.1. Fixed in 8.3.3, 8.4.3 and 8.5.2.",
            "solution": "Upgrade to 8.3.3, 8.4.3, 8.5.2 or later. Restrict external access / block /setup/* if upgrade is not possible.",
        },
        "asset": {
            "asset_id": "AST-9001", "hostname": "cfl-prod-01", "fqdn": "kb.corp.example",
            "ip_address": "10.42.18.21", "public_ip": "203.0.113.47",
            "os": "Ubuntu 22.04.4 LTS", "environment": "Production",
            "location": "AWS eu-west-1 / vpc-0b7e41 / dmz-a",
            "internet_exposed": True, "exposure_via": "Internet-facing ALB (alb-kb-prod) -> TCP 8090",
            "owner_team": "Collaboration Platform",
            "edr": {"installed": True, "healthy": True},
            "waf": "No WAF rule set attached to this listener",
        },
        "service": {
            "service_id": "SVC-KB-001", "name": "Engineering Knowledge Base", "tier": "Tier 2",
            "regulatory_scope": ["ISO 27001"], "data_classification": "Confidential",
            "users": "4,200 employees", "dependents": ["Corporate SSO", "Issue tracker (app link)", "Search indexer"],
            "rto_hours": 8, "owner": "Collaboration Platform", "on_call": "collab-oncall", "change_freeze": None,
        },
        "identity": {
            "account": "svc-confluence-db", "type": "Service account",
            "privilege": "db_owner on PostgreSQL cfl_prod",
            "credential_exposure": "Database credentials stored in confluence.cfg.xml (readable by the application user)",
            "impact": "A forged admin account gives full space access plus stored app-link tokens and database credentials.",
        },
        "threat": {
            "kev": True, "kev_date_added": "2023-10-05", "ransomware_use": "Known",
            "epss": 0.99223, "epss_percentile": 0.99937, "epss_as_of": "2026-10-23",
            "exploit_maturity": "Weaponised - active exploitation reported",
            "attack_technique": "T1190 Exploit Public-Facing Application",
            "intel_sources": ["CISA KEV", "FIRST EPSS", "Vendor advisory"], "live": False,
        },
        "exposure_path": [
            {"asset": "Internet", "technique_or_cve": "T1190", "note": "Unauthenticated request to /setup/setupadministrator.action"},
            {"asset": "alb-kb-prod", "technique_or_cve": "No WAF rule", "note": "Forwards TCP 8090 straight to the host"},
            {"asset": "cfl-prod-01", "technique_or_cve": "CVE-2023-22515", "note": "Creates a Confluence administrator account"},
            {"asset": "svc-confluence-db", "technique_or_cve": "T1552.001", "note": "DB credentials in confluence.cfg.xml"},
            {"asset": "PostgreSQL cfl_prod", "technique_or_cve": "T1005", "note": "All spaces, attachments, app-link tokens"},
        ],
        "blast_radius": [
            "All spaces and attachments (Confidential)",
            "Stored app-link tokens to the issue tracker",
            "PostgreSQL cfl_prod via the service account",
            "SSO handoff configuration",
        ],
        "priority_factors": [
            {"factor": "Active exploitation (CISA KEV)", "impact": 18, "evidence": "Listed in KEV since 2023-10-05; ransomware use: Known"},
            {"factor": "Internet exposure", "impact": 14, "evidence": "Reachable through an internet-facing ALB, no WAF on the listener"},
            {"factor": "Identity blast radius", "impact": 8, "evidence": "DB service account with db_owner; credentials in a readable config file"},
            {"factor": "EPSS", "impact": 5, "evidence": "EPSS 0.992 (99.9th percentile)"},
            {"factor": "Business criticality", "impact": 2, "evidence": "Tier 2 knowledge base holding Confidential data"},
            {"factor": "Compensating controls", "impact": 0, "evidence": "None effective: EDR is healthy but does not block this request pattern"},
        ],
        "peers": [
            {"id": "EXP-peer-1", "cve": "CVE-2024-3094", "title": "xz backdoor in build image", "asset": "bld-dev-017 (dev build container)",
             "cvss": 10.0, "kev": False, "adjust": -38, "note": "Not internet exposed, not in KEV, vulnerable build never deployed"},
            {"id": "EXP-peer-2", "cve": "CVE-2023-38545", "title": "curl SOCKS5 heap overflow", "asset": "ci-runner-04 (isolated CI runner)",
             "cvss": 9.8, "kev": False, "adjust": -29, "note": "No inbound path, not in KEV, ephemeral runner"},
            {"id": "EXP-peer-3", "cve": "CVE-2023-44487", "title": "HTTP/2 Rapid Reset", "asset": "api-gw-prod (internet exposed)",
             "cvss": 7.5, "kev": True, "adjust": 22, "note": "In KEV and exposed, but absorbed by the CDN tier"},
        ],
        "options": [
            {"id": "opt-1", "type": "patch", "title": "Upgrade Confluence 8.4.1 to 8.4.3 (same release train)",
             "risk_reduction_pct": 100, "change_risk": "Low-Medium", "downtime": "~12 min", "effort": "Small (automated)",
             "prerequisites": ["Database snapshot", "Home directory backup", "Emergency window"],
             "tradeoff": "Removes the vulnerable code and keeps plugin compatibility within the 8.4 train.", "recommended": True},
            {"id": "opt-2", "type": "compensating_control", "title": "Block /setup/* at the ALB/WAF and restrict source ranges",
             "risk_reduction_pct": 80, "change_risk": "Low", "downtime": "None", "effort": "Small",
             "prerequisites": ["WAF rule set on the listener"],
             "tradeoff": "Stops the known attack path but the vulnerable code stays; the vendor says this is not a replacement for upgrading."},
            {"id": "opt-3", "type": "patch", "title": "Upgrade to 8.5.2 LTS",
             "risk_reduction_pct": 100, "change_risk": "Medium", "downtime": "~25 min", "effort": "Medium (plugin regression testing)",
             "prerequisites": ["Plugin compatibility matrix", "Staging validation"],
             "tradeoff": "Longer support runway, but a larger regression surface inside an emergency window."},
            {"id": "opt-4", "type": "exception", "title": "Risk acceptance with expiry",
             "risk_reduction_pct": 0, "change_risk": "None", "downtime": "None", "effort": "Paperwork",
             "prerequisites": [], "tradeoff": "Not viable: internet-exposed, KEV-listed and ransomware-associated.",
             "not_viable": "Policy blocks risk acceptance for internet-exposed KEV findings"},
        ],
        "recommended_option": "opt-1",
        "change_package": {
            "title": "Upgrade Confluence on cfl-prod-01 to 8.4.3 (CVE-2023-22515)",
            "change_type": "Emergency", "owner_team": "Collaboration Platform",
            "approver_role": "Security Lead + Service Owner",
            "risk_assessment": "Low-Medium. In-place upgrade within one release train, with a database snapshot, home backup and a tested rollback.",
            "evidence": [
                "Scanner finding with installed version 8.4.1 (affected range 8.0.0-8.5.1)",
                "CISA KEV listing (2023-10-05), ransomware use: Known",
                "Reachable from the internet through alb-kb-prod without a WAF rule",
            ],
            "mitigation_steps": [
                "Snapshot cfl_prod and back up the Confluence home directory",
                "Stop Confluence, run the 8.4.3 installer unattended, start Confluence",
                "Check confluence-administrators for unexpected members (IoC review)",
                "Verify version 8.4.3 and trigger a verification rescan",
            ],
            "rollback_plan": "Restore the home directory archive and the database snapshot, then start the previous 8.4.1 service. Estimated 20 minutes.",
            "maintenance_window": {"label": "Emergency window tonight", "start": _iso(win_start), "end": _iso(win_start + timedelta(minutes=90))},
            "validation_criteria": ["Version reports 8.4.3", "Verification rescan no longer reports CVE-2023-22515", "No unexpected administrator accounts"],
        },
        "sim": {
            "host": {
                "hostname": "cfl-prod-01",
                "packages": {"confluence": "8.4.1"},
                "services": {"confluence": "running"},
                "rules": [], "artifacts": [],
                "users": {"confluence-administrators": ["a.rao", "k.mensah", "svc-confluence-adm"]},
            },
            "vuln_check": {"type": "version_by_train", "package": "confluence", "cve": "CVE-2023-22515",
                           "min_affected": "8.0.0", "fixed_trains": {"8.3": "8.3.3", "8.4": "8.4.3", "8.5": "8.5.2"},
                           "method": "Authenticated scan: package inventory + /status version probe"},
            "change": {"change_id": "CHG0043127", "short_description": "Emergency: upgrade Confluence cfl-prod-01 to 8.4.3 (CVE-2023-22515)",
                       "assignment_group": "Collaboration Platform", "cab": "Emergency CAB (e-approval)"},
            "tasks": [
                {"name": "Gathering Facts", "module": "setup"},
                {"name": "Pre-check: installed Confluence version is in the affected range", "module": "assert", "effect": {"assert_version": ["confluence", "<", "8.4.3"]}},
                {"name": "Snapshot database cfl_prod (pg_dump)", "module": "postgresql_db", "changed": True},
                {"name": "Back up Confluence home directory", "module": "archive", "changed": True},
                {"name": "Stop confluence service", "module": "service", "changed": True, "effect": {"service": ["confluence", "stopped"]}},
                {"name": "Download atlassian-confluence-8.4.3 installer and verify SHA-256", "module": "get_url", "changed": True},
                {"name": "Run installer in unattended mode (upgrade to 8.4.3)", "module": "command", "changed": True, "effect": {"package": ["confluence", "8.4.3"]}},
                {"name": "Start confluence service", "module": "service", "changed": True, "effect": {"service": ["confluence", "running"]}},
                {"name": "Wait for /status to report RUNNING", "module": "uri"},
                {"name": "IoC check: confluence-administrators membership unchanged", "module": "command"},
                {"name": "Post-check: Confluence version is 8.4.3", "module": "assert", "effect": {"assert_version": ["confluence", "==", "8.4.3"]}},
            ],
        },
    }


# ── scenario B: no patch window -> compensating control, residual risk ───────

def _scenario_b(now: datetime) -> Dict[str, Any]:
    freeze_end = (now + timedelta(days=10)).replace(hour=6, minute=0, second=0)
    hotfix_day = (freeze_end + timedelta(days=1)).replace(hour=3, minute=0, second=0)
    win_start = now.replace(minute=0, second=0) + timedelta(hours=1)
    return {
        "id": "B",
        "label": "B - Patch blocked: compensating control",
        "tagline": "Perimeter firewall under a change freeze. Mitigate now, patch later, accept visible residual risk.",
        "expected_outcome": "reduced_residual",
        "cycle": 1,
        "confidence": 90,
        "default_constraints": ["change_freeze", "maintenance_window_only"],
        "signal": {
            "signal_id": f"EXP-{now:%y%m%d}-0057",
            "source": "Vulnerability scanner (authenticated)",
            "scan_id": "SCN-88219",
            "detected_at": _iso(now - timedelta(hours=2)),
            "cve": "CVE-2024-3400",
            "title": "Palo Alto Networks PAN-OS GlobalProtect - command injection (unauthenticated RCE as root)",
            "scanner_severity": "Critical",
            "cvss": 10.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "installed_version": "10.2.6-h1",
            "port": 443,
            "protocol": "tcp",
            "evidence_output": "PAN-OS 10.2.6-h1 with a GlobalProtect portal enabled. Fixed in 10.2.6-h3 or later.",
            "solution": "Upgrade to a fixed hotfix for the release train. Until then enable Threat Prevention IDs 95187, 95189 and 95191 with a Vulnerability Protection profile on the GlobalProtect interface.",
        },
        "asset": {
            "asset_id": "AST-9002", "hostname": "pa-fw-edge-02", "fqdn": "vpn.corp.example",
            "ip_address": "10.10.0.12", "public_ip": "203.0.113.10",
            "os": "PAN-OS 10.2.6-h1", "environment": "Production",
            "location": "DC-LON-1 / edge HA pair (active node)",
            "internet_exposed": True, "exposure_via": "GlobalProtect portal and gateway on TCP 443",
            "owner_team": "Network Security",
            "edr": {"installed": False, "healthy": False},
            "waf": "Not applicable (perimeter firewall)",
        },
        "service": {
            "service_id": "SVC-VPN-001", "name": "Remote Access VPN (GlobalProtect)", "tier": "Tier 1",
            "regulatory_scope": ["PCI DSS 4.0 (access path to CDE jump hosts)", "ISO 27001"], "data_classification": "Restricted",
            "users": "9,800 remote users", "dependents": ["Corporate SSO (SAML)", "CDE jump hosts", "Remote workforce"],
            "rto_hours": 1, "owner": "Network Security", "on_call": "netsec-oncall",
            "change_freeze": {"label": "Quarter-end finance close freeze", "start": _iso(now - timedelta(days=1)), "end": _iso(freeze_end),
                              "policy": "Disruptive changes need a CAB exception; non-disruptive security configuration is permitted"},
        },
        "identity": {
            "account": "svc-ldap-bind + device credentials", "type": "Service and device credentials",
            "privilege": "Root on the firewall after exploitation",
            "credential_exposure": "LDAP bind credentials, VPN certificate private keys and IKE pre-shared keys stored on the device",
            "impact": "Root on the perimeter exposes VPN keys and gives a pivot into the VLAN that hosts the CDE jump hosts.",
        },
        "threat": {
            "kev": True, "kev_date_added": "2024-04-12", "ransomware_use": "Known",
            "epss": 0.99999, "epss_percentile": 1.0, "epss_as_of": "2026-10-23",
            "exploit_maturity": "Weaponised - public PoC and mass exploitation",
            "attack_technique": "T1190 Exploit Public-Facing Application",
            "intel_sources": ["CISA KEV", "FIRST EPSS", "Vendor advisory"], "live": False,
        },
        "exposure_path": [
            {"asset": "Internet", "technique_or_cve": "T1190", "note": "Crafted request to the GlobalProtect portal"},
            {"asset": "pa-fw-edge-02", "technique_or_cve": "CVE-2024-3400", "note": "Command injection, root shell on the firewall"},
            {"asset": "VPN keys + svc-ldap-bind", "technique_or_cve": "T1552", "note": "Credentials and certificates stored on device"},
            {"asset": "CDE jump hosts (VLAN 210)", "technique_or_cve": "T1021", "note": "Lateral movement via remote services"},
        ],
        "blast_radius": [
            "9,800 remote users' VPN sessions and certificates",
            "LDAP bind credentials used for authentication",
            "CDE jump hosts on VLAN 210 (PCI DSS scope)",
        ],
        "priority_factors": [
            {"factor": "Active exploitation (CISA KEV)", "impact": 18, "evidence": "Listed in KEV since 2024-04-12; ransomware use: Known"},
            {"factor": "Internet exposure", "impact": 15, "evidence": "GlobalProtect portal listens on the public interface"},
            {"factor": "Identity blast radius", "impact": 8, "evidence": "Root on firewall exposes VPN keys and LDAP bind credentials"},
            {"factor": "EPSS", "impact": 5, "evidence": "EPSS 0.99999 (100th percentile)"},
            {"factor": "Business criticality", "impact": 4, "evidence": "Tier 1 remote access, path to PCI-scoped jump hosts"},
            {"factor": "Compensating controls", "impact": 0, "evidence": "None currently applied; no EDR on appliance"},
        ],
        "peers": [
            {"id": "EXP-peer-1", "cve": "CVE-2024-6387", "title": "OpenSSH regreSSHion", "asset": "bastion-eu-01 (internet exposed)",
             "cvss": 8.1, "kev": False, "adjust": 14, "note": "Exposed, but not in KEV and the LoginGraceTime workaround is in place"},
            {"id": "EXP-peer-2", "cve": "CVE-2023-46604", "title": "Apache ActiveMQ deserialisation RCE", "asset": "mq-prod-02 (internal only)",
             "cvss": 9.8, "kev": True, "adjust": 6, "note": "In KEV, but segmented and not reachable from the internet"},
            {"id": "EXP-peer-3", "cve": "CVE-2024-3094", "title": "xz backdoor in build image", "asset": "bld-dev-017 (dev build container)",
             "cvss": 10.0, "kev": False, "adjust": -38, "note": "Not internet exposed, not in KEV, vulnerable build never deployed"},
        ],
        "options": [
            {"id": "opt-1", "type": "compensating_control",
             "title": "Enable Threat IDs 95187/95189/95191 and attach a Vulnerability Protection profile to the GlobalProtect interface",
             "risk_reduction_pct": 85, "change_risk": "Low", "downtime": "None", "effort": "Small",
             "prerequisites": ["Applications and Threats content 8836-8695 or later", "Vulnerability Protection profile on the GP interface (signatures do not apply without it)", "Commit and HA sync"],
             "tradeoff": "Immediate, non-disruptive and permitted during the freeze. The vulnerable code remains, so the vendor still advises upgrading. Disabling telemetry is no longer an effective mitigation.",
             "recommended": True},
            {"id": "opt-2", "type": "patch", "title": "Upgrade to PAN-OS 10.2.6-h3 (HA failover)",
             "risk_reduction_pct": 100, "change_risk": "Medium", "downtime": "2-4 min failover, ~15 min per node", "effort": "Medium",
             "prerequisites": ["HA peer in sync", "CAB exception for the freeze", "Config backup"],
             "tradeoff": "Removes the vulnerability but is a disruptive change inside the quarter-end freeze.",
             "blocked_reason": "Quarter-end change freeze; needs a CAB exception"},
            {"id": "opt-3", "type": "config", "title": "Disable the GlobalProtect portal and gateway",
             "risk_reduction_pct": 100, "change_risk": "High", "downtime": "Full remote-access outage", "effort": "Small",
             "prerequisites": [], "tradeoff": "Closes the exposure but cuts access for 9,800 users.",
             "not_viable": "Tier 1 service with a 1 hour RTO"},
            {"id": "opt-4", "type": "exception", "title": "Risk acceptance with expiry",
             "risk_reduction_pct": 0, "change_risk": "None", "downtime": "None", "effort": "Paperwork",
             "prerequisites": [], "tradeoff": "Not viable: internet-exposed, KEV-listed, root-level RCE.",
             "not_viable": "Policy blocks risk acceptance for internet-exposed KEV findings"},
        ],
        "recommended_option": "opt-1",
        "change_package": {
            "title": "Apply Threat Prevention signatures and GlobalProtect protection profile on pa-fw-edge-02 (CVE-2024-3400)",
            "change_type": "Normal (expedited CAB)", "owner_team": "Network Security",
            "approver_role": "Head of Network Security + CAB chair",
            "risk_assessment": "Low. Configuration-only change, no reboot or failover. Residual risk remains until the hotfix is installed.",
            "evidence": [
                "Scanner finding: PAN-OS 10.2.6-h1 with GlobalProtect enabled (fixed in 10.2.6-h3)",
                "CISA KEV listing (2024-04-12), ransomware use: Known",
                "Change freeze policy permits non-disruptive security configuration",
            ],
            "mitigation_steps": [
                "Install Applications and Threats content 8836-8695 or later",
                "Enable Threat IDs 95187, 95189 and 95191 with a blocking action",
                "Attach a Vulnerability Protection profile to the GlobalProtect interface",
                "Commit, confirm HA sync, then replay a non-destructive detection probe",
                f"Raise follow-up change for hotfix 10.2.6-h3 on {hotfix_day:%Y-%m-%d} 03:00 UTC",
            ],
            "rollback_plan": "Revert the candidate configuration to the pre-change commit and re-sync the HA peer. Estimated 5 minutes.",
            "maintenance_window": {"label": "Standard window (no downtime)", "start": _iso(win_start), "end": _iso(win_start + timedelta(minutes=45))},
            "validation_criteria": ["Threat IDs 95187/95189/95191 active", "Vulnerability Protection profile bound to the GP interface", "Detection probe is blocked", "Hotfix change scheduled after the freeze"],
            "followup": {"label": "Hotfix 10.2.6-h3", "scheduled_for": _iso(hotfix_day)},
        },
        "sim": {
            "host": {
                "hostname": "pa-fw-edge-02",
                "packages": {"panos": "10.2.6-h1"},
                "services": {"globalprotect": "running"},
                "rules": [], "artifacts": [], "content_version": "8801-8613",
            },
            "vuln_check": {"type": "version_by_train_with_mitigation", "package": "panos", "cve": "CVE-2024-3400",
                           "fixed": {"10.2.0": "h3", "10.2.1": "h2", "10.2.2": "h5", "10.2.3": "h13", "10.2.4": "h16",
                                     "10.2.5": "h6", "10.2.6": "h3", "10.2.7": "h8", "10.2.8": "h3", "10.2.9": "h1"},
                           "mitigation_rules": ["threat-95187", "vp-profile-gp"],
                           "method": "Authenticated scan + non-destructive detection probe against the GlobalProtect portal"},
            "change": {"change_id": "CHG0043158", "short_description": "Expedited: mitigate CVE-2024-3400 on pa-fw-edge-02 (Threat Prevention + VP profile)",
                       "assignment_group": "Network Security", "cab": "Expedited CAB"},
            "tasks": [
                {"name": "Gathering Facts", "module": "setup"},
                {"name": "Pre-check: HA peer is in sync", "module": "panos_op"},
                {"name": "Pre-check: PAN-OS version is affected and no mitigation is present", "module": "assert", "effect": {"assert_version": ["panos", "<", "10.2.6-h3"]}},
                {"name": "Install Applications and Threats content 8836-8695", "module": "panos_content", "changed": True, "effect": {"content_version": "8836-8695"}},
                {"name": "Enable Threat IDs 95187, 95189, 95191 (action: reset-both)", "module": "panos_security_profile", "changed": True,
                 "effect": {"rule": ["threat-95187", "threat-95189", "threat-95191"]}},
                {"name": "Attach Vulnerability Protection profile to the GlobalProtect interface", "module": "panos_interface", "changed": True, "effect": {"rule": ["vp-profile-gp"]}},
                {"name": "Commit candidate configuration", "module": "panos_commit", "changed": True},
                {"name": "Verify HA peer configuration sync", "module": "panos_op"},
                {"name": "Safe probe: replay CVE-2024-3400 detection payload (non-destructive)", "module": "uri"},
            ],
        },
    }


# ── scenario C: rescan still vulnerable -> ticket closed != exposure reduced ──

def _scenario_c(now: datetime) -> Dict[str, Any]:
    win_start = now.replace(minute=0, second=0) + timedelta(hours=1)
    return {
        "id": "C",
        "label": "C - Rescan fails: closure blocked",
        "tagline": "Payments API. The change is implemented, the ticket would close, but the exposure is still there.",
        "expected_outcome": "blocked_still_present",
        "cycle": 1,
        "confidence": 88,
        "default_constraints": ["maintenance_window_only", "rollback_required"],
        "signal": {
            "signal_id": f"EXP-{now:%y%m%d}-0063",
            "source": "Package inventory agent",
            "scan_id": "SCN-88224",
            "detected_at": _iso(now - timedelta(hours=5)),
            "cve": "CVE-2021-44228",
            "title": "Apache Log4j2 JNDI remote code execution (Log4Shell) in the payments-api classpath",
            "scanner_severity": "Critical",
            "cvss": 10.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "installed_version": "log4j-core 2.14.1",
            "port": 8443,
            "protocol": "tcp",
            "evidence_output": "Inventory reports /opt/payments-api/lib/log4j-core-2.14.1.jar. Note: /opt/payments-api/lib/reporting-engine-3.2.jar is a third-party fat jar whose nested dependencies are not inventoried.",
            "solution": "Upgrade log4j-core to a fixed release (2.17.1 for Java 8+). Check shaded and nested copies.",
        },
        "asset": {
            "asset_id": "AST-9003", "hostname": "pay-api-prod-03", "fqdn": "api.pay.corp.example",
            "ip_address": "10.60.4.33", "public_ip": "203.0.113.88",
            "os": "Ubuntu 22.04.4 LTS", "environment": "Production",
            "location": "AWS eu-west-1 / vpc-0c19aa / app-b",
            "internet_exposed": True, "exposure_via": "Public API gateway (api-gw-prod) -> NLB -> TCP 8443",
            "owner_team": "Payments Engineering",
            "edr": {"installed": True, "healthy": True},
            "waf": "API gateway WAF attached; Log4j managed rule set not enabled on this stage",
        },
        "service": {
            "service_id": "SVC-PAY-001", "name": "Payments API", "tier": "Tier 1",
            "regulatory_scope": ["PCI DSS 4.0", "SOX"], "data_classification": "Restricted",
            "users": "~380k API requests per hour", "dependents": ["Checkout", "Settlement batch", "Fraud scoring"],
            "rto_hours": 1, "owner": "Payments Engineering", "on_call": "payments-oncall", "change_freeze": None,
        },
        "identity": {
            "account": "svc-payments-api (cloud role payments-api-prod-role)", "type": "Workload identity",
            "privilege": "Read/write on the settlement bucket; decrypt with the card-token KMS key",
            "credential_exposure": "Role credentials reachable from the instance metadata service",
            "impact": "Code execution as the app user yields cloud role credentials: settlement files and token decryption.",
        },
        "threat": {
            "kev": True, "kev_date_added": "2021-12-10", "ransomware_use": "Known",
            "epss": 0.99999, "epss_percentile": 1.0, "epss_as_of": "2026-10-23",
            "exploit_maturity": "Weaponised - commodity tooling and mass exploitation",
            "attack_technique": "T1190 Exploit Public-Facing Application",
            "intel_sources": ["CISA KEV", "FIRST EPSS", "Vendor advisory"], "live": False,
        },
        "exposure_path": [
            {"asset": "Internet", "technique_or_cve": "T1190", "note": "JNDI string in a logged request header"},
            {"asset": "api-gw-prod", "technique_or_cve": "WAF rule set off", "note": "Log4j managed rules not enabled on this stage"},
            {"asset": "pay-api-prod-03", "technique_or_cve": "CVE-2021-44228", "note": "log4j-core resolves the lookup, remote code runs"},
            {"asset": "payments-api-prod-role", "technique_or_cve": "T1552.005", "note": "Cloud credentials from the metadata service"},
            {"asset": "Settlement bucket + KMS token key", "technique_or_cve": "T1530", "note": "Data from cloud storage, token decryption"},
        ],
        "blast_radius": [
            "Settlement files in the settlement bucket",
            "Card-token KMS key decryption (PCI scope)",
            "Checkout, settlement and fraud-scoring dependants",
        ],
        "priority_factors": [
            {"factor": "Active exploitation (CISA KEV)", "impact": 18, "evidence": "Listed in KEV since 2021-12-10; ransomware use: Known"},
            {"factor": "Internet exposure", "impact": 14, "evidence": "Reachable through the public API gateway and NLB"},
            {"factor": "Identity blast radius", "impact": 10, "evidence": "Cloud role with settlement bucket and card-token key access"},
            {"factor": "EPSS", "impact": 5, "evidence": "EPSS 0.99999 (100th percentile)"},
            {"factor": "Business criticality", "impact": 5, "evidence": "Tier 1, PCI DSS and SOX scope"},
            {"factor": "Compensating controls", "impact": 0, "evidence": "WAF Log4j rule set not enabled; no egress filtering for LDAP/RMI"},
        ],
        "peers": [
            {"id": "EXP-peer-1", "cve": "CVE-2021-3156", "title": "sudo heap overflow (Baron Samedit)", "asset": "ops-jump-02 (internal)",
             "cvss": 7.8, "kev": True, "adjust": -4, "note": "Local access required, MFA-protected jump host"},
            {"id": "EXP-peer-2", "cve": "CVE-2023-49103", "title": "ownCloud graphapi credential disclosure", "asset": "owncloud-dev-02 (dev VLAN)",
             "cvss": 10.0, "kev": True, "adjust": -34, "note": "In KEV, but the instance is dev-only, unreachable from the internet and holds no real data"},
            {"id": "EXP-peer-3", "cve": "CVE-2023-22809", "title": "sudoedit privilege escalation", "asset": "app-stg-02 (staging)",
             "cvss": 7.8, "kev": False, "adjust": -12, "note": "Staging only, not in KEV"},
        ],
        "options": [
            {"id": "opt-1", "type": "patch",
             "title": "Upgrade log4j-core and log4j-api to 2.17.1 in /opt/payments-api/lib and restart",
             "risk_reduction_pct": 100, "change_risk": "Low-Medium", "downtime": "Rolling, no customer impact", "effort": "Small (automated)",
             "prerequisites": ["Lib directory backup", "Drain node from the gateway pool", "Emergency window"],
             "tradeoff": "Fixes every copy the inventory knows about. Risk flagged: reporting-engine-3.2.jar is a third-party fat jar whose nested dependencies are unverified, so a deep archive scan is part of the validation.",
             "recommended": True},
            {"id": "opt-2", "type": "compensating_control",
             "title": "Enable the API gateway Log4j WAF rule set and deny outbound LDAP/RMI (389, 636, 1099) from the app subnet",
             "risk_reduction_pct": 70, "change_risk": "Low", "downtime": "None", "effort": "Small",
             "prerequisites": ["WAF rule set available", "Egress security group change"],
             "tradeoff": "Blocks common JNDI callbacks and exfiltration paths, but the vulnerable code stays."},
            {"id": "opt-3", "type": "config", "title": "Set -Dlog4j2.formatMsgNoLookups=true",
             "risk_reduction_pct": 40, "change_risk": "Low", "downtime": "Restart", "effort": "Small",
             "prerequisites": [], "tradeoff": "Partial and version dependent. A stop-gap, not a fix."},
            {"id": "opt-4", "type": "exception", "title": "Risk acceptance with expiry",
             "risk_reduction_pct": 0, "change_risk": "None", "downtime": "None", "effort": "Paperwork",
             "prerequisites": [], "tradeoff": "Not viable: internet-exposed, KEV-listed, PCI scope.",
             "not_viable": "Policy blocks risk acceptance for internet-exposed KEV findings"},
        ],
        "recommended_option": "opt-1",
        "change_package": {
            "title": "Upgrade log4j-core/log4j-api to 2.17.1 on pay-api-prod-03 (CVE-2021-44228)",
            "change_type": "Emergency", "owner_team": "Payments Engineering",
            "approver_role": "Security Lead + Payments Engineering Manager",
            "risk_assessment": "Low-Medium. Library swap and rolling restart. Known gap: the third-party reporting-engine fat jar cannot be edited in place.",
            "evidence": [
                "Inventory finding: log4j-core 2.14.1 in /opt/payments-api/lib (affected: 2.0-beta9 to 2.15.0)",
                "CISA KEV listing (2021-12-10), ransomware use: Known",
                "Reachable from the internet; cloud role with PCI-scoped key access",
            ],
            "mitigation_steps": [
                "Back up /opt/payments-api/lib and drain the node from the gateway pool",
                "Replace log4j-core and log4j-api 2.14.1 with 2.17.1, restart the service",
                "Run health checks and return the node to the pool",
                "Validate with an authenticated scan that inspects nested archives",
            ],
            "rollback_plan": "Restore the lib directory backup and restart payments-api. Estimated 10 minutes.",
            "maintenance_window": {"label": "Emergency window (rolling)", "start": _iso(win_start), "end": _iso(win_start + timedelta(minutes=60))},
            "validation_criteria": ["No log4j-core below 2.17.1 on the classpath", "Deep scan includes nested archives (fat jars)", "Health check green"],
        },
        "sim": {
            "host": {
                "hostname": "pay-api-prod-03",
                "packages": {}, "services": {"payments-api": "running"},
                "rules": [],
                "artifacts": [
                    "/opt/payments-api/lib/log4j-core-2.14.1.jar",
                    "/opt/payments-api/lib/log4j-api-2.14.1.jar",
                    "/opt/payments-api/lib/reporting-engine-3.2.jar",
                    "/opt/payments-api/lib/reporting-engine-3.2.jar!/BOOT-INF/lib/log4j-core-2.14.1.jar",
                ],
            },
            "vuln_check": {"type": "artifact_scan", "cve": "CVE-2021-44228", "pattern": r"log4j-core-(\d+(?:\.\d+)*)\.jar$",
                           "fixed_version": "2.17.1",
                           "method": "Authenticated scan with nested archive (fat jar) inspection"},
            "change": {"change_id": "CHG0043190", "short_description": "Emergency: upgrade log4j to 2.17.1 on pay-api-prod-03 (CVE-2021-44228)",
                       "assignment_group": "Payments Engineering", "cab": "Emergency CAB (e-approval)"},
            "tasks": [
                {"name": "Gathering Facts", "module": "setup"},
                {"name": "Pre-check: top-level classpath contains log4j-core below 2.17.1", "module": "find"},
                {"name": "Back up /opt/payments-api/lib", "module": "archive", "changed": True},
                {"name": "Drain node from the gateway target pool", "module": "elb_target", "changed": True},
                {"name": "Stop payments-api service", "module": "service", "changed": True, "effect": {"service": ["payments-api", "stopped"]}},
                {"name": "Replace log4j-core-2.14.1.jar with log4j-core-2.17.1.jar", "module": "copy", "changed": True,
                 "effect": {"replace_artifact": ["/opt/payments-api/lib/log4j-core-2.14.1.jar", ["/opt/payments-api/lib/log4j-core-2.17.1.jar"]]}},
                {"name": "Replace log4j-api-2.14.1.jar with log4j-api-2.17.1.jar", "module": "copy", "changed": True,
                 "effect": {"replace_artifact": ["/opt/payments-api/lib/log4j-api-2.14.1.jar", ["/opt/payments-api/lib/log4j-api-2.17.1.jar"]]}},
                {"name": "Start payments-api service", "module": "service", "changed": True, "effect": {"service": ["payments-api", "running"]}},
                {"name": "Wait for /actuator/health to report UP", "module": "uri"},
                {"name": "Return node to the gateway target pool", "module": "elb_target", "changed": True},
                {"name": "Post-check: no top-level log4j-core below 2.17.1", "module": "find"},
            ],
        },
    }


_BUILDERS = {"A": _scenario_a, "B": _scenario_b, "C": _scenario_c}


def get_scenarios(now: Optional[datetime] = None) -> Dict[str, Dict[str, Any]]:
    base = _now_utc(now)
    return {key: _BUILDERS[key](base) for key in SCENARIO_ORDER}


def get_scenario(key: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    return _BUILDERS[key](_now_utc(now))


def with_live_threat(scenario: Dict[str, Any], threat: Dict[str, Any]) -> Dict[str, Any]:
    """Copy of the scenario using refreshed threat intel; keeps factor evidence text consistent with it."""
    s = copy.deepcopy(scenario)
    s["threat"] = threat
    for f in s["priority_factors"]:
        if f["factor"].startswith("Active exploitation"):
            if threat["kev"]:
                f["evidence"] = f"Listed in KEV since {threat['kev_date_added']}; ransomware use: {threat['ransomware_use']}"
            else:
                f["impact"], f["evidence"] = 0, "Not listed in CISA KEV"
        elif f["factor"] == "EPSS":
            f["evidence"] = f"EPSS {threat['epss']:.3f} ({threat['epss_percentile'] * 100:.1f}th percentile)"
    return s


def scenario_for_prompt(scenario: Dict[str, Any]) -> Dict[str, Any]:
    """Ground-truth facts for the LLM prompt (no simulator internals)."""
    return {k: copy.deepcopy(v) for k, v in scenario.items() if k not in _PROMPT_STRIP}


def raw_scanner_payload(scenario: Dict[str, Any]) -> Dict[str, Any]:
    """Scanner-shaped JSON for step 1 (vendor-neutral field names)."""
    sig, asset = scenario["signal"], scenario["asset"]
    return {
        "finding_id": sig["signal_id"],
        "scan_id": sig["scan_id"],
        "source": sig["source"],
        "state": "OPEN",
        "first_found": sig["detected_at"],
        "last_found": sig["detected_at"],
        "asset": {"id": asset["asset_id"], "hostname": asset["hostname"], "fqdn": asset["fqdn"],
                  "ipv4": asset["ip_address"], "os": asset["os"], "tags": [asset["environment"], asset["owner_team"]]},
        "vulnerability": {"cve": [sig["cve"]], "title": sig["title"], "severity": sig["scanner_severity"],
                          "cvss3_base_score": sig["cvss"], "cvss3_vector": sig["cvss_vector"], "solution": sig["solution"]},
        "port": {"port": sig["port"], "protocol": sig["protocol"]},
        "installed_version": sig["installed_version"],
        "plugin_output": sig["evidence_output"],
    }


# ── priority block (computed, so numbers always agree with the factors) ──────

def build_priority_block(scenario: Dict[str, Any]) -> Dict[str, Any]:
    sig = scenario["signal"]
    cvss = sig["cvss"]
    factors = scenario["priority_factors"]
    score = contextual_score(cvss, [f["impact"] for f in factors])
    label = priority_label(score)

    ranked: List[Dict[str, Any]] = [{"id": sig["signal_id"], "cve": sig["cve"], "asset": scenario["asset"]["hostname"],
                                     "cvss": cvss, "contextual": score, "label": label, "self": True,
                                     "note": "This exposure"}]
    for p in scenario["peers"]:
        s = contextual_score(p["cvss"], [p["adjust"]])
        ranked.append({"id": p["id"], "cve": p["cve"], "asset": p["asset"], "cvss": p["cvss"], "contextual": s,
                       "label": priority_label(s), "self": False, "note": p["note"], "kev": p.get("kev", False),
                       "title": p["title"]})
    cvss_rank = 1 + sum(1 for r in ranked if r["cvss"] > cvss)
    ctx_rank = 1 + sum(1 for r in ranked if r["contextual"] > score)
    top_cvss = max(r["cvss"] for r in ranked if not r["self"])
    outranked = [r for r in ranked if not r["self"] and r["cvss"] >= cvss and r["contextual"] < score]
    if outranked:
        lead = f"{sig['cve']} ranks #{ctx_rank} of {len(ranked)} on contextual risk even though {len(outranked)} finding(s) with equal or higher CVSS rank lower."
    else:
        lead = f"{sig['cve']} ranks #{ctx_rank} of {len(ranked)} on contextual risk (CVSS rank #{cvss_rank})."
    t, a, i, s_ = scenario["threat"], scenario["asset"], scenario["identity"], scenario["service"]
    rationale = (
        f"{lead} It is actively exploited (CISA KEV, ransomware use {t['ransomware_use']}), EPSS is {t['epss']:.3f}, "
        f"the asset is {'internet-exposed' if a['internet_exposed'] else 'internal'} via {a['exposure_via']}, and the "
        f"{s_['name']} service is {s_['tier']} ({', '.join(s_['regulatory_scope'])}). Exploitation yields {i['privilege'].lower()}, "
        f"so the blast radius is business-level, not just host-level."
    )
    if outranked:
        rationale += f" Sorting by CVSS alone would put {len(outranked)} isolated or unexploited finding(s) at or above it (top peer CVSS {top_cvss})."
    return {
        "cvss": cvss, "cvss_rank": cvss_rank, "contextual_score": score, "contextual_rank": ctx_rank,
        "priority_label": label, "sla_hours": sla_hours(label), "rationale": rationale,
        "factors": factors, "ranked": sorted(ranked, key=lambda r: -r["contextual"]), "total": len(ranked),
    }


# ── deterministic payload builders (synthetic fallback + schema completion) ───

def build_plan_payload(scenario: Dict[str, Any]) -> Dict[str, Any]:
    sig, asset, service = scenario["signal"], scenario["asset"], scenario["service"]
    pr = build_priority_block(scenario)
    rec = next(o for o in scenario["options"] if o["id"] == scenario["recommended_option"])
    cycle = scenario.get("cycle", 1)
    summary = (
        f"{sig['cve']} on {asset['hostname']} ({service['name']}) is {pr['priority_label']} with contextual score "
        f"{pr['contextual_score']}/100. Recommended: {rec['title']}. Human approval is required before execution."
    )
    ident, threat = scenario["identity"], scenario["threat"]
    insight = (
        f"{sig['cve']} on {asset['hostname']} is reachable via {asset['exposure_via']}. Exploitation yields "
        f"{ident['privilege'].lower()}, and {ident['credential_exposure'][0].lower()}{ident['credential_exposure'][1:]}. "
        f"That sits under {service['name']} ({service['tier']}, {', '.join(service['regulatory_scope'])}), and the threat "
        f"context is {threat['exploit_maturity'].lower()} with EPSS {threat['epss']:.3f}."
    )
    options = copy.deepcopy(scenario["options"])
    for opt in options:
        if opt.get("not_viable"):
            opt["ai_assessment"] = f"Not viable: {opt['not_viable']}."
        elif opt.get("blocked_reason"):
            opt["ai_assessment"] = f"Blocked: {opt['blocked_reason']}. {opt['tradeoff']}"
        else:
            opt["ai_assessment"] = opt["tradeoff"]

    from app.exposure_remediation import reference
    inputs = scenario.get("analyst_inputs") or {}
    framework_ids = inputs.get("frameworks") or reference.default_framework_ids(scenario)
    constraint_ids = inputs["constraints"] if "constraints" in inputs else scenario.get("default_constraints", [])
    conflicts = reference.constraint_conflicts(scenario, constraint_ids)
    for opt in options:
        if opt["id"] in conflicts:
            opt["constraint_conflicts"] = conflicts[opt["id"]]
            opt["ai_assessment"] += " Conflicts with the selected constraint(s): " + "; ".join(conflicts[opt["id"]]) + "."
    controls = reference.evaluate_controls(scenario, framework_ids)
    applying = [c for c in controls if c["status"] == "applies"]
    drivers = ", ".join(f"{c['framework']} {c['control_id']}" for c in applying[:5]) or "none"
    due = (threat.get("kev_record") or {}).get("dueDate")
    compliance_insight = (
        f"{len(applying)} of {len(controls)} selected controls apply to {service['name']}: {drivers}."
        + (f" The CISA KEV due date for {sig['cve']} is {due}, a reference benchmark here (binding only for US federal civilian agencies)." if due else "")
        + (" Selected constraints: " + "; ".join(c["label"] for c in reference.constraint_catalog() if c["id"] in constraint_ids) + "." if constraint_ids else "")
    )
    correlation = {
        "signal_id": sig["signal_id"], "asset": copy.deepcopy(asset), "service": copy.deepcopy(service), "identity": copy.deepcopy(ident),
        "threat": copy.deepcopy(threat), "exposure_path": copy.deepcopy(scenario["exposure_path"]),
        "blast_radius": list(scenario["blast_radius"]), "insight": insight,
    }
    return {
        "ai_confidence": scenario.get("confidence", 90),
        "summary": summary,
        "step_by_step_execution": [
            "Correlated the scanner signal with identity, business service and threat context",
            "Explained priority against peer findings, not CVSS alone",
            "Evaluated patch, configuration, compensating-control and exception paths",
            "Drafted a change package with evidence, rollback and validation criteria",
        ],
        "correlation": correlation,
        "priority": pr,
        "remediation_options": options,
        "recommended_option": scenario["recommended_option"],
        "recommended_reason": f"{rec['title']}. {rec['tradeoff']}",
        "compliance_insight": compliance_insight,
        "change_package": copy.deepcopy(scenario["change_package"]),
        "human_approval_required": True,
        "findings": [{
            "id": sig["signal_id"], "title": f"{sig['cve']} - {sig['title']}", "severity": "Critical" if pr["contextual_score"] >= 85 else "High",
            "description": pr["rationale"], "evidence": sig["evidence_output"],
            "recommendation": rec["title"], "cve_id": sig["cve"],
        }],
        "recommendations": [rec["title"]] + [f"Validate: {c}" for c in scenario["change_package"]["validation_criteria"]],
        "cycle": cycle,
    }


_VERDICTS = {
    "remediated": ("Exposure reduced and verified", "reduced_verified"),
    "mitigated": ("Exposure reduced - residual risk remains", "reduced_residual"),
    "vulnerable": ("Exposure NOT reduced - closure blocked", "blocked_still_present"),
}


def build_revalidate_payload(scenario: Dict[str, Any], facts: Dict[str, Any]) -> Dict[str, Any]:
    """facts: change_id, approver, approved_at, executed_at, rescan (dict), exposure_before, exposure_after, ticket_state."""
    sig, asset = scenario["signal"], scenario["asset"]
    rescan = facts["rescan"]
    status = rescan["status"]
    verdict, outcome = _VERDICTS[status]
    before, after = facts["exposure_before"], facts["exposure_after"]
    where = f"{asset['hostname']}"
    if status == "remediated":
        narrative = (
            f"The verification rescan of {where} no longer reports {sig['cve']}. {rescan['headline']} "
            f"Change {facts['change_id']} was approved by {facts['approver']} and implemented; the contextual exposure score "
            f"for this finding fell from {before} to {after}. The ticket can close because the exposure is gone, not because the task finished."
        )
        residual = "None identified. Keep the finding under monitoring for regression."
        next_actions = ["Close the change record with the attached evidence bundle", "Add the finding to the weekly regression rescan"]
    elif status == "mitigated":
        narrative = (
            f"{where} is still running an affected build, but the verification probe is now blocked. {rescan['headline']} "
            f"Exposure fell from {before} to {after} (not to zero). The change record closes as 'successful with residual risk' and the "
            f"fix remains open as a tracked follow-up, so the dashboard shows reduction, not elimination."
        )
        fu = scenario["change_package"].get("followup", {})
        residual = "Vulnerable code is still present; protection depends on the compensating control staying in place until the fix is installed."
        next_actions = [f"Install {fu.get('label', 'the vendor fix')} on {fu.get('scheduled_for', 'the next available window')}",
                        "Re-run the verification scan after the fix and remove the compensating control dependency",
                        "Time-box the residual risk and name an accountable owner"]
    else:
        narrative = (
            f"Change {facts['change_id']} was implemented and a conventional ITSM flow would now close the ticket. "
            f"The verification rescan of {where} still reports {sig['cve']}: {rescan['headline']} "
            f"Exposure is unchanged at {before}. Closure is blocked and the loop is re-opened with the root cause attached."
        )
        residual = "Full exposure remains: " + "; ".join(rescan.get("evidence", [])[:2])
        next_actions = ["Re-plan the remediation using the rescan evidence", "Keep the ticket open until a clean rescan"]
    return {
        "ai_confidence": scenario.get("confidence", 90),
        "summary": f"{verdict}: {sig['cve']} on {where}.",
        "verdict": verdict,
        "outcome": outcome,
        "closure_evidence": {
            "change_id": facts["change_id"], "approved_by": facts["approver"], "approved_at": facts["approved_at"],
            "executed_at": facts["executed_at"], "rescan": rescan, "exposure_before": before, "exposure_after": after,
            "ticket_state": facts["ticket_state"], "narrative": narrative,
        },
        "residual_risk": residual,
        "next_actions": next_actions,
        "findings": [{
            "id": sig["signal_id"], "title": f"{sig['cve']} revalidation: {verdict}", "severity": "Info" if status == "remediated" else "High",
            "description": narrative, "evidence": "; ".join(rescan.get("evidence", [])), "recommendation": next_actions[0], "cve_id": sig["cve"],
        }],
    }


# ── follow-up scenario (loop re-opens after a failed rescan) ──────────────────

def build_followup_scenario(scenario: Dict[str, Any], rescan: Dict[str, Any], now: Optional[datetime] = None) -> Dict[str, Any]:
    """Second pass for scenario C: same schema, residual facts, corrective change."""
    base = _now_utc(now)
    nested = [e for e in rescan.get("evidence", [])]
    s = copy.deepcopy(scenario)
    s["cycle"] = 2
    s["confidence"] = 91
    s["signal"].update({
        "signal_id": scenario["signal"]["signal_id"] + "-R1",
        "source": "Verification rescan (nested archive inspection)",
        "detected_at": rescan.get("scanned_at", _iso(base)),
        "installed_version": "log4j-core 2.14.1 (nested in reporting-engine-3.2.jar)",
        "evidence_output": "Rescan after CHG0043190: " + "; ".join(nested),
        "title": "Residual Log4Shell exposure: vulnerable log4j-core shaded inside a third-party fat jar",
    })
    s["exposure_path"][2]["note"] = "Nested log4j-core 2.14.1 inside reporting-engine-3.2.jar still resolves JNDI lookups"
    s["options"] = [
        {"id": "opt-1", "type": "patch", "title": "Replace reporting-engine-3.2.jar with the vendor build 3.2.2 (bundles log4j-core 2.17.1)",
         "risk_reduction_pct": 100, "change_risk": "Low-Medium", "downtime": "Rolling, no customer impact", "effort": "Small (automated)",
         "prerequisites": ["Vendor build 3.2.2 staged and checksum verified", "Jar backup", "Emergency window"],
         "tradeoff": "Removes the last known vulnerable copy. The first change could not edit this third-party archive in place.", "recommended": True},
        {"id": "opt-2", "type": "compensating_control", "title": "Enable the gateway Log4j WAF rule set and deny outbound LDAP/RMI from the app subnet",
         "risk_reduction_pct": 70, "change_risk": "Low", "downtime": "None", "effort": "Small", "prerequisites": ["WAF rule set available"],
         "tradeoff": "Fast interim control, but the vulnerable code stays."},
        {"id": "opt-3", "type": "exception", "title": "Risk acceptance with expiry", "risk_reduction_pct": 0, "change_risk": "None",
         "downtime": "None", "effort": "Paperwork", "prerequisites": [], "tradeoff": "Not viable for an internet-exposed KEV finding.",
         "not_viable": "Policy blocks risk acceptance for internet-exposed KEV findings"},
    ]
    s["recommended_option"] = "opt-1"
    win_start = base.replace(minute=0, second=0) + timedelta(hours=1)
    s["change_package"] = {
        "title": "Replace reporting-engine-3.2.jar with 3.2.2 on pay-api-prod-03 (residual CVE-2021-44228)",
        "change_type": "Emergency", "owner_team": "Payments Engineering",
        "approver_role": "Security Lead + Payments Engineering Manager",
        "risk_assessment": "Low-Medium. Vendor-supplied build replaces the fat jar. First change already proved the rollout path.",
        "evidence": [
            "Verification rescan after CHG0043190 found a nested log4j-core 2.14.1 in reporting-engine-3.2.jar",
            "Exposure score unchanged after the first change",
            "Vendor build 3.2.2 bundles log4j-core 2.17.1",
        ],
        "mitigation_steps": [
            "Back up reporting-engine-3.2.jar and stop payments-api on the drained node",
            "Install reporting-engine-3.2.2.jar and start the service",
            "Run health checks and return the node to the pool",
            "Re-run the authenticated deep scan including nested archives",
        ],
        "rollback_plan": "Restore the previous reporting-engine jar from backup and restart payments-api. Estimated 10 minutes.",
        "maintenance_window": {"label": "Emergency window (rolling)", "start": _iso(win_start), "end": _iso(win_start + timedelta(minutes=45))},
        "validation_criteria": ["Deep scan finds no log4j-core below 2.17.1, including nested archives", "Health check green"],
    }
    s["sim"]["change"] = {"change_id": "CHG0043204", "short_description": "Emergency: replace reporting-engine fat jar on pay-api-prod-03 (residual CVE-2021-44228)",
                          "assignment_group": "Payments Engineering", "cab": "Emergency CAB (e-approval)"}
    s["sim"]["tasks"] = [
        {"name": "Gathering Facts", "module": "setup"},
        {"name": "Pre-check: nested log4j-core below 2.17.1 present in reporting-engine-3.2.jar", "module": "find"},
        {"name": "Back up reporting-engine-3.2.jar", "module": "archive", "changed": True},
        {"name": "Drain node from the gateway target pool", "module": "elb_target", "changed": True},
        {"name": "Stop payments-api service", "module": "service", "changed": True, "effect": {"service": ["payments-api", "stopped"]}},
        {"name": "Install vendor build reporting-engine-3.2.2.jar (bundles log4j-core 2.17.1)", "module": "copy", "changed": True,
         "effect": {"replace_artifact": ["/opt/payments-api/lib/reporting-engine-3.2.jar",
                                         ["/opt/payments-api/lib/reporting-engine-3.2.2.jar",
                                          "/opt/payments-api/lib/reporting-engine-3.2.2.jar!/BOOT-INF/lib/log4j-core-2.17.1.jar"]]}},
        {"name": "Start payments-api service", "module": "service", "changed": True, "effect": {"service": ["payments-api", "running"]}},
        {"name": "Wait for /actuator/health to report UP", "module": "uri"},
        {"name": "Return node to the gateway target pool", "module": "elb_target", "changed": True},
        {"name": "Post-check: deep scan including nested archives", "module": "find"},
    ]
    return s
