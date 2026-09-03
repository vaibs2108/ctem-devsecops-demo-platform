"""
SyntheticDataEngine — High-fidelity enterprise security synthetic data generator.
Generates all 8 enterprise-grade datasets required for the CTEM and DevSecOps use cases.
AGENTS.md Section 10.1 & 10.2.
"""
from __future__ import annotations

import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class SyntheticDataEngine:
    """Generates all 8 enterprise-grade security datasets.
    
    Includes realistic hostnames, CVE IDs, MITRE ATT&CK techniques, 
    and RAG/EPSS properties. Uses NumPy vectorisation for speed.
    """

    def __init__(self, seed: Optional[int] = 42) -> None:
        self.seed = seed
        if seed is not None:
            np.random.seed(seed)
        self.datasets: Dict[str, pd.DataFrame] = {}

    def generate_all(self) -> Dict[str, pd.DataFrame]:
        """Generate all 8 datasets and store them."""
        logger.info("Generating all 8 enterprise security datasets...")

        # 1. CTEM
        assets = self.generate_asset_inventory()
        findings = self.generate_vulnerability_findings(assets)
        backlog = self.generate_reremedial_backlog(findings)
        validations = self.generate_validation_results(findings)

        # 2. DevSecOps
        commits = self.generate_code_commits()
        review_findings = self.generate_code_review_findings(commits)
        pull_requests = self.generate_pull_requests(review_findings)
        validation_results = self.generate_security_validation_results(pull_requests)

        self.datasets = {
            "asset_inventory": assets,
            "vulnerability_findings": findings,
            "remediation_backlog": backlog,
            "validation_results": validations,
            "code_commits": commits,
            "code_review_findings": review_findings,
            "pull_requests": pull_requests,
            "security_validation_results": validation_results,
        }
        logger.info("Successfully generated all 8 datasets.")
        return self.datasets

    # ── 1. CTEM Datasets ─────────────────────────────────────────────────────

    def generate_asset_inventory(self, count: int = 500) -> pd.DataFrame:
        classes = ["Server", "Workstation", "Network", "Cloud", "Container", "IoT"]
        class_probs = [0.3, 0.4, 0.05, 0.1, 0.1, 0.05]
        envs = ["Production", "Staging", "Dev", "DR"]
        env_probs = [0.5, 0.25, 0.2, 0.05]
        teams = ["DevOps", "FinSec", "CloudPlatform", "SecOps", "CoreEngineering", "Analytics"]
        os_options = ["Ubuntu 22.04", "Windows Server 2022", "CentOS Stream 9", "macOS Sonoma", "Alpine Linux", "Cisco IOS"]
        criticalities = ["Critical", "High", "Medium", "Low"]
        crit_probs = [0.15, 0.25, 0.4, 0.2]

        data = []
        for i in range(count):
            asset_id = f"AST-{1000 + i}"
            a_class = np.random.choice(classes, p=class_probs)
            env = np.random.choice(envs, p=env_probs)
            team = np.random.choice(teams)
            
            # Hostnames
            suffix = f"{i:03d}"
            if a_class == "Server":
                hostname = f"{np.random.choice(['web', 'db', 'app'])}-{env.lower()[:3]}-{suffix}"
            elif a_class == "Container":
                hostname = f"pod-{np.random.choice(['api', 'worker'])}-{suffix}"
            elif a_class == "Workstation":
                hostname = f"usr-{np.random.choice(['eng', 'fin', 'ops'])}-{suffix}"
            else:
                hostname = f"net-{np.random.choice(['rt', 'sw', 'fw'])}-{suffix}"

            ip = f"10.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 254)}"
            os_val = np.random.choice(os_options)
            crit = np.random.choice(criticalities, p=crit_probs)
            exposed = bool(np.random.rand() < (0.35 if a_class in ["Server", "Cloud"] else 0.05))
            scan_date = (datetime.now() - timedelta(days=int(np.random.randint(0, 30)))).strftime("%Y-%m-%d")
            sbom = bool(np.random.rand() < 0.7)

            data.append({
                "asset_id": asset_id,
                "hostname": hostname,
                "asset_class": a_class,
                "environment": env,
                "owner_team": team,
                "ip_address": ip,
                "os": os_val,
                "business_criticality": crit,
                "internet_exposed": exposed,
                "last_scan_date": scan_date,
                "sbom_available": sbom,
            })
        return pd.DataFrame(data)

    def generate_vulnerability_findings(self, assets_df: pd.DataFrame, count: int = 1000) -> pd.DataFrame:
        cves = [
            ("CVE-2023-44487", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "CWE-400", "HTTP/2 Rapid Reset"),
            ("CVE-2024-3094", 10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CWE-506", "XZ Utils Backdoor"),
            ("CVE-2023-38545", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-119", "SOCKS5 Heap Buffer Overflow"),
            ("CVE-2023-22809", 7.8, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "CWE-269", "Sudo Privilege Escalation"),
            ("CVE-2024-21626", 8.6, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", "CWE-200", "runc File Descriptor Leak"),
            ("CVE-2023-32629", 7.8, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "CWE-269", "OverlayFS Local Privilege Escalation"),
            ("CVE-2023-49103", 10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CWE-306", "ownCloud Credential Leak"),
            ("CVE-2023-46604", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-502", "ActiveMQ Deserialisation RCE"),
        ]
        
        statuses = ["Open", "In Progress", "Patched", "Accepted Risk"]
        status_probs = [0.6, 0.2, 0.15, 0.05]

        data = []
        asset_ids = assets_df["asset_id"].values
        for i in range(count):
            vuln_id = f"VUL-{10000 + i}"
            asset_id = np.random.choice(asset_ids)
            cve = cves[np.random.randint(len(cves))]
            
            cve_id, cvss, vector, cwe, component = cve
            epss = np.random.beta(1, 8)  # skewed towards lower scores
            kisa_kev = bool(np.random.rand() < 0.15)  # 15% CISA KEV collision
            
            # Elevate EPSS and CVSS if CISA KEV
            if kisa_kev:
                epss = max(epss, np.random.uniform(0.7, 0.99))
            
            exploit_avail = bool(np.random.rand() < 0.4)
            is_fp = bool(np.random.rand() < 0.2)  # 20% false positive rate
            exploit_confirmed = False if is_fp else bool(np.random.rand() < 0.6)
            
            patch_avail = bool(np.random.rand() < 0.85)
            patch_ver = f"v{np.random.randint(1, 5)}.{np.random.randint(0, 10)}.{np.random.randint(1, 20)}" if patch_avail else "N/A"
            status = np.random.choice(statuses, p=status_probs)

            # Risk score calculation
            # Max score = 100. Weighted by CVSS, business criticality, internet exposure, KEV
            asset_row = assets_df[assets_df["asset_id"] == asset_id].iloc[0]
            crit_val = {"Critical": 1.5, "High": 1.25, "Medium": 1.0, "Low": 0.8}[asset_row["business_criticality"]]
            exposure_val = 1.4 if asset_row["internet_exposed"] else 0.8
            kev_val = 1.5 if kisa_kev else 1.0
            
            risk_score = round(min(100.0, cvss * 6.5 * crit_val * exposure_val * kev_val * (0.0 if is_fp else 1.0)), 1)

            data.append({
                "vuln_id": vuln_id,
                "asset_id": asset_id,
                "cve_id": cve_id,
                "cvss_score": cvss,
                "cvss_vector": vector,
                "cwe_id": cwe,
                "affected_component": component,
                "exploit_available": exploit_avail,
                "exploitability_confirmed": exploit_confirmed,
                "false_positive": is_fp,
                "cisa_kev": kisa_kev,
                "epss_score": round(epss, 4),
                "patch_available": patch_avail,
                "patch_version": patch_ver,
                "status": status,
                "risk_score": risk_score,
            })
        return pd.DataFrame(data)

    def generate_reremedial_backlog(self, findings_df: pd.DataFrame) -> pd.DataFrame:
        data = []
        open_findings = findings_df[findings_df["status"].isin(["Open", "In Progress"])]
        
        for idx, row in open_findings.iterrows():
            item_id = f"REM-{2000 + idx}"
            vuln_id = row["vuln_id"]
            asset_id = row["asset_id"]
            
            # Risk-ranked priority
            score = row["risk_score"]
            if score >= 75.0:
                priority = "P1"
                days_to_breach = int(np.random.randint(-2, 5))
            elif score >= 45.0:
                priority = "P2"
                days_to_breach = int(np.random.randint(5, 20))
            else:
                priority = "P3"
                days_to_breach = int(np.random.randint(20, 60))

            rem_type = np.random.choice(["PATCH", "CONFIG", "UPGRADE", "REPLACE"])
            
            # Remediation commands
            comp = row["affected_component"]
            if rem_type == "PATCH":
                steps = f"1. apt-get update && apt-get install --only-upgrade {comp.lower().replace(' ', '_')}\n2. systemctl restart {comp.lower().replace(' ', '_')}"
            elif rem_type == "CONFIG":
                steps = f"1. Edit configuration file at /etc/{comp.lower().replace(' ', '_')}/config.conf\n2. Set enable_secure_mode=true\n3. Reload configuration."
            else:
                steps = f"1. Pull latest Docker container image for {comp.lower().replace(' ', '_')}\n2. Redeploy stack in swarm."

            assigned = np.random.choice(["SecOps-Tier1", "CloudPlatform-Eng", "PlatformDev-Dev", "LinuxAdmins"])
            due_date = (datetime.now() + timedelta(days=days_to_breach)).strftime("%Y-%m-%d")
            
            data.append({
                "item_id": item_id,
                "vuln_id": vuln_id,
                "asset_id": asset_id,
                "priority": priority,
                "remediation_type": rem_type,
                "reremediation_steps": steps,
                "assigned_owner": assigned,
                "due_date": due_date,
                "status": "In Progress" if row["status"] == "In Progress" else "Todo",
                "kev_collision": row["cisa_kev"],
                "days_to_sla_breach": days_to_breach,
                "ticket_ref": f"JIRA-{np.random.randint(10000, 99999)}",
            })
        return pd.DataFrame(data)

    def generate_validation_results(self, findings_df: pd.DataFrame) -> pd.DataFrame:
        data = []
        tested_findings = findings_df.sample(frac=0.4, random_state=42)
        
        reasons = [
            "Compensating firewall rule active, port closed externally",
            "Signature payload blocked by local Endpoint Agent",
            "Vulnerable code path not reachable due to wrapper sanitisation",
            "Operating System version mismatch for active exploit payload",
        ]

        for idx, row in tested_findings.iterrows():
            val_id = f"VAL-{3000 + idx}"
            is_fp = row["false_positive"]
            
            exploit_confirmed = not is_fp and bool(np.random.rand() < 0.85)
            reason = "Exploit completed and reverse shell established on test container." if exploit_confirmed else np.random.choice(reasons)
            if is_fp:
                reason = "Scanner signature misidentified library version. Compensating patch verified."
            
            exp_score = round(np.random.uniform(0.1, 0.95), 2)
            tester = np.random.choice(["AI-BAS-Agent", "Sentinel-Scanner", "RedTeam-Validator"])
            val_date = (datetime.now() - timedelta(days=int(np.random.randint(0, 10)))).strftime("%Y-%m-%d")
            conf = int(np.random.randint(40, 100))

            data.append({
                "validation_id": val_id,
                "vuln_id": row["vuln_id"],
                "sandbox_tested": True,
                "exploit_confirmed": exploit_confirmed,
                "false_positive_reason": reason,
                "exploitability_score": exp_score,
                "validated_by": tester,
                "validation_date": val_date,
                "confidence": conf,
            })
        return pd.DataFrame(data)

    # ── 2. DevSecOps Datasets ─────────────────────────────────────────────────

    def generate_code_commits(self, count: int = 150) -> pd.DataFrame:
        repos = ["platform-api", "billing-service", "web-frontend", "auth-service", "data-pipeline"]
        authors = ["a.sharma", "j.chen", "m.okafor", "r.silva", "svc-ci-bot"]
        branches = ["feature/user-search", "fix/billing-timeout", "feature/oauth-refresh", "chore/deps-bump", "hotfix/login-redirect"]
        messages = [
            "Add user search endpoint",
            "Fix billing webhook timeout handling",
            "Refresh OAuth token rotation logic",
            "Bump third-party dependencies",
            "Patch login redirect open-redirect issue",
        ]

        data = []
        for i in range(count):
            commit_sha = f"{np.random.randint(0x1000000, 0x7fffffff):08x}"
            repo = repos[i % len(repos)]
            branch = branches[i % len(branches)]
            author = np.random.choice(authors)
            files_changed = int(np.random.randint(1, 12))
            commit_time = (datetime.now() - timedelta(hours=int(np.random.randint(0, 720)))).isoformat()

            data.append({
                "commit_sha": commit_sha,
                "repo": repo,
                "branch": branch,
                "author": author,
                "commit_message": messages[i % len(messages)],
                "files_changed": files_changed,
                "timestamp": commit_time,
            })
        return pd.DataFrame(data)

    def generate_code_review_findings(self, commits_df: pd.DataFrame, count: int = 250) -> pd.DataFrame:
        finding_templates = [
            {"finding_type": "SQL Injection", "severity": "Critical", "cwe": "CWE-89", "file": "app/api/routes/users.py", "line": 47, "description": "User-supplied input concatenated directly into a raw SQL string.", "snippet": "query = \"SELECT * FROM users WHERE username = '\" + username + \"'\""},
            {"finding_type": "Hardcoded Secret", "severity": "Critical", "cwe": "CWE-798", "file": "app/config/settings.py", "line": 12, "description": "Cloud provider secret access key committed in plaintext.", "snippet": "AWS_SECRET_ACCESS_KEY = \"AKIA...REDACTED...\""},
            {"finding_type": "Vulnerable Package", "severity": "High", "cwe": "CVE-2018-18074", "file": "requirements.txt", "line": 9, "description": "Pinned dependency version has a known credential-leak-on-redirect vulnerability.", "snippet": "requests==2.6.0"},
            {"finding_type": "SQL Injection", "severity": "High", "cwe": "CWE-89", "file": "app/api/routes/billing.py", "line": 88, "description": "Dynamic query built via f-string interpolation of the invoice_id parameter.", "snippet": "cursor.execute(f\"SELECT * FROM invoices WHERE id={invoice_id}\")"},
            {"finding_type": "Hardcoded Secret", "severity": "High", "cwe": "CWE-798", "file": "app/services/notify.py", "line": 21, "description": "Third-party API key hardcoded instead of read from the secrets manager.", "snippet": "SLACK_WEBHOOK_TOKEN = \"xoxb-REDACTED\""},
            {"finding_type": "Vulnerable Package", "severity": "Medium", "cwe": "CVE-2023-30861", "file": "package.json", "line": 15, "description": "Frontend dependency vulnerable to cookie leakage across sessions.", "snippet": "\"flask\": \"2.2.2\""},
        ]

        data = []
        commit_shas = commits_df["commit_sha"].values
        for i in range(count):
            tmpl = finding_templates[i % len(finding_templates)]
            commit_sha = np.random.choice(commit_shas)

            data.append({
                "finding_id": f"DSO-{2000 + i}",
                "commit_sha": commit_sha,
                "finding_type": tmpl["finding_type"],
                "severity": tmpl["severity"],
                "cwe": tmpl["cwe"],
                "file": tmpl["file"],
                "line": tmpl["line"],
                "description": tmpl["description"],
                "snippet": tmpl["snippet"],
                "auto_fix_available": bool(np.random.rand() < 0.85),
            })
        return pd.DataFrame(data)

    def generate_pull_requests(self, review_df: pd.DataFrame, count: int = 150) -> pd.DataFrame:
        statuses = ["Approved", "Merged", "Open", "Rejected"]
        status_probs = [0.35, 0.4, 0.15, 0.1]

        data = []
        finding_ids = review_df["finding_id"].values
        for i in range(count):
            pr_number = 1000 + i
            linked_finding = np.random.choice(finding_ids)
            status = np.random.choice(statuses, p=status_probs)

            data.append({
                "pr_number": pr_number,
                "finding_id": linked_finding,
                "title": f"fix(security): auto-generated remediation for {linked_finding}",
                "branch": f"ai/fix-{linked_finding.lower()}",
                "status": status,
                "fix_summary": "Parameterised the vulnerable query and added a regression test." if i % 3 == 0 else "Replaced hardcoded credential with environment-sourced secret." if i % 3 == 1 else "Bumped vulnerable dependency to the patched release.",
                "created_date": (datetime.now() - timedelta(hours=int(np.random.randint(0, 240)))).isoformat(),
            })
        return pd.DataFrame(data)

    def generate_security_validation_results(self, prs_df: pd.DataFrame, count: int = 300) -> pd.DataFrame:
        checks = ["SQL injection regression test", "Secret scan (gitleaks)", "Dependency audit", "Unit test suite", "SAST scan"]

        data = []
        pr_numbers = prs_df["pr_number"].values
        for i in range(count):
            check_name = checks[i % len(checks)]
            status = np.random.choice(["Passed", "Failed"], p=[0.92, 0.08])

            data.append({
                "check_id": f"VAL-{5000 + i}",
                "pr_number": np.random.choice(pr_numbers),
                "check_name": check_name,
                "status": status,
                "details": f"{check_name} completed — {'no issues found' if status == 'Passed' else 'regression detected, review required'}.",
            })
        return pd.DataFrame(data)


# Backwards compatibility stub for typo in Prompt
class SyntheticDataEngineWithTypo(SyntheticDataEngine):
    def generate_remediation_backlog(self, findings_df: pd.DataFrame) -> pd.DataFrame:
        return self.generate_reremedial_backlog(findings_df)

# Assign a method mapping so that either spelling works
SyntheticDataEngine.generate_reremedial_backlog = SyntheticDataEngine.generate_reremedial_backlog  # type: ignore[assignment]
SyntheticDataEngine.generate_remediation_backlog = SyntheticDataEngine.generate_reremedial_backlog  # type: ignore[assignment]
