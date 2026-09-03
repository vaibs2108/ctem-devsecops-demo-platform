"""
AI Capability Demo — MCP Tool Registry
Catalogues all security tools + Jira + ServiceNow with their capabilities,
endpoints, and expected schemas for Path A / Path B integrations.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class MCPToolMetadata(BaseModel):
    """Metadata representing a single security tool integration in the MCP registry."""
    name: str = Field(..., description="Unique tool name (e.g. tenable_io, github)")
    display_name: str = Field(..., description="User-friendly display name (e.g. Tenable.io)")
    category: str = Field(..., description="CTEM|DevSecOps|Remediation")
    description: str = Field(..., description="Short explanation of what the tool does")
    capabilities: List[str] = Field(default_factory=list, description="Supported operations: read_assets, read_vulns, execute_scan, isolate_host, write_ticket, etc.")
    endpoints: Dict[str, str] = Field(default_factory=dict, description="Resource paths mapped to logical actions")
    required_env_vars: List[str] = Field(default_factory=list, description="Variables needed in .env to activate live mode")

class MCPToolRegistry:
    """Main registry for tool configuration and validation."""
    
    def __init__(self) -> None:
        self.tools: Dict[str, MCPToolMetadata] = {}
        self._load_default_registry()

    def get_tool(self, name: str) -> Optional[MCPToolMetadata]:
        """Retrieve tool metadata by identifier."""
        return self.tools.get(name.lower())

    def get_tools_by_category(self, category: str) -> List[MCPToolMetadata]:
        """Retrieve all tools belonging to a specific capability category."""
        return [t for t in self.tools.values() if t.category.lower() == category.lower()]

    def is_live_capable(self, name: str, env_dict: dict) -> bool:
        """Check if all required env vars are present to run a tool in live mode."""
        tool = self.get_tool(name)
        if not tool:
            return False
        if not tool.required_env_vars:
            return False
        return all(env_dict.get(var) for var in tool.required_env_vars)

    def _load_default_registry(self) -> None:
        """Populate the registry with the enterprise-grade tools."""
        
        # ── CTEM TOOLS ────────────────────────────────────────────────────────
        self.tools["tenable_io"] = MCPToolMetadata(
            name="tenable_io",
            display_name="Tenable.io",
            category="CTEM",
            description="Vulnerability management and continuous exposure tracking.",
            capabilities=["read_assets", "read_vulns", "execute_scan"],
            endpoints={
                "get_assets": "/assets",
                "get_vulns": "/vulns",
                "trigger_scan": "/scans/launch"
            },
            required_env_vars=["TENABLE_API_KEY", "TENABLE_SECRET_KEY"]
        )
        
        self.tools["qualys_vmdr"] = MCPToolMetadata(
            name="qualys_vmdr",
            display_name="Qualys VMDR",
            category="CTEM",
            description="Vulnerability Management, Detection, and Response platform.",
            capabilities=["read_assets", "read_vulns", "execute_scan"],
            endpoints={
                "get_assets": "/api/2.0/fo/asset/host",
                "get_vulns": "/api/2.0/fo/vuln",
                "trigger_scan": "/api/2.0/fo/scan"
            },
            required_env_vars=["QUALYS_USERNAME", "QUALYS_PASSWORD"]
        )

        self.tools["wiz"] = MCPToolMetadata(
            name="wiz",
            display_name="Wiz",
            category="CTEM",
            description="Cloud security posture management (CSPM) and exposure scanning.",
            capabilities=["read_assets", "read_vulns", "read_compliance"],
            endpoints={
                "get_assets": "/graphql",
                "get_vulns": "/graphql",
                "get_compliance": "/graphql"
            },
            required_env_vars=["WIZ_CLIENT_ID", "WIZ_CLIENT_SECRET"]
        )

        self.tools["prisma_cloud"] = MCPToolMetadata(
            name="prisma_cloud",
            display_name="Prisma Cloud",
            category="CTEM",
            description="Cloud-native security and compliance analysis.",
            capabilities=["read_assets", "read_vulns", "read_compliance"],
            endpoints={
                "get_assets": "/v2/inventory",
                "get_vulns": "/v2/alert",
                "get_compliance": "/v2/compliance"
            },
            required_env_vars=["PRISMA_ACCESS_KEY", "PRISMA_SECRET_KEY"]
        )

        self.tools["aws_security_hub"] = MCPToolMetadata(
            name="aws_security_hub",
            display_name="AWS Security Hub",
            category="CTEM",
            description="Aggregated security alerts and compliance checks for AWS environment.",
            capabilities=["read_assets", "read_vulns"],
            endpoints={
                "get_assets": "/findings",
                "get_vulns": "/findings"
            },
            required_env_vars=["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
        )

        self.tools["snyk"] = MCPToolMetadata(
            name="snyk",
            display_name="Snyk",
            category="CTEM",
            description="Developer security platform for code, dependencies, containers, and IaC.",
            capabilities=["read_assets", "read_vulns"],
            endpoints={
                "get_assets": "/v1/orgs/{org_id}/projects",
                "get_vulns": "/v1/orgs/{org_id}/project/{project_id}/issues"
            },
            required_env_vars=["SNYK_TOKEN"]
        )

        # ── DEVSECOPS TOOLS ────────────────────────────────────────────────────
        self.tools["github"] = MCPToolMetadata(
            name="github",
            display_name="GitHub",
            category="DevSecOps",
            description="Source control, pull requests, and CI/CD workflow integration.",
            capabilities=["read_commits", "write_pr", "read_pr", "write_check"],
            endpoints={
                "get_commits": "/repos/{owner}/{repo}/commits",
                "create_pr": "/repos/{owner}/{repo}/pulls",
                "create_check_run": "/repos/{owner}/{repo}/check-runs"
            },
            required_env_vars=["GITHUB_TOKEN"]
        )

        self.tools["gitlab"] = MCPToolMetadata(
            name="gitlab",
            display_name="GitLab",
            category="DevSecOps",
            description="Source control, merge requests, and CI/CD pipeline integration.",
            capabilities=["read_commits", "write_pr", "read_pr", "write_check"],
            endpoints={
                "get_commits": "/projects/{id}/repository/commits",
                "create_mr": "/projects/{id}/merge_requests",
                "create_pipeline": "/projects/{id}/pipeline"
            },
            required_env_vars=["GITLAB_TOKEN"]
        )

        self.tools["semgrep"] = MCPToolMetadata(
            name="semgrep",
            display_name="Semgrep",
            category="DevSecOps",
            description="Static application security testing (SAST) — code-pattern vulnerability scanning.",
            capabilities=["execute_scan", "read_vulns"],
            endpoints={
                "trigger_scan": "/api/v1/scans",
                "get_findings": "/api/v1/scans/{scan_id}/findings"
            },
            required_env_vars=["SEMGREP_APP_TOKEN"]
        )

        self.tools["sonarqube"] = MCPToolMetadata(
            name="sonarqube",
            display_name="SonarQube",
            category="DevSecOps",
            description="Code quality and security analysis with quality-gate enforcement.",
            capabilities=["execute_scan", "read_vulns"],
            endpoints={
                "trigger_scan": "/api/ce/submit",
                "get_issues": "/api/issues/search"
            },
            required_env_vars=["SONARQUBE_URL", "SONARQUBE_TOKEN"]
        )

        # ── REMEDIATION / TICKETING TOOLS ─────────────────────────────────────
        self.tools["jira"] = MCPToolMetadata(
            name="jira",
            display_name="Jira",
            category="Remediation",
            description="Atlassian workflow management and issue tracking system.",
            capabilities=["write_ticket", "get_ticket"],
            endpoints={
                "create_issue": "/rest/api/2/issue",
                "get_issue": "/rest/api/2/issue/{issue_key}"
            },
            required_env_vars=["JIRA_URL", "JIRA_USERNAME", "JIRA_API_TOKEN"]
        )

        self.tools["servicenow"] = MCPToolMetadata(
            name="servicenow",
            display_name="ServiceNow",
            category="Remediation",
            description="Enterprise IT service management and incident tracking.",
            capabilities=["write_ticket", "get_ticket"],
            endpoints={
                "create_incident": "/api/now/table/incident",
                "get_incident": "/api/now/table/incident/{sys_id}"
            },
            required_env_vars=["SERVICENOW_INSTANCE", "SERVICENOW_USERNAME", "SERVICENOW_PASSWORD"]
        )
