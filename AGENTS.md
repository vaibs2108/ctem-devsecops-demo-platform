# CTEM & DevSecOps AI Platform — AGENTS.md
# Version: 5.0 — Complete Platform Specification
# Source of Truth for all development, AI agent prompting, and demo delivery

---

# 1. Platform Vision

**Name**: CTEM & DevSecOps AI Platform — Enterprise Security Showcase  
**Version**: Demo Phase (Pre-production) — v5.0  
**Purpose**: Demonstrate two frontier AI-led security capabilities to CXO and technical audiences. The platform functions simultaneously as a compelling executive demo and a credible enterprise production implementation blueprint.

## Two Core Capabilities

### 1. Continuous Threat Exposure Management (CTEM) — 5-Stage Lifecycle
Demonstrates the complete Gartner CTEM cycle — not just static scanner findings:
1. **Scoping**: Define external boundary, map business criticality, identify unmanaged Shadow IT assets.
2. **Discovery**: Map CVEs against assets, enrich with real-world CISA KEV and EPSS intelligence, and render **🧩 Attack Path Analysis**.
3. **Prioritisation**: Apply multi-dimensional contextual risk (Asset Criticality × Exposure × Active Telemetry) with **🔗 Vulnerability Chaining** and explicit rationale explaining why a CVSS 7.5 KEV exploit is ranked above a CVSS 9.8 isolated internal flaw.
4. **Validation**: Test network reachability and topology to isolate false positives and verify compensating controls.
5. **Mobilisation**: Generate system-specific patch commands and orchestrate automated ticketing to Jira / ServiceNow.

### 2. AI-Led DevSecOps Pipeline — 7-Step Lean Journey
Demonstrates autonomous, secure code delivery at machine speed with mandatory human-in-the-loop (HITL) control:
1. **Developer Commits Code**: Ingests repository commit metadata and code diffs.
2. **AI-Driven Code Review**: `CodeReviewAgent` flags SQL injection (CWE-89), hardcoded secrets, and vulnerable dependencies with exact file and line citations.
3. **Exploit Chain Analysis**: `ExploitAnalysisAgent` explains end-to-end exploitability in plain developer language.
4. **Fix Generation**: `FixGenerationAgent` produces a minimal, correct unified diff (e.g. parameterized query binding).
5. **Automated Pull Request Creation**: Opens structured PR with security changelog and branch tracking.
6. **Automated Security Validation**: CI gate runs automated SAST (Semgrep), Secret Detection (TruffleHog), and regression tests (PyTest).
7. **Human Approval & Deployment**: Mandatory HITL gate routes Critical/High issues to the Security Lead for sign-off before unlocking production deployment.
*Headline Outcome*: **🎯 Secure code at machine speed**.

## Core Design Principles
- **Data Flow Hierarchy**: MCP/API Live Tools (P1) → File Upload (P2) → Synthetic Data Engine (P3).
- **Synthetic Data**: Enterprise-grade in structure (2,000 assets, 5,000 findings), clearly watermarked with synthetic indicators.
- **Pure Dark Theme**: Bespoke glassmorphism design system (`#080b14` background, cyan `#00d4ff` and green `#00ff88` accents).
- **Human-in-the-Loop (HITL)**: Mandatory approval gates for high-risk actions (critical exposure remediation and production code deployment).
- **Comprehensive Observability**: Full trace logging (LangSmith SaaS), SQLite token tracking with USD budget controls, and in-app health metrics.
- **Short-Term Memory**: SQLite-backed 48-hour conversational memory for Copilot and pipeline context.

---

# 2. Technology Stack

| Layer | Technology | Rationale |
|---|---|---|
| **Frontend** | Streamlit (Python 3.11+) | Python-native, zero web framework overhead, HF Spaces / Docker ready |
| **Styling** | Vanilla CSS + Glassmorphism | Custom dark theme tokens, responsive cards, micro-animations |
| **Charts** | Plotly + Altair | Interactive radial gauges, severity distributions, and trend charts |
| **Agent Orchestration** | LangChain + LangGraph | Multi-agent execution, state tracking, and HITL interrupt gates |
| **Primary LLM** | GPT-4o-mini (OpenAI API) | 128k context, $0.15/1M input, fast response, low cost |
| **Reasoning LLM** | GPT-4o (OpenAI API) | Optional tier for complex exploit chaining and attack paths |
| **Structured Output** | Pydantic v2 | Strict schema validation for all agent responses before UI rendering |
| **Safety & Moderation** | OpenAI Moderation API | Automatic prompt injection and toxic payload filtering |
| **Vector DB** | FAISS (`faiss-cpu`) | In-memory, pure Python, zero Docker dependency for demo phase |
| **Embeddings** | `text-embedding-3-small` | Consistent OpenAI embeddings for hybrid semantic search |
| **Token Tracking** | SQLite (stdlib `token_usage.db`) | Zero setup, persistent, per-session cost and latency audit |
| **Memory** | SQLite (stdlib `memory.db`) | 48-hour conversational and pipeline state persistence |
| **Observability** | LangSmith + OpenTelemetry | In-app trace inspection, span metrics, and hallucination detection |
| **Ticketing Integration** | Jira REST API + ServiceNow | Real API ticket generation with credential validation (Path A) |

---

# 3. Infrastructure & File Structure

## 3.1 Repository Layout

```
ai_capability_demo/
├── main.py                              # Entry point: session init, routing, auth, sidebar
├── requirements.txt                     # Pure Python dependencies (pip install only)
├── Dockerfile                           # Container build configuration
├── docker-compose.yml                   # Optional local container runtime
├── .env / .env.example                  # Environment variables & API keys
├── .streamlit/
│   └── config.toml                      # Dark theme tokens, port 7860
├── token_pricing.yaml                   # LLM model rates (USD per 1M tokens)
│
├── data/
│   ├── token_usage.db                   # SQLite: LLM token consumption & cost events
│   ├── audit_log.db                     # SQLite: HITL decisions & security guardrail events
│   └── memory.db                        # SQLite: 48-hour short-term memory store
│
├── app/
│   ├── data/
│   │   ├── generator.py                 # SyntheticDataEngine: assets, CVEs, commits, backlogs
│   │   ├── synthetic_banner.py          # Data source watermarks & badges
│   │   └── compliance_frameworks.yaml   # NIST CSF 2.0, CIS, OWASP, CISA KEV mappings
│   │
│   ├── kpi/
│   │   └── engine.py                    # KPIEngine: dynamic metrics from live or synthetic data
│   │
│   ├── llm/
│   │   ├── router.py                    # LLMRouter: multi-tier model routing (mini / 4o)
│   │   ├── chunker.py                   # DataChunkEngine: map-reduce chunking for large datasets
│   │   └── token_tracker.py             # TokenUsageTracker: SQLite persistent cost tracking
│   │
│   ├── rag/
│   │   ├── indexes.py                   # FAISSIndexManager: named vector collections
│   │   ├── ingestor.py                  # RAGIngestor: chunking and vector storage
│   │   └── retriever.py                 # RAGRetriever: hybrid semantic + keyword lookup
│   │
│   ├── memory/
│   │   └── short_term.py                # ShortTermMemory: 48h context retention
│   │
│   ├── mcp/
│   │   └── client.py                    # MCPClient: REST/MCP security tool connectors
│   │
│   ├── runtime/
│   │   └── agent_manager.py             # AgentManager: prompts, execution pipelines, fallbacks
│   │
│   ├── guardrails/
│   │   └── validator.py                 # GuardrailManager: Pydantic v2 + Moderation + HITL
│   │
│   ├── observability/
│   │   ├── tracer.py                    # Dynamic OpenTelemetry instrumentation
│   │   ├── langsmith_client.py          # LangSmith API client for in-app traces
│   │   ├── hallucination.py             # HallucinationDetector: NVD CVE & ATT&CK validation
│   │   └── health_metrics.py            # In-app pipeline latency and health tracking
│   │
│   └── ui/
│       ├── theme.py                     # Pure dark theme, glassmorphism cards, color tokens
│       ├── components/
│       │   ├── auth.py                  # Login gate, session auth, profile badge
│       │   ├── charts.py                # Plotly gauges, heatmaps, and attack path visualizers
│       │   ├── interactive_demo.py      # Universal stage execution & AI results renderer
│       │   └── lifecycle_stage.py       # 3-column input panel, stage progress bar, headers
│       ├── copilots/
│       │   └── copilot.py               # Grounded RAG security assistant with memory
│       ├── dashboards/
│       │   └── executive.py             # Executive Command Center (CTEM & DevSecOps KPIs)
│       └── pages/
│           ├── ctem.py                  # 5-stage CTEM lifecycle workspace
│           ├── devsecops.py             # 7-step lean DevSecOps pipeline workspace
│           ├── agents_repo.py           # 10-Agent Catalog with Live Sandbox Console
│           ├── data_explorer.py         # Raw security dataset browser
│           ├── settings.py              # LLM tier toggles & MCP tool credentials
│           ├── token_usage.py           # Token Consumption & USD Budget Optimization
│           └── observability.py         # In-App Observability: traces, spans, and metrics
```

---

# 4. Navigation Architecture

## 4.1 Sidebar Layout (Always Visible After Login)
```
🛡️  CTEM & DevSecOps AI Platform
     Enterprise Security Showcase
─────────────────────────────────
[User Profile Badge: avatar + username + role]
─────────────────────────────────
🏠  Home
📊  Data Explorer
🤖  Agents
💬  Copilot
─────────────────────────────────
⚙️  Settings
📈  Token Usage
🔭  Observability
─────────────────────────────────
[Data Mode Badge]   🟢 API Live | 🔵 File Upload | 🟠 Synthetic
[LLM Tier Badge]    🟢 GPT-4o-mini  OR  🟡 Not Configured
─────────────────────────────────
AI Readiness Index: XX.X%
─────────────────────────────────
[Domain Score Bars]
  CTEM Exposure Shield      XX%  ██████░░
  DevSecOps Code Velocity   XX%  ███████░
─────────────────────────────────
[Logout Button]
```

## 4.2 Home Page Horizontal Tabs
The primary workspace renders three dedicated top-level tabs via `st.tabs()`:
1. **📊 Dashboard**: Executive Command Center featuring dual radial gauges, segregated CTEM and DevSecOps KPI scorecards, and operational resilience indexes.
2. **🎯 CTEM**: 5-stage Continuous Threat Exposure Management lifecycle.
3. **🐙 DevSecOps**: 7-step linear secure coding pipeline ending in *"Secure code at machine speed"*.

---

# 5. Core Use Case Specifications

## 5.1 Continuous Threat Exposure Management (CTEM)

```
[Stage 1: Scoping] ➔ [Stage 2: Discovery] ➔ [Stage 3: Prioritisation] ➔ [Stage 4: Validation] ➔ [Stage 5: Mobilisation]
```

### Stage 1: Scoping
- **Objective**: Establish authoritative boundary parameters across cloud, on-prem, and external assets; detect unmanaged Shadow IT.
- **Input**: `asset_inventory` (2,000 assets: IP ranges, cloud VPCs, hostnames, criticality tags).
- **Key AI Question**: *"Which assets exist in this environment, which are internet-exposed, which are business-critical, and which represent unmanaged Shadow IT?"*
- **Frontier Output**: Scoped boundary profile identifying internet-facing assets and flagging unmanaged resources (e.g. public S3 buckets).

### Stage 2: Discovery
- **Objective**: Correlate assets with vulnerability scans enriched with active threat intelligence (CISA KEV + EPSS).
- **Input**: `vulnerability_findings` (5,000 findings).
- **Key AI Question**: *"Which CVEs affect scoped assets and are actively being exploited in the wild right now?"*
- **Frontier AI Demo Moment**: Interactive **🧩 Attack Path Analysis** visualizing the progression from perimeter exposure to core database access.

### Stage 3: Prioritisation
- **Objective**: Separate theoretical CVSS severity from actual business risk using contextual telemetry.
- **Input**: Discovery findings backlog.
- **Key AI Question**: *"Which vulnerabilities demand immediate remediation based on asset value, reachability, and active KEV status?"*
- **Frontier AI Demo Moment**: **🔗 Vulnerability Chaining** and **💥 Key Demo Moment Banner** highlighting why a CVSS 7.5 KEV exploit on an exposed server is ranked **P1 Critical**, while a CVSS 9.8 flaw in an isolated dev container is deprioritised to **P3 Low**.

### Stage 4: Validation
- **Objective**: Verify real exploitability against network compensating controls and eliminate false positives.
- **Input**: Prioritised vulnerability backlog.
- **Key AI Question**: *"Can this vulnerability be reached and exploited from an external perspective, or do firewall/ingress controls mitigate the threat?"*
- **Output**: Exploit-validated findings with false positive suppression evidence logged for auditability.

### Stage 5: Mobilisation
- **Objective**: Translate validated risks into system-specific fix commands and automated engineering tickets.
- **Input**: Validated vulnerability findings.
- **Key AI Question**: *"What is the exact remediation patch command, who is the assignee, and what is the compliance SLA?"*
- **Output**: Automated Jira / ServiceNow ticket generation with copyable shell patch commands and rollback instructions.

---

## 5.2 AI-Led DevSecOps Pipeline

```
[Developer Commits Code] ➔ [1. Code Review] ➔ [2. Exploit Chain] ➔ [3. Fix Generation] ➔ [4. Create PR] ➔ [5. Security Validation] ➔ [6. Human Approval] ➔ [7. Deployed]
```

### 1. Developer Commits Code
- Ingests commit details: repository name, branch, author, commit hash, commit message, and changed code diff.

### 2. AI-Driven Code Review (`CodeReviewAgent`)
- Scans modified code for security defects.
- **Findings**: Flags **SQL Injection (CWE-89)**, **Hardcoded Secrets (JWT secret key)**, and **Vulnerable Dependencies (outdated package)** with exact line-number citations and syntax-highlighted code evidence.

### 3. AI-Driven Exploit Chain Analysis (`ExploitAnalysisAgent`)
- Translates code findings into an attacker exploitation narrative.
- Details the HTTP request payload an attacker would send, why the database parser evaluates it to TRUE, and the business impact (full unauthorized administrative session bypass).

### 4. AI-Driven Fix Generation (`FixGenerationAgent`)
- Automatically generates the minimal, secure patch diff replacing vulnerable string interpolation with database-driver parameter binding (`%s`).
- Validates Abstract Syntax Tree (AST) integrity.

### 5. Automated Pull Request Creation (`PRValidationAgent`)
- Packages the generated patch into a pull request (`fix(sec): Parameterize SQL query in auth.py [SEC-AUTO-142]`).
- Specifies target merge branch, security description, and automated changelog.

### 6. Automated Security Validation
- Executes automated pre-merge checks:
  - **Semgrep SAST**: Passed (0 security findings on patched branch).
  - **TruffleHog Secret Scan**: Passed (0 hardcoded credentials or API tokens).
  - **PyTest Unit Suite**: Passed (18/18 tests passed, zero functional regressions).

### 7. Human Approval Gate (HITL)
- Routes Critical/High severity issues to the Security Lead for review.
- Requires explicit analyst sign-off (`Approve & Merge` vs. `Reject & Request Changes`).

### 8. Code Deployed
- Unlocks deployment to target production environment upon approval.
- **Headline Outcome**:  
  **🎯 Secure code at machine speed**  
  *Vulnerabilities caught, explained, fixed, validated, and deployed — with a human still in control of the final call.*

---

# 6. Specialized Agent Catalog & Sandbox

The platform features **10 specialized security agents** divided evenly between CTEM and DevSecOps.

| Domain | Agent Name | Lifecycle Stage | Primary Focus |
|---|---|---|---|
| **CTEM** | `CTEMScopingAgent` | Stage 1 — Scoping | Attack surface boundary mapping & Shadow IT discovery |
| **CTEM** | `CTEMDiscoveryAgent` | Stage 2 — Discovery | CVE correlation, CISA KEV feeds, and EPSS percentiles |
| **CTEM** | `CTEMPrioritisationAgent` | Stage 3 — Prioritisation | Multi-factor risk engine & contextual SLA ranking |
| **CTEM** | `CTEMValidatorAgent` | Stage 4 — Validation | Exploit validation & false positive suppression |
| **CTEM** | `CTEMRemediationAgent` | Stage 5 — Mobilisation | Exact patch generation & Jira/ServiceNow ticket creation |
| **DevSecOps** | `CodeReviewAgent` | Stage 1 — Code Review | Line-level SAST analysis for SQLi, secrets, and CVEs |
| **DevSecOps** | `ExploitAnalysisAgent` | Stage 2 — Exploit Analysis | Exploit chain narratives & attacker payload simulation |
| **DevSecOps** | `FixGenerationAgent` | Stage 3 — Fix Generation | Clean parameterized query patches & unified diff generation |
| **DevSecOps** | `PRValidationAgent` | Stage 4 — PR Validation | Pull request packaging & automated security gate auditing |
| **DevSecOps** | `DeploymentApprovalAgent` | Stage 5 — Deployment Gate | HITL gate routing, policy enforcement, and deployment release |

## Live Sandbox Console
Accessible via **Agents** in the sidebar:
- **Domain Synchronization**: Switching between CTEM and DevSecOps instantly syncs the active sandbox agent.
- **Instructional Core**: Editable system prompts for fine-tuning agent instructions.
- **Tailored Mock Inputs**: Pre-loaded with realistic domain payloads (JSON network specs for CTEM; git commit diffs for DevSecOps).
- **Live Trace Execution**: Routes prompts through `GPT-4o-mini` (or high-fidelity schema simulation if offline), displaying latency, token consumption, and Pydantic-validated JSON outcomes.
- **Persistent Tracking**: Automatically registers compute costs to `token_usage.db`.

---

# 7. Executive Command Center Dashboard

Rendered on Tab 0 of the Home page:
1. **Dual Radial Gauges**:
   - **CTEM**: Exposure Mitigation Shield percentage.
   - **DevSecOps**: Secure Code Velocity percentage.
2. **Segregated Executive Scorecards**:
   - **CTEM KPIs**: Exposure Shield (%), SLA Compliance (%), KEV Collision Rate (%), False Positive Suppression (%).
   - **DevSecOps KPIs**: Auto-Fix Success Rate (%), Deployment Gate Pass Rate (%), PR Approval Rate (%), Findings Per Commit.
3. **Operational Performance Index**:
   - Calculated AI Readiness Index (weighted score across all ingested telemetry).
   - Active Exposure Suppression Rate.
   - 30-Day Risk Coverage Trend charts.

---

# 8. Token Consumption & Cost Optimization

Audits compute costs in real-time via [`app/ui/pages/token_usage.py`](file:///d:/GenAi/Projects/CTEM%20&%20Devsecops/app/ui/pages/token_usage.py):
- **Pricing Configuration**: Rates defined in `token_pricing.yaml` (GPT-4o-mini: $0.15/1M input, $0.60/1M output).
- **Real-Time KPI Cards**:
  - Cumulative USD Spend (exact sum from SQLite events).
  - API Call Count.
  - Token Breakdown (Input Tokens vs. Output Tokens).
  - Average Latency (in milliseconds).
- **Session Budget Ceiling**: Dynamic slider ($0.50 to $50.00, default $10.00) with visual threshold warnings (Safe 🟢, Warning 🟡 at 80%, Critical 🔴 at 95%).
- **Historical Spend Charts**: Daily spend trend (last 30 days) and cost distribution by lifecycle stage.

---

# 9. Observability & Guardrails

## 9.1 Observability Stack
- **LangSmith SaaS Tracing**: Connects via `LANGCHAIN_API_KEY` to render execution traces, span latencies, and token counts.
- **Dynamic OpenTelemetry Stubs**: In-app trace decorators capture runtime execution spans.
- **Hallucination Detector**: Validates CVE IDs against the official NIST NVD API and checks MITRE ATT&CK technique IDs against STIX 2.1 schemas.
- **System Health Monitor**: Live metrics for memory usage, active database connections, and average pipeline latency.

## 9.2 Security Guardrails
1. **Pydantic v2 Output Validation**: Guarantees that every agent output conforms to strict typed JSON schemas before reaching the UI.
2. **OpenAI Moderation API**: Evaluates all incoming payloads for prompt injection, jailbreaks, and unsafe content.
3. **Human-in-the-Loop (HITL)**: Enforces mandatory manual review for:
   - P1 Critical Exposure remediation in CTEM.
   - Critical/High code changes before production deployment in DevSecOps.

---

# 10. Environment Variables (`.env`)

```bash
# ── Core LLM Configuration ──────────────────────────────────────────────────
OPENAI_API_KEY=your_openai_api_key_here
MODEL_NAME=gpt-4o-mini
REASONING_MODEL=gpt-4o

# ── Observability (LangSmith) ─────────────────────────────────────────────────
LANGCHAIN_TRACING_V2=true
LANGCHAIN_API_KEY=your_langsmith_api_key_here
LANGCHAIN_PROJECT=ctem-devsecops-demo

# ── NIST NVD API (Optional) ─────────────────────────────────────────────────
NVD_API_KEY=your_nvd_api_key_here

# ── Authentication ───────────────────────────────────────────────────────────
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_password_here

# ── Ticketing Integration (Path A) ───────────────────────────────────────────
JIRA_BASE_URL=https://your-domain.atlassian.net
JIRA_API_TOKEN=your_jira_token_here
JIRA_USER_EMAIL=analyst@corp.internal
SERVICENOW_INSTANCE_URL=https://your-instance.service-now.com
SERVICENOW_USER=admin
SERVICENOW_PASSWORD=your_servicenow_password_here
```

---

# 11. Quickstart Guide

```bash
# 1. Clone repository
git clone https://github.com/vaibs2108/ctem-devsecops-demo-platform.git
cd ctem-devsecops-demo-platform

# 2. Install dependencies (Python 3.11 recommended)
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env and supply your OPENAI_API_KEY and ADMIN_PASSWORD

# 4. Launch platform
streamlit run main.py
```
Open `http://localhost:7860` in your browser. Log in with your configured credentials to access the full CTEM & DevSecOps demonstration.