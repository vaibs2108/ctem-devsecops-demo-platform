# AI Capability Demo — AGENTS.md
# Version: 5.0 — Complete Platform Specification
# Source of Truth for all development, AI agent prompting, and demo delivery

---

# 1. Platform Vision

**Name**: AI Capability Demo — Enterprise Security Showcase
**Version**: Demo Phase (pre-production) — v5.0
**Purpose**: Demonstrate four frontier AI-led security capabilities to CXO and technical
audiences. The platform functions as a compelling pre-sales demo and a credible production
implementation blueprint simultaneously.

**Four Use Cases — Each Showing the Full AI Lifecycle:**
1. AI-Led Continuous Threat Exposure Management (CTEM) — 5-stage lifecycle
2. Autonomous Threat Hunting — 5-stage lifecycle
3. AI-Enabled Penetration Testing — 5-stage lifecycle
4. AI-Led Detection Engineering — 6-stage lifecycle

**Core Design Principles:**
- Every use case shows the FULL AI lifecycle — Scoping → Discovery → Analysis →
  Validation → Mobilisation — not just a finding list
- Data always flows: MCP/API Live tools (P1) → File Upload (P2) → Synthetic (P3)
- Synthetic data is enterprise-grade in structure, always clearly watermarked
- Full dataset analysis via FAISS RAG — never 15-row samples
- Human-in-the-loop (HITL) gates are visible and mandatory for critical findings
- Remediation = Path A only (Jira/ServiceNow ticket creation with real credentials)
- Observability is active on every layer and fully visible inside the application UI
- 48-hour short-term memory — context persists across browser sessions within 2 days
- Every stage shows its objective, agent identity, expected analysis, and expected output
  BEFORE the user clicks Execute — transparency is a first-class feature
- Each stage result shows: AI Analysis, Under the Hood (pipeline transparency), AI
  Recommendations, Output Dataset Preview, and Handoff to next stage

---

# 2. Technology Stack

| Layer | Technology | Rationale |
|---|---|---|
| Frontend | Streamlit | Python-native, HF Spaces compatible, zero web framework overhead |
| Charts | Plotly + Altair | Interactive gauges, heatmaps, trend charts |
| Agent Orchestration | LangChain + LangGraph | StateGraph for HITL interrupts, multi-agent pipelines |
| Primary LLM | GPT-4o-mini (OpenAI API) | 128k context, $0.15/1M input, consistent quality, no GPU |
| Optional LLM | Ollama (UI config only) | Shown in Settings for future production use — not active in demo |
| Structured Output | Pydantic v2 | All LLM responses validated before any rendering |
| Content Safety | OpenAI Moderation API | Applied to all inputs and LLM outputs |
| **Vector DB** | **FAISS (faiss-cpu)** | **Pure Python, pip install, in-memory, no Docker needed** |
| Embeddings | text-embedding-3-small (OpenAI) | Consistent with primary LLM |
| RAG Framework | LangChain + FAISS | Multiple named indexes per collection |
| Data Engine | Pandas + NumPy | Pre-aggregation before RAG ingestion |
| Full-Dataset Pipeline | DataChunkEngine | Map-reduce: 500-row chunks, async, synthesis step |
| File Parsing | PyMuPDF + chardet + python-docx | PDF, encoded text, Word documents |
| MCP/API Client | httpx + mcp SDK | Direct REST API calls for security tools; MCP SDK for Jira |
| Data Transformation | MCPTransformer per tool | Normalises vendor payloads to platform schema |
| **Token Tracking** | **SQLite (stdlib)** | **Python built-in, zero setup, persistent, works everywhere** |
| **Short-Term Memory** | **SQLite (stdlib)** | **48-hour conversation + session context store** |
| **LLM Observability** | **LangSmith (SaaS)** | **Full traces in-app via API, with dynamic `is_langsmith_synced` runtime checks and dynamic OpenTelemetry stubs** |
| **App Metrics** | **In-memory dict + Plotly** | **Session-scoped health metrics rendered in Streamlit** |
| **Hallucination Detection** | **HallucinationDetector (custom)** | **NVD API + ATT&CK STIX validation, shown in-app** |
| Workflow Ticketing | Jira REST API + ServiceNow REST API | Real credentials, actual ticket creation |
| Hosting | HF Spaces (Docker) or any Python host | docker-compose.yml + .streamlit/config.toml included |

---

# 3. Infrastructure — Demo Phase

## 3.1 What Installs via pip (Everything)

```
pip install -r requirements.txt
```

This single command installs the complete platform. No Docker required for the application
itself. No GPU. No system packages beyond Python 3.11.

| Component | How it's installed | Notes |
|---|---|---|
| FAISS | `faiss-cpu` via pip | Pure Python, CPU only, sufficient for demo |
| SQLite | Python stdlib `sqlite3` | Zero install — ships with Python |
| LangSmith | `langsmith` via pip | Connects to smith.langchain.com SaaS |
| OpenAI | `openai` via pip | Calls api.openai.com |
| All other packages | `pip install -r requirements.txt` | |

## 3.2 Hosting Options — All Supported

| Platform | What to do | Notes |
|---|---|---|
| **Local (laptop/desktop)** | `pip install -r requirements.txt` + `streamlit run main.py` | Simplest — works on Mac/Windows/Linux |
| **HuggingFace Spaces** | Push to HF repo — uses `Dockerfile` + `.streamlit/config.toml` | Free tier works; FAISS rebuilds on restart |
| **Any cloud VM (Azure/GCP/AWS)** | Same as local — Python + pip + streamlit | No special cloud config needed |
| **Docker (optional)** | `docker-compose up` — starts app only | FAISS still in-memory; SQLite persists in volume |

## 3.3 File Structure

```
ai_capability_demo/
├── main.py                              # Entry point, routing, session init
├── requirements.txt                     # All Python dependencies — pip install only
├── Dockerfile                           # HF Spaces container build
├── docker-compose.yml                   # Optional: containerised local run
├── .env / .env.example                  # Secrets and config
├── .streamlit/
│   └── config.toml                      # Dark theme, port 7860, HF Spaces config
├── token_pricing.yaml                   # LLM cost rates — editable without code change
│
├── data/
│   ├── token_usage.db                   # SQLite — token events + cost log (auto-created)
│   ├── audit_log.db                     # SQLite — HITL decisions + guardrail events
│   └── memory.db                        # SQLite — 48-hour short-term memory store
│
├── app/
│   ├── data/
│   │   ├── generator.py                 # SyntheticDataEngine — 16 datasets
│   │   ├── synthetic_banner.py          # Sidebar data badge + watermark utilities
│   │   ├── compliance_frameworks.yaml   # MITRE ATT&CK, NIST, OWASP refs
│   │   └── ingest_frameworks.py         # One-time framework ingestion into FAISS
│   │
│   ├── kpi/
│   │   └── engine.py                    # KPIEngine — all metrics from live or synthetic
│   │
│   ├── llm/
│   │   ├── router.py                    # LLMRouter — GPT-4o-mini primary
│   │   ├── chunker.py                   # DataChunkEngine — map-reduce pipeline
│   │   └── token_tracker.py             # TokenUsageTracker — SQLite + cost calc
│   │
│   ├── rag/
│   │   ├── indexes.py                   # FAISSIndexManager — named indexes per collection
│   │   ├── ingestor.py                  # RAGIngestor — chunk, embed, add to FAISS
│   │   └── retriever.py                 # RAGRetriever — hybrid semantic + BM25
│   │
│   ├── memory/
│   │   └── short_term.py                # ShortTermMemory — 48h SQLite-backed store
│   │
│   ├── mcp/
│   │   └── [tool transformers]          # MCPTransformer per connected tool
│   │
│   ├── runtime/
│   │   ├── agent_manager.py             # AgentManager — LangGraph pipelines + all 21 stage prompts
│   │   └── evaluator.py                 # Stage output evaluator
│   │
│   ├── guardrails/
│   │   └── validator.py                 # GuardrailManager — Pydantic + Moderation + HITL
│   │
│   ├── observability/
│   │   ├── tracer.py                    # Dynamic OTel stubbing & runtime trace decorator
│   │   ├── langsmith_client.py          # LangSmith API queries for in-app display
│   │   ├── hallucination.py             # HallucinationDetector — NVD + ATT&CK validation
│   │   ├── health_metrics.py            # InAppMetrics — session-scoped health store
│   │   └── audit_logger.py              # Structured audit log writer (structlog → SQLite)
│   │
│   ├── upload/
│   │   └── processor.py                 # FileUploadProcessor
│   │
│   ├── workflow/
│   │   └── remediation.py               # RemediationWorkflowEngine — Path A only
│   │
│   └── ui/
│       ├── theme.py                     # Dark theme, glassmorphism CSS, colour palette
│       ├── components/
│       │   ├── auth.py                  # Login + profile badge + logout
│       │   ├── charts.py                # All Plotly renderers
│       │   ├── interactive_demo.py      # Universal stage execution engine (97 kB)
│       │   ├── lifecycle_stage.py       # Stage progress bar, stage panel renderer,
│       │   │                            #   stage definitions, input/output maps (62 kB)
│       │   └── synthetic_banner.py      # Synthetic data watermark (moved to app/data/)
│       ├── copilots/
│       │   └── copilot.py               # RAG chatbot with memory
│       ├── dashboards/
│       │   └── executive.py             # Executive Command Center
│       └── pages/
│           ├── ctem.py                  # UC1 — 5-stage CTEM (28 kB)
│           ├── threat_hunting.py        # UC2 — 5-stage Threat Hunting (24 kB)
│           ├── pen_testing.py           # UC3 — 5-stage Pen Testing (38 kB)
│           ├── detection_eng.py         # UC4 — 6-stage Detection Engineering (26 kB)
│           ├── data_explorer.py         # Raw dataset browser
│           ├── agents_repo.py           # Agent catalogue (19 kB)
│           ├── settings.py              # Settings: MCP/API Config + LLM Config
│           ├── token_usage.py           # Token consumption + cost optimisation
│           └── observability.py         # Full observability dashboard (in-app) (28 kB)
```

## 3.4 Production Migration Notes

| Demo Component | Production Replacement | Effort |
|---|---|---|
| FAISS (in-memory) | Qdrant (Docker/Cloud) — persistent, metadata-filtered | 1 day — swap URL in config |
| SQLite (local file) | PostgreSQL / Supabase — multi-instance, replicated | 1 day — swap connection string |
| OpenAI API only | Add Ollama (local GPU) — configure in Settings UI | 1 day — install Ollama, pull model |
| In-app metrics | Prometheus + Grafana (Docker) — persistent time-series | 2 days |
| Path A ticketing | Path B — AI auto-remediation with MCP write-back | 3-4 weeks |
| Single instance | Container autoscaling (Azure Container Apps / GCP Cloud Run) | 1 week |

---

# 4. Navigation Architecture

## 4.1 Sidebar (Left Panel — Always Visible After Login)

```
🛡️  AI Capability Demo
     Enterprise Security Showcase
─────────────────────────────────
[User Profile Badge — avatar + username + role]
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
[Data Mode Badge]    🟢 API Live | 🔵 File Upload | 🟠 Synthetic
[LLM Badge]          🟢 GPT-4o-mini  OR  🟡 LLM: Not configured
─────────────────────────────────
AI Readiness Index
     XX.X%
     Scoping: Complete · Status: Verified
─────────────────────────────────
[Use Case Score Cards — 4 cards]
  CTEM          XX%  ████░░
  Threat Hunting XX%  ████░░
  Pen Testing   XX%  ███░░░
  Detection Eng XX%  █████░
─────────────────────────────────
[Logout Button]
```

The AI Readiness Index and per-use-case score bars are computed live by `KPIEngine`
from the synthetic or live datasets on every render. They are not hardcoded.

## 4.2 Authentication

- Login page renders before any content (full-page gate)
- `check_auth()` in `app/ui/components/auth.py` checks `st.session_state.authenticated`
- Default admin credentials configured via `.env` (ADMIN_USERNAME / ADMIN_PASSWORD)
- On successful login: `st.session_state.username`, `st.session_state.user_role` are set
- Profile badge renders in sidebar: avatar icon + username + role (admin / analyst)
- Logout button clears all session state and returns to login page

## 4.3 Home Page — Horizontal Tab Layout

```
📊 Dashboard  |  🎯 CTEM  |  🔍 Threat Hunting  |  ⚔️ Pen Testing  |  🛡️ Detection Eng
```

All five tabs are rendered via `st.tabs()` in `main.py → _render_home()`.
Tab 0 = Executive Dashboard. Tabs 1–4 = Use Case pages.

## 4.4 Use Case Page Structure — Standard Layout for All Four

Every use case page follows this exact layout:

```
[Use Case Title + Accent Colour Header]
[Use Case Overview Card — rendered by render_usecase_overview_card()]
[Horizontal Stage Progress Bar — clickable pills with ✅ for completed stages]
────────────────────────────────────────────────────────────────────
[Stage Header — Stage N of M | Stage Name | Stage Description]
[Stage Objective Card — Business objective, key question, input, output]
────────────────────────────────────────────────────────────────────
[Section 1 — 3-Column Input & Configuration Panel]
  Col 1: Data Source Selector + File Upload (if File mode)
  Col 2: Filters + Live Dataset Preview (filtered, max 10 rows)
  Col 3: Frameworks + Guardrail Badges
[Section 2 — Agent Details Bar (always visible before Execute)]
[Section 3 — Execute AI Analysis Button + Pipeline Progress]
[Section 4 — Results (rendered after execution)]
  Tab 1: 🧠 AI Analysis
  Tab 2: ⚙️ Under the Hood
  Tab 3: 💡 AI Recommendations
  Tab 4: 📋 Output & Next Stage Handoff
  Tab 5: 🛠️ Remediation & Workflow  (final stages only)
```

Stage completion is tracked — completed stages show ✅ in the progress bar.
Output from Stage N feeds automatically into Stage N+1 as context.
Clicking a completed stage pill navigates back to see its results.

---

# 5. Stage Objective Cards (All 21 Stages)

Every stage renders a `render_usecase_overview_card()` and `render_stage_header()`
before any input controls. The stage objective card contains:

1. **Business Objective** — one sentence stating what this stage achieves and why
2. **Key AI Question** — the specific question the AI is answering
3. **Primary Input** — what dataset enters this stage
4. **Primary Output** — what structured data exits to the next stage
5. **Frameworks Active** — which security standards apply

## 5.1 CTEM Stage Objectives

**Stage 1 — Scoping**
- Objective: Establish a complete, authoritative attack surface boundary before any scanning begins — so the business knows exactly what it is responsible for defending.
- AI Question: "Which assets exist in this environment, which are internet-exposed, which are business-critical, and which are unknown to the CMDB (shadow IT)?"
- Input: CMDB Asset Register / synthetic `asset_inventory` (2,000 rows)
- Output: Scoped Assets Boundary Map with criticality scores, exposure flags, and shadow IT findings
- Frameworks: NIST CSF 2.0, CIS Controls, CISA KEV

**Stage 2 — Discovery**
- Objective: Map every scoped asset against known vulnerabilities, enriched with real-world exploitation probability — not just theoretical CVSS scores.
- AI Question: "Which CVEs affect which assets, and which of them are actively being exploited in the wild right now (CISA KEV + EPSS)?"
- Input: Scoped Assets Boundary Map
- Output: Active Vulnerability Scan Results (5,000 rows with CVE ID, CVSS, EPSS, KEV flag, patch status)
- Frameworks: CISA KEV Catalog, CVSS v3.1, EPSS

**Stage 3 — Prioritisation**
- Objective: Rank vulnerabilities by ACTUAL business risk, not theoretical CVSS score — so security teams spend time on what matters, not what sounds scary.
- AI Question: "Which vulnerabilities should be patched first, accounting for asset criticality, active exploitation, business exposure, and available compensating controls?"
- Key Demo Moment: A CVSS 5.0 KEV entry is ranked ABOVE a CVSS 9.5 entry with no active exploitation and no internet exposure. The AI writes the explicit rationale.
- Input: Active Vulnerability Scan Results
- Output: Risk-Prioritised Vulnerability Backlog with P1/P2/P3 classification and visible risk formula per finding
- Frameworks: NIST CSF 2.0, EPSS, CISA KEV

**Stage 4 — Validation**
- Objective: Confirm which prioritised vulnerabilities are genuinely exploitable in this specific environment — and dismiss false positives with written evidence.
- AI Question: "Is this vulnerability actually reachable by an attacker from outside, given the current network topology, port exposure, and compensating controls?"
- Key Demo Moment: CVE on port 5432 is classified as a false positive — not internet-reachable. AI writes: "Port 5432 not exposed externally — not exploitable from external attacker perspective."
- Input: Risk-Prioritised Vulnerability Backlog
- Output: Exploit-Validated Vulnerability Findings with false positive log and written rationale per dismissal
- Frameworks: CVSS v3.1 exploitability metrics, CIS Benchmarks

**Stage 5 — Mobilisation**
- Objective: Convert validated findings into specific, actionable remediation steps with ownership assignment and automated ticketing — closing the loop from detection to fix.
- AI Question: "What is the exact remediation command, who owns it, when is it due, and how does it get tracked?"
- Input: Exploit-Validated Vulnerability Findings
- Output: Remediation Ticket Package with named commands, owner assignments, and Jira/ServiceNow tickets
- Frameworks: NIST CSF Respond function, SLA enforcement (P1: 24h, P2: 72h, P3: 7d)

## 5.2 Threat Hunting Stage Objectives

**Stage 1 — Hypothesis Generation**
- Objective: Formulate targeted hunting hypotheses BEFORE any alert fires — because waiting for SIEM alerts means the attacker is already inside.
- AI Question: "Based on current threat intelligence, which adversary TTPs are most likely being used against this environment right now?"
- Input: Enterprise SIEM Event Streams / synthetic `siem_events` (10,000 rows)
- Output: Ranked Hunting Hypotheses with MITRE ATT&CK TTP mappings and confidence scores

**Stage 2 — Data Enrichment**
- Objective: Enrich raw telemetry with contextual intelligence so that weak signals become detectable patterns — turning noise into evidence.
- AI Question: "Which events across SIEM, EDR, and NetFlow are anomalous when correlated with passive DNS, certificate transparency, and threat actor infrastructure?"
- Input: Anomalous SIEM Events from Hypothesis stage
- Output: Enriched & Correlated Threat Alerts with anomaly scores, IOC matches, cross-source correlations

**Stage 3 — Automated Investigation**
- Objective: Reconstruct the full attack timeline from behavioural signals — no rules required, no prior alert needed.
- AI Question: "Do the enriched events form a coherent attack narrative? Can the full kill chain be reconstructed from behavioural signals alone?"
- Key Demo Moment: T1021.002 (SMB lateral movement) + T1078 (Valid Account abuse) — zero rule-based alerts fired. AI reconstructs the full lateral movement sequence from behavioural signals alone.
- Input: Enriched & Correlated Threat Alerts
- Output: Reconstructed Attack Timelines with ordered events, timestamps, hosts, users, technique IDs

**Stage 4 — Validation & Resolution**
- Objective: Classify each finding with a confident verdict and reasoning, then push validated threats to the SIEM platform.
- AI Question: "Is this a confirmed threat, a likely benign anomaly, or does it require human review — and what is the evidence for that verdict?"
- Input: Reconstructed Attack Timelines
- Output: Threat Containment Actions with classification (Confirmed / Benign / Human Review) and SIEM push confirmation

**Stage 5 — Operationalisation**
- Objective: Convert confirmed threat behaviours into permanent detection rules and updated playbooks — so the same attack can never go undetected again.
- AI Question: "What new detection rules and playbook updates would prevent this attack pattern from recurrence?"
- Input: Threat Containment Actions
- Output: Permanent Detection Rules in SPL/KQL formats + ATT&CK coverage delta (feeds into UC4)

## 5.3 Pen Testing Stage Objectives

**CRITICAL GUARDRAIL**: Rules of Engagement (RoE) acknowledgement is **mandatory** before Stage 1 executes. Synthetic/sandboxed targets only in demo. No real scanning from this platform — tools run on a separate lab VM; this platform reads their output via API.

**Stage 1 — Reconnaissance**
- Objective: Map the complete external attack surface using only open-source intelligence — before sending a single packet to the target.
- AI Question: "What can an attacker learn about this target from publicly available sources — domains, subdomains, exposed credentials, tech stack, and misconfigured cloud storage?"
- Key Demo Moment: Hardcoded AWS key found in a public GitHub commit history before any packet is sent. Pure OSINT. The AI finds it in seconds.
- Input: Authorised Penetration Testing Scope (RoE acknowledged)
- Output: OSINT Surface Recon Map with subdomains, open services, tech stack, DNS records, credential exposures

**Stage 2 — Vulnerability Discovery**
- Objective: Identify specific vulnerabilities and attack vectors across the scoped surface using AI-driven hypothesis generation, not just scanner output.
- AI Question: "Which specific vulnerabilities and non-obvious attack chains exist in this surface — including API chaining weaknesses, authentication bypasses, and logic flaws?"
- Input: OSINT Surface Recon Map
- Output: Vulnerability Path Candidates with confidence scores and attack vector classifications

**Stage 3 — Exploitation**
- Objective: Demonstrate real-world exploitability by constructing multi-step attack chains that show how low-severity issues combine into critical-impact outcomes.
- AI Question: "Can individual vulnerabilities be chained to produce a critical business impact outcome (e.g., SSRF to IAM credential theft to full account takeover)?"
- Input: Vulnerability Path Candidates
- Output: Adversary Exploit Chains with per-step technique IDs, severity progression, and composite chain severity

**Stage 4 — Validation**
- Objective: Confirm which attack chains are genuinely exploitable given current defences, and assess the business impact of each confirmed path.
- AI Question: "Does each exploit chain succeed against existing controls (WAF, MFA, network segmentation), and what is the maximum business impact if executed?"
- Input: Adversary Exploit Chains
- Output: Validated Exploit PoCs (description only — no executable code) with control gap assessment

**Stage 5 — Reporting**
- Objective: Produce an executive-ready and technically precise pentest report with prioritised remediation steps that map directly to business risk.
- AI Question: "How should findings be communicated to both technical teams (specific fix commands) and executives (business risk language), and in what priority order?"
- Input: Validated Exploit PoCs
- Output: Full Pentest Report with executive summary, technical findings, and prioritised remediation

## 5.4 Detection Engineering Stage Objectives

**Stage 1 — Requirements**
- Objective: Define precisely what needs to be detected, for which adversary technique, against which data source, before writing a single rule.
- AI Question: "What gaps exist in our current detection coverage against MITRE ATT&CK, which techniques are most actively used by threat actors targeting this sector, and what is the detection requirement specification for each gap?"
- Input: Existing Rules dataset (500 rows) + Coverage Gaps dataset (300 rows)
- Output: Detection Requirements with ATT&CK technique gap analysis, TP/FP criteria, and data source requirements

**Stage 2 — Logic Generation**
- Objective: Generate production-ready detection rules in all required platform formats from natural-language threat descriptions — no manual SPL/KQL writing required.
- AI Question: "Given this threat behaviour description, what is the correct Sigma rule, and what are its accurate translations to SPL, KQL, YARA-L, and XSIAM format?"
- Input: Detection Requirements from Stage 1
- Output: Generated Detection Rules in Sigma (canonical), SPL, KQL, YARA-L, XSIAM — all syntax-validated

**Stage 3 — Evaluation**
- Objective: Stress-test generated rules against historical data to measure TP/FP rates, identify evasion paths, and tune thresholds before production deployment.
- AI Question: "How does this rule perform on real data — what is the TP rate, FP rate, and what specific evasion techniques would bypass it?"
- Input: Generated Detection Rules
- Output: Rule Scorecards with TP/FP metrics, evasion path analysis, and tuning recommendations

**Stage 4 — CI/CD Deployment**
- Objective: Deploy validated rules through an automated CI/CD pipeline with testing, staging, and version-controlled rollback capability.
- AI Question: "What is the safest deployment path for this rule, what tests must pass before promotion, and what is the rollback plan if false positives spike?"
- Input: Evaluated and tuned rules from Stage 3
- Output: Deployment PR/change records with test results, staging checklists, and version metadata

**Stage 5 — Shadow Mode**
- Objective: Run new rules silently in production for a configurable period to measure real-world performance without impacting analyst workload.
- AI Question: "How does this rule perform on live production traffic over 7 days — should it be promoted, tuned, or retired based on actual TP/FP rates?"
- Input: Deployed rules from CI/CD stage
- Output: Shadow Performance Report with alert volume, TP rate, and promote/tune/retire recommendation per rule

**Stage 6 — Self-Tuning**
- Objective: Continuously optimise detection rules based on SOC feedback, false positive rates, and threat evolution — without manual engineering intervention.
- AI Question: "Based on analyst feedback and real-world performance data, what threshold adjustments and logic refinements would improve rule precision without sacrificing recall?"
- Input: Shadow Performance Reports + SOC analyst feedback
- Output: Updated rule thresholds, refined detection logic, ATT&CK coverage improvement delta

---

# 6. Stage Panel — Detailed Layout Specification

## 6.1 Section 1 — Three-Column Input & Configuration Panel

Rendered by `render_3col_input_panel()` in `lifecycle_stage.py`.

**Column 1 — Data Source & Upload**
- Data source radio: `🟢 API Live` / `🔵 File Upload` / `🟠 Synthetic`
- When File Upload selected: `st.file_uploader()` for accepted formats per use case
- CTEM: .json, .csv, .yaml, .yml, .tf, .conf, .txt
- Threat Hunting: .log, .txt, .json, .csv
- Pen Testing: .txt, .json, .yaml, .csv
- Detection Engineering: .sigma, .yml, .yaml, .txt, .json, .csv
- Data source selection persists in `st.session_state.active_data_source_{use_case}`

**Column 2 — Filter Controls + Live Dataset Preview**
- Severity/criticality dropdown filter (ALL + available values)
- Category/type filter (asset class for CTEM; source system for Threat Hunting; target type for Pen Testing; platform for Detection Engineering)
- Row count badge: "Showing X of Y rows" — updates live as filters change
- `st.dataframe()` preview of the filtered dataset, capped at 10 rows with key columns highlighted
- Note displayed below preview: "Execute AI Analysis runs on the full filtered dataset, not just this preview"

**Column 3 — Frameworks + Guardrail Badges**
- Active framework badges for this use case and stage (e.g. NIST CSF 2.0, CISA KEV)
- HITL badge: "🔶 HITL Gate Active — P1 findings require manual validation"
- Safety rule badge for pen testing: "🔴 Synthetic/Sandboxed Targets Only"
- Synthetic data badge when active: "🟠 SYNTHETIC DATA — NOT PRODUCTION"

## 6.2 Section 2 — Agent Details Bar

Rendered by `render_agent_details_bar()` in `lifecycle_stage.py`.
Always visible before the Execute button. Contains:

- **Agent Name**: e.g. `CTEMScopingAgent`
- **Agent Role**: One sentence describing what this agent is responsible for
- **Expected Analysis** (3–4 bullets): What the agent will examine in the data
- **Expected Output**: What structured data will be produced
- **Key Demo Insight**: The single most impressive thing this agent will surface

Agent metadata is stored in `STAGE_AGENT_METADATA` dict in `lifecycle_stage.py`,
keyed by `{use_case}_{stage_key}`.

Full agent catalogue per use case:

**CTEM (5 agents)**
| Agent | Stage | Expected Analysis | Key Demo Insight |
|---|---|---|---|
| CTEMScopingAgent | Scoping | Asset class distribution, environment mapping, shadow IT detection, internet exposure | Uncovers assets not in the official CMDB |
| CTEMDiscoveryAgent | Discovery | CVE cross-reference, EPSS scoring, KEV collision detection, patch availability | X findings mapped to Y assets with Z active exploits |
| CTEMPrioritisationAgent | Prioritisation | Composite risk scoring, business context weighting, SLA breach identification | CVSS 5.0 KEV item ranked above CVSS 9.5 non-exploited item |
| CTEMValidatorAgent | Validation | Network reachability, compensating control check, FP reasoning | Explicit written rationale per false positive dismissal |
| CTEMRemediationAgent | Mobilisation | Specific patch commands, owner assignment, SLA due dates, ticket creation | Named commands + expected output per fix, not generic advice |

**Threat Hunting (5 agents)**
| Agent | Stage | Expected Analysis | Key Demo Insight |
|---|---|---|---|
| ThreatHypothesisAgent | Hypothesis | Threat intel correlation, TTP hypothesis generation, ATT&CK mapping | Formulates hypotheses before any alert fires |
| DataEnrichmentAgent | Enrichment | Cross-source correlation, passive DNS, certificate transparency, IOC matching | Weak signals become coherent patterns |
| InvestigationAgent | Investigation | Kill chain reconstruction, behavioural timeline building, technique identification | Full lateral movement sequence from pure behavioural signals |
| ValidationAgent | Validation | Finding classification, SIEM push, executive summary | Confident verdict with written evidence per finding |
| OperationalisationAgent | Operationalisation | Detection rule generation, playbook update, ATT&CK coverage delta | Confirmed threats feed directly into UC4 Detection Engineering |

**Pen Testing (5 agents)**
| Agent | Stage | Expected Analysis | Key Demo Insight |
|---|---|---|---|
| PenTestScopingAgent | Reconnaissance | OSINT enumeration, subdomain discovery, credential exposure scanning | Hardcoded AWS key in public GitHub before a single packet is sent |
| VulnDiscoveryAgent | Discovery | Vulnerability hypothesis generation, API chain analysis, auth pattern analysis | Non-obvious attack paths the scanner would miss |
| ExploitChainAgent | Exploitation | Chain construction, severity elevation, PoC description | Low-severity issues chained to critical business impact |
| ExploitValidationAgent | Validation | Control bypass testing, WAF effectiveness, exploitability confirmation | Determines if defences actually stop the chain |
| PenTestReportAgent | Reporting | Executive summary generation, technical finding ranking, remediation prioritisation | Report ready for CXO and technical teams simultaneously |

**Detection Engineering (7 agents)**
| Agent | Stage | Expected Analysis | Key Demo Insight |
|---|---|---|---|
| DetectionRequirementsAgent | Requirements | Coverage gap analysis, ATT&CK technique mapping, TP/FP criteria definition | Identifies the specific techniques with zero current coverage |
| DetectionDraftAgent | Logic Generation | Natural language → Sigma rule generation | Sigma rule from threat description in seconds |
| RuleTranslatorAgent | Logic Generation | Sigma → SPL / KQL / YARA-L / XSIAM translation + syntax validation | All four platform formats from one Sigma canonical |
| RuleEvaluatorAgent | Evaluation | TP/FP rate testing, evasion path analysis, threshold optimisation | Specific evasion techniques that would bypass this rule |
| RuleImproverAgent | Evaluation | Threshold tuning, noise reduction, recall preservation | Improved rule with lower FP rate and preserved TP rate |
| ShadowModeAgent | Shadow Mode | Shadow alert volume, TP rate, promote/tune/retire recommendation | 7-day production performance without analyst impact |
| SelfTuningAgent | Self-Tuning | SOC feedback integration, threshold adjustment, coverage delta | Rules improve themselves based on analyst decisions |

## 6.3 Section 3 — Execute AI Analysis

Rendered by `render_execute_button()` and `render_progress_indicator()` in `interactive_demo.py`.

- Large primary action button: "🚀 Execute AI Analysis"
- Data source label shown on button (e.g. "Execute AI Analysis — Synthetic Data")
- Synthetic data amber warning strip shown above button when data_source == "synthetic"
- On click: sequential progress indicator with stage-specific messages (4 steps)
- Progress messages are stage-specific (e.g. "Ingesting corporate CIDRs...", "Scanning for Shadow IT...")
- Pipeline calls `agent_manager.run_stage(use_case, stage_key, datasets, data_source)`
- On completion: result stored in `st.session_state.{uc}_stage_outputs[stage_key]`
- Stage marked complete: `st.session_state.{uc}_completed_stages.append(idx)`
- `st.rerun()` triggers result rendering

## 6.4 Section 4 — Results Panel

Rendered by `render_ai_results()` in `interactive_demo.py`.

Results are organised into 4 or 5 tabs depending on stage:

### Tab 1: 🧠 AI Analysis

- **Data source declaration header** (always first): "MCP Live: Tenable" / "File Upload: x.csv" / "⚠️ SYNTHETIC DATA — FOR DEMO PURPOSES ONLY"
- **4 Stage-Level KPI Metric Cards** (computed live from AgentOutcome.metrics)
- **AI Findings** — numbered finding cards with:
  - Severity badge (Critical / High / Medium / Low) — RAG-coloured
  - Finding title and description
  - AI-scored confidence indicator per finding
  - Inline hallucination warning if triggered: "⚠️ Unverified: CVE-2024-XXXXX not found in NVD"
- **AI Confidence Score gauge** (40–99%, dynamic per analysis):
  - Shown as a Plotly gauge with colour coding (red < 60, amber 60–80, green > 80)
  - Confidence rationale text below gauge explaining what drove the score up or down
  - Variance across findings is mandatory — static 85% on every run is a prompt violation

### Tab 2: ⚙️ Under the Hood

Explains the AI's decision-making process to the audience. Shows:

- **Data Pipeline Stats**:
  - Rows ingested, FAISS chunks created, tokens retrieved
  - Ingestion method (synthetic / upload / live API)
  - Pre-aggregation summary stats (e.g. "357 unique assets, 12 asset classes")
- **Agent Reasoning**:
  - System prompt category used (e.g. "Prioritisation with business context weighting")
  - LLM model used (GPT-4o-mini / GPT-4o reasoning mode)
  - RAG retrieval stats: semantic top-K retrieved, BM25 top-K retrieved, merged context tokens
- **Confidence Scoring Breakdown**:
  - What factors drove confidence up (e.g. "High data completeness, multiple corroborating signals")
  - What factors reduced confidence (e.g. "Missing network topology data — exploitability partially inferred")
- **Guardrail Events**:
  - Pydantic validation: passed / retried N times
  - Moderation check: passed / flagged
  - Hallucination check: N CVE IDs validated, N ATT&CK technique IDs validated, N flags raised
- **LLM Call Stats**:
  - Model, input tokens, output tokens, latency (ms), cost (USD)

### Tab 3: 💡 AI Recommendations

Separate from analysis — action-oriented output for the analyst. Shows:

- **Immediate Actions** (P1 items) — bulleted list with specific next steps
- **Short-Term Actions** (P2 items, within 72h)
- **Strategic Recommendations** — broader posture improvements beyond this stage
- **What to Watch** — early warning indicators for related risk
- **Next Stage Preview** — brief description of what Stage N+1 will do with this output

### Tab 4: 📋 Output Dataset & Next Stage Handoff

Rendered by `render_handoff_card()` in `interactive_demo.py`.

- **Output Dataset Card**:
  - Dataset name (e.g. "risk_prioritised_vulnerability_backlog")
  - Shape: Rows × Columns
  - Key columns highlighted (displayed in accent colour)
  - `st.dataframe()` preview of first 5 rows with colour-coded severity column
  - Download as CSV button
- **Handoff Arrow Card**:
  - "→ Input for Stage N+1: [Stage Name]"
  - Which specific columns from this output are used as input
  - "Stage N+1 is unlocked ✅" or "Complete this stage to unlock Stage N+1 🔒"
- **Previous Stage Input Context** (collapsible):
  - Shows what was passed IN to this stage from the previous stage
  - Sourced from `_get_previous_stage_output()` in `lifecycle_stage.py`

### Tab 5: 🛠️ Remediation & Workflow (Final Stages Only)

Rendered only in: CTEM Mobilisation, Threat Hunting Operationalisation,
Pen Testing Reporting, Detection Engineering Self-Tuning.

Contains three sub-tabs:
- **Approval Queue**: WorkflowItems auto-populated from findings. Per-item controls:
  owner dropdown, due date, Approve, Reject with reason. "Approve All Critical" bulk action.
  On approve: Jira or ServiceNow API call creates real ticket. `ticket_ref` + `ticket_url` populated.
- **Implementation Tracking**: Kanban — Pending → Approved → In Progress → Validation → Closed.
  Card shows: title, severity, owner, due date, days remaining (RAG-coloured), ticket link.
- **Analytics**: Velocity chart, SLA breach gauge, owner workload bar, MTTR metric card.

---

# 7. Stage-Level KPI Specifications (All 21 Stages)

KPI cards are displayed immediately below the AI Analysis header, before findings.
Values are computed live from `AgentOutcome.metrics` (4 cards per stage, Pydantic-validated).

## 7.1 CTEM KPIs

| Stage | KPI 1 | KPI 2 | KPI 3 | KPI 4 |
|---|---|---|---|---|
| Scoping | Total Assets Scoped | Internet-Exposed | Business-Critical | Shadow IT Detected |
| Discovery | Vulns Discovered | KEV Collisions | EPSS-Scored | Patch Available % |
| Prioritisation | P1 Items | KEV-Elevated Items | SLA Breach Risk | Avg Risk Score |
| Validation | Exploitability Confirmed | FP Removed | FP Rate % | AI Confidence % |
| Mobilisation | Tickets Created | P1 Remediated | SLA Compliance % | MTTR (days) |

## 7.2 Threat Hunting KPIs

| Stage | KPI 1 | KPI 2 | KPI 3 | KPI 4 |
|---|---|---|---|---|
| Hypothesis | Hypotheses Generated | TTPs Covered | Trigger Sources | Avg Confidence % |
| Enrichment | Events Enriched | IOC Matches | Cross-Source Correlations | Anomaly Score Avg |
| Investigation | Hypotheses Confirmed | Timelines Reconstructed | Kill Chain Stages Mapped | Techniques Identified |
| Validation | Confirmed Threats | FP Dismissed | Human Review Escalations | MTTN (hours) |
| Operationalisation | Playbooks Updated | Rules Recommended | ATT&CK Coverage Delta | Detection Gaps Closed |

## 7.3 Pen Testing KPIs

| Stage | KPI 1 | KPI 2 | KPI 3 | KPI 4 |
|---|---|---|---|---|
| Reconnaissance | Subdomains Found | Open Services | Credential Exposures | Tech Stack Items |
| Discovery | Vulnerabilities Found | Attack Vectors | API Chain Candidates | Confidence Avg % |
| Exploitation | Chains Constructed | Critical Chains | Avg Chain Depth | Severity Elevations |
| Validation | Chains Confirmed | Controls Bypassed | PoCs Documented | Avg Business Impact |
| Reporting | Findings Documented | P1 Findings | Remediation Steps | Time to First Exploit |

## 7.4 Detection Engineering KPIs

| Stage | KPI 1 | KPI 2 | KPI 3 | KPI 4 |
|---|---|---|---|---|
| Requirements | ATT&CK Gaps Identified | Techniques Covered | Data Sources Required | Priority Gaps (P1) |
| Logic Generation | Rules Generated | Sigma Rules | Platform Translations | Syntax Valid % |
| Evaluation | TP Rate % | FP Rate % | Evasion Paths Found | Rules Tuned |
| CI/CD | PRs Created | Tests Passed | Rules Deployed | Rollback Triggers |
| Shadow Mode | Shadow Alerts | TP Rate % | Promoted Rules | Retired Rules |
| Self-Tuning | Thresholds Adjusted | FP Reduction % | Recall Preserved % | Coverage Delta % |

---

# 8. Input/Output Dataset Flow (All 21 Stages)

Sourced from `STAGE_INPUT_OUTPUT_MAP` in `lifecycle_stage.py`. This map drives the
handoff card in Tab 4 and the "Previous Stage Input" context block.

## 8.1 CTEM Dataset Flow

```
asset_inventory (2,000 rows)
  → [Scoping] → Scoped Assets Boundary Map
  → [Discovery] → vulnerability_findings (5,000 rows) with CVE, CVSS, EPSS, KEV
  → [Prioritisation] → remediation_backlog (1,000 rows) with P1/P2/P3 risk scores
  → [Validation] → validation_results (500 rows) with exploit confirmed / FP flag
  → [Mobilisation] → Remediation Ticket Package (Jira/ServiceNow refs)
```

## 8.2 Threat Hunting Dataset Flow

```
siem_events (10,000 rows — 02:00-04:00 UTC anomaly spike)
  → [Hypothesis] → Anomalous SIEM Events with TTP hypothesis mapping
  → [Enrichment] → hunt_alerts (2,000 rows) enriched with IOC + passive DNS
  → [Investigation] → investigation_timelines (300 rows) with kill chain reconstruction
  → [Validation] → neutralization_actions (200 rows) with Confirmed/Benign/Review
  → [Operationalisation] → detection rules (SPL/KQL) + playbook updates
```

## 8.3 Pen Testing Dataset Flow

```
pentest_scope (100 rows — fictitious domains only, RoE acknowledged)
  → [Reconnaissance] → recon_findings (1,000 rows) with OSINT surface map
  → [Discovery] → pentest_scope (vulnerability path candidates)
  → [Exploitation] → exploit_chains (200 rows — almost always Critical severity)
  → [Validation] → Validated Exploit PoCs with control gap assessment
  → [Reporting] → pentest_report_items (500 rows) with executive + technical sections
```

## 8.4 Detection Engineering Dataset Flow

```
existing_rules (500 rows — realistic SPL/KQL/YARA-L bodies)
  + coverage_gaps (300 rows)
  → [Requirements] → Detection Requirements with ATT&CK gap analysis
  → [Logic Generation] → generated_rules (200 rows — all 4 platform outputs)
  → [Evaluation] → rule_performance (400 rows — precision/recall/F1 per rule)
  → [CI/CD] → Deployment records with test results + version metadata
  → [Shadow Mode] → Shadow performance report per rule
  → [Self-Tuning] → Updated thresholds + coverage improvement delta
```

---

# 9. Data Architecture

## 9.1 Data Ingestion Hierarchy

```
Priority 1 — API/MCP Live Tools
  REST API call → MCPTransformer → Normalised DataFrame → FAISS Ingestor → Named Index

Priority 2 — File Upload
  Uploaded file → FileUploadProcessor → Parsed text → FAISS Ingestor → Named Index

Priority 3 — Synthetic Data
  SyntheticDataEngine → Generated DataFrame → FAISS Ingestor → Named Index
  [SYNTHETIC DATA watermark active everywhere]
```

## 9.2 FAISS Index Architecture

FAISS does not support metadata filtering natively. Solution: separate named indexes
per collection — each index contains only vectors of one type.

```python
class FAISSIndexManager:
    INDEXES = {
        # CTEM
        "ctem_assets":           {"vector_size": 1536},
        "ctem_vulnerabilities":  {"vector_size": 1536},
        "ctem_remediations":     {"vector_size": 1536},
        "ctem_validations":      {"vector_size": 1536},
        # Threat Hunting
        "hunt_events":           {"vector_size": 1536},
        "hunt_alerts":           {"vector_size": 1536},
        "hunt_investigations":   {"vector_size": 1536},
        # Pen Testing
        "pentest_recon":         {"vector_size": 1536},
        "pentest_chains":        {"vector_size": 1536},
        "pentest_reports":       {"vector_size": 1536},
        # Detection Engineering
        "detection_rules":       {"vector_size": 1536},
        "detection_gaps":        {"vector_size": 1536},
        "detection_generated":   {"vector_size": 1536},
        # Frameworks (shared, built once at startup)
        "mitre_attack":          {"vector_size": 1536},
        "nist_csf":              {"vector_size": 1536},
        "owasp_top10":           {"vector_size": 1536},
        "cisa_kev":              {"vector_size": 1536},
        "sigma_rules":           {"vector_size": 1536},
    }

    def add(self, index_name: str, texts: list[str],
            metadata: list[dict], embeddings: list[list[float]]):
        """Add vectors + metadata to a named index."""

    def search(self, index_name: str, query_embedding: list[float],
               top_k: int = 50) -> list[dict]:
        """Semantic search on named index. Returns metadata dicts."""

    def bm25_search(self, index_name: str, query: str,
                    top_k: int = 20) -> list[dict]:
        """Keyword search using BM25 on stored text."""

    def hybrid_search(self, index_name: str, query: str,
                      query_embedding: list[float], top_k: int = 50) -> list[dict]:
        """Merge semantic + BM25 results. Deduplicate. Return top_k."""
```

**Production migration**: Replace `FAISSIndexManager` with `QdrantClient`.
Method signatures stay identical — only internals change. One file swap.

## 9.3 RAG Pipeline

```
Full Dataset (N rows from API / upload / synthetic)
        │
        ▼
[Pre-Aggregation — Pandas, zero LLM cost]
  Frequency tables, severity distributions, anomaly concentrations,
  time-series bucketing, cross-field correlations
  → AggregationSummary dict (injected into every LLM prompt)
        │
        ├─────────────────────────────┐
        ▼                             ▼
[FAISS Ingestion]              [Chunk Pipeline — fallback for very large datasets]
  512-token text chunks          500-row chunks, async parallel LLM
  text-embedding-3-small         map-reduce synthesis
  → Named FAISS index
        │
        ▼
[Hybrid Retrieval at analysis time]
  Semantic search (top-50) + BM25 keyword (top-20) → merge + deduplicate
  ~25,000 tokens of relevant context
        │
        ▼
[LLM Call]
  AggregationSummary (~3k tokens) + Retrieved context (~25k) + System prompt (~2k)
  = ~30k total — well within GPT-4o-mini 128k window
        │
        ▼
[AgentOutcome — Pydantic validated → HallucinationDetector → Section 4 render]
```

## 9.4 Framework Ingestion at Startup

Frameworks are ingested once at application startup via `app/data/ingest_frameworks.py`.
On HF Spaces cold start, reingest takes ~90 seconds (shown as spinner).

| Framework | Source | FAISS Index | Notes |
|---|---|---|---|
| MITRE ATT&CK v14 | STIX JSON (attack.mitre.org) | mitre_attack | ~600 techniques |
| CISA KEV Catalog | JSON API (cisa.gov) | cisa_kev | Daily-updated, ~1,100 entries |
| OWASP Top 10 (2021) | Hardcoded (stable) | owasp_top10 | 10 entries |
| NIST CSF 2.0 | Text extraction | nist_csf | Core functions + controls |
| Sigma Rules | YAML (SigmaHQ GitHub) | sigma_rules | Community rules subset |

## 9.5 Synthetic Data Engine

**File**: `app/data/generator.py` — `SyntheticDataEngine(seed=None)`
- Seed configurable in Settings (fixed integer or blank for random)
- Default seed=42 set in `main.py → load_data()` for reproducible demos
- All 16 datasets cross-linked via shared foreign keys
- Ingested into FAISS at startup — same pipeline as real data
- Every vector tagged with `metadata.data_source = "synthetic"`

**16 Datasets:**
- CTEM (4): `asset_inventory` (2,000), `vulnerability_findings` (5,000), `remediation_backlog` (1,000), `validation_results` (500)
- Threat Hunting (4): `siem_events` (10,000 — 02:00-04:00 UTC anomaly spike), `hunt_alerts` (2,000), `investigation_timelines` (300), `neutralization_actions` (200)
- Pen Testing (4): `pentest_scope` (100 — fictitious domains only), `recon_findings` (1,000), `exploit_chains` (200 — chains almost always Critical), `pentest_report_items` (500)
- Detection Engineering (4): `existing_rules` (500 — realistic SPL/KQL/YARA-L bodies), `coverage_gaps` (300), `generated_rules` (200 — all 4 platform outputs), `rule_performance` (400 — precision/recall/F1 per rule)

---

# 10. Data-Driven Execution Engine

**File**: `app/ui/components/interactive_demo.py` — `_build_data_driven_content()`

This function ensures every stage renders rich, number-filled analysis content even if
the LLM call is cached or slow. It computes live statistics from `st.session_state.datasets`
and builds three content objects:

- `steps[]` — Step-by-step execution trace with actual dataset row counts
- `analysis[]` — Detailed analytical bullets with computed percentages and counts
- `output` — One-sentence output summary with exact numbers
- `handoff` — Handoff description naming the receiving agent and dataset

**Helper functions used:**
```python
def _rows(key) -> int:
    """Safely return row count of dataset[key]."""

def _unique(key, col) -> int:
    """Return count of unique values in dataset[key][col]."""

def _count_where(key, col, val) -> int:
    """Return count of rows where dataset[key][col] == val."""

def _count_true(key, col) -> int:
    """
    Type-safe count of truthy values — handles bool, numeric,
    and string-encoded truth values ("true", "1", "yes", "y").
    Never throws TypeError on mixed-type columns.
    """
```

This data-driven approach means the same code produces different numbers for different
datasets, whether synthetic, uploaded, or live API. The demo always shows real-looking
analysis regardless of LLM response time.

---

# 11. LLM Architecture

## 11.1 LLM Router

**File**: `app/llm/router.py`

```python
class LLMRouter:
    """
    Primary:  GPT-4o-mini (OpenAI API) — all demo analysis
    Optional: GPT-4o (OpenAI API) — reasoning mode for UC3/UC4 complex tasks
    Future:   Ollama (local) — configured in Settings UI, not active in demo phase

    All calls:
    - Tracked by TokenUsageTracker → SQLite
    - Traced by LangSmith automatically via LangChain integration
    - Timed for health metrics → InAppMetrics
    """

    def chat(self, messages: list, use_case: str, stage: str,
             context: str = "analysis",
             reasoning_mode: bool = False) -> tuple[str, str]:
        model = self.reasoning_model if reasoning_mode else self.primary_model
        start = time.time()
        response = self.openai_client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=self.settings.max_tokens_analysis,
            temperature=self.settings.temperature_analysis,
        )
        duration_ms = int((time.time() - start) * 1000)
        self.tracker.log(
            model=model, source="openai",
            use_case=use_case, stage=stage, context=context,
            input_tokens=response.usage.prompt_tokens,
            output_tokens=response.usage.completion_tokens,
            cost_usd=self._calc_cost(model, response.usage),
            duration_ms=duration_ms,
        )
        self.health_metrics.record_llm_call(
            model=model, latency_ms=duration_ms,
            tokens=response.usage.total_tokens,
            success=True,
        )
        return response.choices[0].message.content, model

    def get_active_model_info(self) -> dict:
        """Returns {'model': 'GPT-4o-mini', 'source': 'openai'} for sidebar badge."""
```

## 11.2 System Prompt Standards (All 21 Stage Prompts)

All stage system prompts in `agent_manager.py` follow these rules:

1. **Data source declaration** (first sentence): `MCP Live: {tool}` / `File Upload: {filename}` / `⚠️ SYNTHETIC DATA`
2. **Lifecycle stage context**: "You are executing Stage N ({name}) of the {use_case} lifecycle"
3. **AI Confidence Score**: Dynamic 40–99%. Ambiguous data → 40–65%. Definitive cross-corroborated data → 85–99%. Variance across findings is mandatory. Static values are a prompt violation.
4. **Specificity**: Remediation = named commands, named packages, expected CLI output — not generic advice
5. **FP discipline**: Every FP classification cites specific technical evidence (port, control, environment)
6. **Output format**: Pydantic `AgentOutcome` structure — JSON with defined fields

## 11.3 AgentManager — Stage Dispatch

**File**: `app/runtime/agent_manager.py` (66.8 kB)

```python
class AgentManager:
    def __init__(self, llm_router: LLMRouter, faiss_manager, tracker: TokenUsageTracker):
        self.router = llm_router
        self.faiss = faiss_manager
        self.tracker = tracker

    def run_stage(self, use_case: str, stage_key: str,
                  datasets: dict, data_source: str) -> AgentOutcome:
        """
        Dispatch to the correct stage prompt and execution logic.
        Returns validated AgentOutcome.
        """
        # Route to stage-specific method
        method = getattr(self, f"_run_{use_case}_{stage_key}", None)
        if method:
            return method(datasets, data_source)
        raise ValueError(f"No agent method for {use_case}/{stage_key}")
```

---

# 12. Guardrails

## Layer 1 — Pydantic v2 Structured Output

```python
class AgentOutcome(BaseModel):
    lifecycle_stage:      str
    data_source:          str    # "API Live: Tenable" / "File: x.csv" / "⚠️ SYNTHETIC DATA"
    analysis_markdown:    str = Field(min_length=50)
    metrics:              List[MetricCard] = Field(min_length=4, max_length=4)
    data_grid:            List[dict] = Field(min_length=1, max_length=10)
    ai_confidence:        int = Field(ge=40, le=99)
    confidence_rationale: str

    @field_validator("metrics")
    @classmethod
    def no_placeholder_values(cls, v):
        for card in v:
            assert card.value not in ("0", "0.0", "N/A", "", "TBD")
        return v
```

One auto-retry on validation failure, then safe fallback to data-driven content.
Raw LLM text is never rendered directly.

## Layer 2 — Content Safety

- PII scan on all uploads (SSN, card numbers, passport patterns)
- OpenAI Moderation API on all inputs and all LLM outputs
- Prompt injection detection on uploaded files before RAG ingestion
- UC3: all outputs screened for executable exploit code patterns (description only permitted)

## Layer 3 — Human-in-the-Loop (HITL)

```python
HITL_THRESHOLDS = {
    "ctem_stage4":      {"condition": "exploitability_confirmed AND cvss >= 9.0",
                         "confidence_floor": 85},
    "hunt_stage4":      {"condition": "conclusion == Confirmed AND severity == Critical",
                         "confidence_floor": 85},
    "pentest_stage3":   {"condition": "chain_severity == Critical",
                         "confidence_floor": 85},
    "detection_stage3": {"condition": "gap_priority == P1 AND active_threat_actor",
                         "confidence_floor": 80},
}
```

HITL gate renders as:
```
⚠️ Human Review Required
[Finding description + what the AI proposes to do]
[✅ Approve & Continue]    [❌ Dismiss Finding]
```
All HITL decisions are written to `audit_log.db` + LangSmith trace.

## Layer 4 — Synthetic Data Watermark (4 Locations)

1. Sidebar badge: 🟠 Synthetic (always visible)
2. Section 3 pre-execution strip: amber warning banner above Execute button
3. Section 1 Col 3 guardrail badges: "🟠 SYNTHETIC DATA — NOT PRODUCTION" (read-only badge)
4. Section 4 analysis header: blockquote watermark on every result block

Accent colours desaturated 30% when synthetic mode is active (via `desaturate_colour()`).

## Layer 5 — Type-Safe Telemetry (`_count_true`)

Custom `_count_true` logic prevents runtime TypeErrors on mixed-type columns:
- Numeric / boolean columns: direct `int(series.sum())`
- String-encoded truth: checks for "true", "1", "yes", "y" in lowercased strings
- Falls back to non-null count for other column types

---

# 13. Short-Term Memory

**File**: `app/memory/short_term.py`

## 13.1 Purpose

The 48-hour memory enables:
- Copilot to remember context from previous conversations within the same session window
- Stage analysis results to be recalled across browser sessions (within 48h)
- User preferences (data source selection, configured tools) to persist
- Conversation continuity — analyst can return and ask "what did we find in the CTEM scan?"

## 13.2 Implementation

```python
class ShortTermMemory:
    DB_PATH = "data/memory.db"
    TTL_HOURS = 48

    def _init_db(self):
        conn = sqlite3.connect(self.DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS memory_entries (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id   TEXT NOT NULL,
                user         TEXT NOT NULL,
                entry_type   TEXT NOT NULL,
                use_case     TEXT,
                stage        TEXT,
                key          TEXT NOT NULL,
                value        TEXT NOT NULL,     -- JSON serialised
                created_at   TEXT NOT NULL,
                expires_at   TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mem_user ON memory_entries(user)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mem_key  ON memory_entries(key)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mem_exp  ON memory_entries(expires_at)")
        conn.commit()
        conn.close()

    def store(self, user: str, entry_type: str, key: str, value: dict,
              use_case: str = None, stage: str = None,
              session_id: str = None, ttl_hours: int = 48): ...

    def recall(self, user: str, entry_type: str = None,
               key: str = None, use_case: str = None) -> list[dict]: ...

    def recall_recent_analyses(self, user: str, use_case: str) -> list[dict]: ...

    def recall_conversation(self, user: str, last_n: int = 20) -> list[dict]: ...

    def _expire_old_entries(self):
        """Delete rows past expires_at. Called on init and every 6 hours."""
```

## 13.3 What Gets Stored

| Entry Type | Key | Value | TTL |
|---|---|---|---|
| `stage_result` | `{use_case}_{stage}` | AgentOutcome (JSON) | 48h |
| `copilot_message` | `msg_{timestamp}` | {role, content} | 48h |
| `user_preference` | `data_source_{use_case}` | "api" / "upload" / "synthetic" | 48h |
| `finding_context` | `findings_{use_case}` | Top findings from last analysis | 48h |
| `kpi_snapshot` | `kpi_{use_case}_{timestamp}` | KPI values at analysis time | 48h |
| `tool_connection` | `tool_{tool_id}` | Connection status (not credentials) | 48h |

---

# 14. Observability — Full In-App Dashboard

**File**: `app/ui/pages/observability.py` (27.7 kB)
**Sidebar label**: 🔭 Observability

All observability is visible inside the Streamlit application — no external dashboards,
no iframes. The page has five tabs.

## Tab 1 — LangSmith Traces

- **Dynamic Workspace Sync State**: Real-time `is_langsmith_synced()` check
- **Recent Runs Table**: Agent name, Use Case, Stage, Status (✅/❌), Latency (ms), Tokens, Model, Timestamp
- **Programmatic Mock Run Exclusions**: Stale entries (IDs tr-100 to tr-103) filtered on load
- **Robust Telemetry Guards**: Division-by-zero protection on all success rate metrics
- **Dynamic Project Deep-Link**: "🔗 Open LangSmith Dashboard" button → `https://smith.langchain.com/projects/p/{ls_project}`
- **OpenTelemetry-Style Execution Trace**: Click any run to expand full sub-step tree
- **Run-Level SaaS Console Redirection**: "View Full Trace" buttons per run

## Tab 2 — Hallucination Detection

**File**: `app/observability/hallucination.py`

```python
class HallucinationDetector:
    def validate_cve_ids(self, text: str) -> list[HallucinationFlag]:
        """Extract CVEs from AI output. Validate against NVD API."""

    def validate_attack_techniques(self, text: str) -> list[HallucinationFlag]:
        """Extract T-codes. Validate against ATT&CK STIX in FAISS mitre_attack index."""

    def validate_asset_references(self, text: str,
                                   asset_df: pd.DataFrame) -> list[HallucinationFlag]:
        """Validate cited hostnames/asset IDs against ingested inventory."""

    def run_all(self, agent_outcome: AgentOutcome,
                context: dict) -> HallucinationReport: ...
```

**Inline in data_grid**: Rows with hallucination flags show:
`⚠️ Unverified: CVE-2024-XXXXX not found in NVD` in red alongside the finding.

**Tab 2 shows:**
- Hallucination rate gauge (% of AI-cited facts unverifiable)
- Flag table: each unverified citation, source checked, result
- Validation history chart: hallucination rate trend per use case (last 24h)
- Status by validator type (CVE / ATT&CK / Asset): green/amber/red

## Tab 3 — Health Metrics

**File**: `app/observability/health_metrics.py`

- 4 health KPI cards: LLM Success Rate / Avg Latency / P95 Latency / Active Since
- LLM latency distribution histogram (Plotly)
- RAG retrieval score distribution (scores < 0.70 = amber, < 0.60 = red)
- RAG query volume by index
- Guardrail events table
- HITL decisions summary

## Tab 4 — Token Usage & Cost

**(Also accessible as standalone page: 📈 Token Usage)**

1. Session Summary: Total Tokens / OpenAI Cost USD / API Calls / Avg Cost per Call
2. Historical Trend (7/30/all days): token by day, daily cost bar, cost by use case, model donut
3. Call-Level Detail Table: Timestamp | Use Case | Stage | Context | Model | Input Tokens | Output Tokens | Cost USD | Duration ms — sortable, CSV export
4. Cost Optimisation Insights (5 rule-based)
5. Budget Tracker: session/daily/monthly ceiling — amber at 80%, red at 95%

**SQLite Schema:**
```sql
CREATE TABLE IF NOT EXISTS token_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT NOT NULL,
    session_id    TEXT NOT NULL,
    use_case      TEXT,
    stage         TEXT,
    context       TEXT,       -- analysis|synthesis|chunk_N|copilot|embedding|remediation
    model         TEXT NOT NULL,
    source        TEXT NOT NULL,
    input_tokens  INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    total_tokens  INTEGER DEFAULT 0,
    cost_usd      REAL DEFAULT 0.0,
    duration_ms   INTEGER DEFAULT 0,
    chunk_index   INTEGER
);
```

## Tab 5 — Audit Log

**File**: `app/observability/audit_logger.py`

Events logged via `structlog` → SQLite:
- `hitl_decision`: use_case, stage, finding_id, decision (approved/dismissed), user, model, confidence
- `guardrail_violation`: type, action_taken, context (credentials never logged)
- `ticket_created`: tool, ticket_ref, finding_title, priority, use_case
- `api_connection`: tool_id, status, sanitised_url

**Tab 5 shows:** live event stream, filters, HITL decision summary, guardrail frequency by type, ticket creation log, CSV export.

---

# 15. Remediation System

## 15.1 Path A — Workflow (Implemented)

**Pydantic models:**
```python
class RemediationTicketSpec(BaseModel):
    title:              str
    description:        str
    ticket_type:        str
    use_case:           str
    priority:           str          # P1|P2|P3
    severity:           str          # Critical|High|Medium|Low
    assignee_team:      str
    due_date:           str          # ISO date based on priority SLA
    cvss_score:         Optional[float]
    cve_id:             Optional[str]
    technique_id:       Optional[str]
    ai_confidence:      int
    remediation_steps:  List[str]    # specific commands, not generic advice
    tool_source:        str

class WorkflowItem(BaseModel):
    item_id:       str
    finding_title: str
    severity:      str
    owner:         str
    due_date:      str
    status:        str  # Pending Approval|Approved|In Progress|Validation|Closed|Rejected
    ticket_ref:    Optional[str]
    ticket_url:    Optional[str]
    audit_entries: List[str] = []
```

## 15.2 Jira REST API Integration

```python
class JiraClient:
    def test_connection(self) -> tuple[bool, str]:
        """GET /rest/api/3/myself"""

    def create_ticket(self, spec: RemediationTicketSpec) -> dict:
        """POST /rest/api/3/issue — returns ticket_ref, ticket_url, ticket_id"""

    def _to_adf(self, markdown_text: str) -> dict:
        """Convert markdown to Atlassian Document Format for Jira v3 API."""
```

## 15.3 ServiceNow REST API Integration

```python
class ServiceNowClient:
    def test_connection(self) -> tuple[bool, str]:
        """GET /api/now/table/sys_user"""

    def create_incident(self, spec: RemediationTicketSpec) -> dict:
        """POST /api/now/table/incident — returns ticket_ref, ticket_url, sys_id"""
```

## 15.4 Path B — Proposed (Not Implemented)

Shown as greyed-out glass card with "Next Steps — Production Phase" badge:
- Pre-Action Impact Assessment (exact API call, target, payload, blast radius)
- Single scroll-gated approval button
- Execution + post-remediation verification grid
- Auto-generated tickets for all executed actions
- Estimated build effort: 3–4 weeks
- Required: MCP write credentials for target security tools

---

# 16. Settings Page

**File**: `app/ui/pages/settings.py` (13.7 kB)
**Sidebar label**: ⚙️ Settings
**Two tabs**: MCP / API Configuration | LLM Configuration

**Comment-Safe .env Writer**: Updates `.env` line-by-line, preserving all comments.
**Automated LLM Router Cache Purge**: On save, `st.session_state.llm_router = None`
forces re-initialisation with new credentials — no app restart required.

## Tab 1 — MCP / API Configuration

Per-tool: name, server URL, auth type, credential fields (password-masked),
status badge (🟢/🔴/🟡), Test Connection button.

| Category | Tools |
|---|---|
| CTEM | Tenable.io, Qualys VMDR, Wiz, Prisma Cloud, AWS Security Hub, Snyk |
| Threat Hunting | Splunk, Microsoft Sentinel, CrowdStrike Falcon, SentinelOne, Elastic, PA XSIAM |
| Pen Testing | Burp Suite Enterprise, Nessus, Shodan |
| Detection Eng | Splunk (shared), Sentinel (shared), Chronicle, PA XSIAM (shared), Elastic (shared) |
| Ticketing | Jira, ServiceNow |

## Tab 2 — LLM Configuration

| Setting | Default | Notes |
|---|---|---|
| Primary LLM | GPT-4o-mini | OpenAI API — active |
| OpenAI API Key | from .env | sk-... |
| Reasoning Mode | Off | Toggle — uses GPT-4o for UC3 chains + UC4 rules |
| Reasoning Model | GPT-4o | Only when reasoning mode enabled |
| LangSmith API Key | from .env | For observability tracing |
| LangSmith Project | ai-security-demo | Project name |
| Max Tokens — Analysis | 2000 | Per stage call |
| Max Tokens — Synthesis | 3000 | Map-reduce synthesis |
| Max Tokens — Copilot | 1000 | Per copilot response |
| Temperature — Analysis | 0.2 | Low = deterministic findings |
| Temperature — Copilot | 0.4 | Slightly higher for conversation |
| Chunk Size (rows) | 500 | DataChunkEngine |
| Synthetic Data Seed | 42 (main.py default) | Integer = fixed; blank = random |
| Memory TTL (hours) | 48 | Short-term memory retention |
| Breach Simulation | Off | Toggle — adds Breach & Attack Simulation to Tab 1 |
| Ollama (Future) | Not active | Shown for production configuration preview |

---

# 17. KPI Engine

**File**: `app/kpi/engine.py`

| Use Case | KPI | Formula |
|---|---|---|
| CTEM | Vuln Exposure Coverage | % assets with ≥1 validated finding |
| CTEM | FP Suppression Rate | % findings classified FP / total validated |
| CTEM | KEV Collision Rate | % open vulns in CISA KEV |
| CTEM | MTTR | Avg days discovery → status=Patched |
| CTEM | P1 SLA Breach Rate | % P1 items past due_date |
| Threat Hunting | Hypothesis Accuracy | % confirmed / total investigated |
| Threat Hunting | MTTN | Avg hours alert → outcome=Success |
| Threat Hunting | Cross-Source Correlation | % alerts with ≥2 source_systems |
| Threat Hunting | HITL Approval Rate | % actions approved after gate |
| Pen Testing | Exploit Chain Depth | Avg steps per chain |
| Pen Testing | Critical Chain Rate | % chains at chain_severity=Critical |
| Pen Testing | Time to First Exploit | Avg time_to_exploit_min |
| Pen Testing | Control Bypass Rate | % exploits bypassing existing controls |
| Detection Eng | ATT&CK Coverage % | Active-rule unique T-codes / total T-codes |
| Detection Eng | Gap Closure Rate | % gaps with a generated rule |
| Detection Eng | Rule Precision | Avg TP/(TP+FP) from rule_performance |
| Detection Eng | Translation Accuracy | % Syntax Valid across all 4 platforms |
| Detection Eng | Shadow Promotion Rate | % shadow rules promoted to active |
| Overall | AI Readiness Index | Weighted avg of 4 use case scores (25% each) |

`get_ai_readiness_index()` and `get_use_case_score(uc)` are called by the sidebar
on every render to update the progress bars.

---

# 18. Executive Dashboard

**File**: `app/ui/dashboards/executive.py`

1. Hero banner — gradient glass card, platform name, data source status
2. Use Case Score Gauges — 4 Plotly gauges, RAG-coloured, no tick marks
3. Cross-Use-Case KPI Cards — 8 cards in 2×4 grid, CXO-language labels
4. AI Readiness Index — single large gauge
5. 30-Day Trend Chart — Exposure Coverage + Hunt Accuracy + Detection Coverage
6. Vulnerability Heatmap — asset class × CVSS band
7. Threat Hunt Signal Distribution — bar chart by source system
8. Active Exposures — horizontal bar chart by asset class
9. Detection Coverage Scorecard — donut (Covered / Gap / Compensating)
10. Observability Quick-Strip (bottom, admin only): LLM health badge, RAG quality badge, last hallucination event, active session count

---

# 19. Copilot

**File**: `app/ui/copilots/copilot.py`
**Sidebar label**: 💬 Copilot

- RAG over all FAISS indexes (synthetic + framework + live data if connected)
- 48-hour memory: remembers prior session findings and conversation
- File upload within copilot: ingest additional context into FAISS live
- Starter questions per use case (3 each — pill buttons)
- Full chat history in session state + SQLite memory store
- All calls tracked by TokenUsageTracker + LangSmith
- Guardrail screening on all inputs and outputs

**System prompt construction:**
```python
def build_copilot_system_prompt(user: str, memory: ShortTermMemory) -> str:
    recent_analyses = memory.recall_recent_analyses(user, use_case="all")
    recent_findings = memory.recall(user, entry_type="finding_context")
    kpi_snapshots   = memory.recall(user, entry_type="kpi_snapshot")

    return f"""
You are a Senior Security Analyst AI Copilot with access to the following context
from the past 48 hours of this analyst's work session:

RECENT ANALYSIS RESULTS:
{json.dumps(recent_analyses, indent=2)[:3000]}

TOP FINDINGS FROM RECENT SCANS:
{json.dumps(recent_findings, indent=2)[:2000]}

CURRENT KPI SNAPSHOT:
{json.dumps(kpi_snapshots, indent=2)[:1000]}

Use this context to provide continuity. If the analyst asks "what did we find yesterday"
or "remind me of the critical findings", answer from this context, not from general knowledge.
    """
```

---

# 20. Agents Repository Page

**File**: `app/ui/pages/agents_repo.py` (19.3 kB)
**Sidebar label**: 🤖 Agents

Displays the full agent catalogue for all four use cases. Per agent:
- Agent name, use case, stage number
- Role description
- Expected input dataset
- Expected output dataset
- Key analysis capabilities (bullet list)
- Framework alignment (ATT&CK, NIST, OWASP, etc.)
- Status badge: Active / Planned / Shadow Mode

---

# 21. Data Explorer Page

**File**: `app/ui/pages/data_explorer.py` (5.88 kB)
**Sidebar label**: 📊 Data Explorer

- Dataset selector (all 16 synthetic datasets)
- Row count, column count, data types summary
- `st.dataframe()` interactive browse of the full dataset
- Column statistics: min, max, mean, null %, unique values
- Download as CSV button
- Filter controls per dataset

---

# 22. UI/UX Design System

**File**: `app/ui/theme.py` (25.6 kB)

```python
BG_PRIMARY    = "#0a0e27"
BG_SECONDARY  = "#111638"
BG_GLASS      = "rgba(17, 22, 56, 0.6)"
ACCENT_BLUE   = "#00d4ff"    # CTEM
ACCENT_RED    = "#ff4444"    # Threat Hunting
ACCENT_PURPLE = "#a855f7"    # Pen Testing
ACCENT_GREEN  = "#00ff88"    # Detection Engineering
ACCENT_AMBER  = "#ffaa00"    # HITL gates, warnings
TEXT_PRIMARY  = "#ffffff"
TEXT_SECONDARY = "#d1d1e0"
TEXT_MUTED    = "#8c8cab"
BORDER_GLASS  = "rgba(255, 255, 255, 0.08)"
RAG_GREEN     = "#00ff88"    # score >= 80
RAG_AMBER     = "#ffaa00"    # score 60–79
RAG_RED       = "#ff4444"    # score < 60
```

- Dark theme, glassmorphism cards, Inter font
- RAG colour coding: Green ≥80, Amber ≥60, Red <60
- Synthetic active: accent colours desaturated 30% via `desaturate_colour(colour, 0.3)`
- Stage progress bar: horizontal pills, ✅ for completed, clickable navigation
- Hallucination warning badge: ⚠️ inline in data_grid rows
- Path B panel: greyed-out glass card with "Next Steps" badge
- `render_glass_card()`, `render_metric_card()`, `render_badge()`, `render_severity_badge()` — reusable components

---

# 23. Session State Keys

| Key | Type | Purpose |
|---|---|---|
| `authenticated` | bool | Login gate |
| `username` | str | Logged-in user |
| `session_id` | str | UUID — DB partitioning |
| `user_role` | str | admin or analyst |
| `memory` | ShortTermMemory | 48h SQLite-backed memory instance |
| `datasets` | dict | 16 synthetic DataFrames |
| `kpi_engine` | KPIEngine | Cached KPI computations |
| `llm_router` | LLMRouter | Cached router (None = not initialised) |
| `current_page` | str | Navigation state (home / copilot / agents / etc.) |
| `active_data_source_{uc}` | str | api / upload / synthetic per use case |
| `active_stage_{uc}` | int | Current stage index (0-based) |
| `{uc}_active_stage` | int | Active stage for that use case |
| `{uc}_completed_stages` | list[int] | Stage indices with ✅ completion |
| `{uc}_stage_outputs` | dict | AgentOutcome per completed stage_key |
| `{uc}_hitl_approved` | dict | HITL gate state per stage_key |
| `copilot_messages` | list | Full chat history for Copilot |
| `workflow_audit_log` | list | Remediation workflow audit trail |
| `settings_show_breach_sim` | bool | Breach simulation toggle |
| `health_metrics` | InAppMetrics | Session health accumulator |
| `hallucination_reports` | dict | Per-stage hallucination reports |
| `langsmith_obs` | LangSmithObservability | LangSmith API client |

---

# 24. API Transformer Schemas

All API clients connect via direct HTTPS REST calls.

| Tool | Connection | Auth |
|---|---|---|
| Jira | REST API v3 (httpx) | API Token (email + token) |
| ServiceNow | Table API (httpx) | Basic Auth |
| Tenable.io | REST API (httpx) | X-ApiKeys header |
| Qualys | REST API (httpx) | Basic Auth |
| Wiz | GraphQL API (httpx) | OAuth2 client credentials |
| Prisma Cloud | REST API (httpx) | API Key |
| AWS Security Hub | boto3 SDK | AWS credentials (key + secret + region) |
| Snyk | REST API (httpx) | Bearer token |
| Splunk | REST API :8089 (httpx) | Username/password or token |
| Microsoft Sentinel | Azure SDK | Azure AD app (tenant+client+secret) |
| CrowdStrike | REST API (httpx) | OAuth2 client credentials |
| SentinelOne | REST API (httpx) | API token |
| Elastic | REST API (httpx) | API key |
| PA XSIAM | Cortex API (httpx) | API key |
| Google Chronicle | REST API (httpx) | Service account JSON |
| Burp Enterprise | REST API v1 (httpx) | API key |
| Nessus | REST API :8834 (httpx) | Access key + secret key |
| Shodan | REST API (httpx) | API key |

Each transformer maps vendor-specific payload fields to the unified platform schema
(CTEM_TARGET_SCHEMA, HUNT_TARGET_SCHEMA, PENTEST_TARGET_SCHEMA, DETECTION_TARGET_SCHEMA).
Transformers are in `app/mcp/` (noted as `app/api/transformers/` in earlier spec versions).

---

# 25. Requirements & Environment

## 25.1 requirements.txt

```
# ── Core ─────────────────────────────────────────────────────────────────────
streamlit>=1.38.0,<2.0.0
python-dotenv>=1.0.1
pydantic>=2.7.0,<3.0.0
pydantic-settings>=2.3.0
PyYAML>=6.0.1

# ── LLM & Agents ─────────────────────────────────────────────────────────────
langchain>=0.2.14,<0.4.0
langchain-core>=0.2.30,<0.4.0
langchain-community>=0.2.12,<0.4.0
langchain-openai>=0.1.23,<0.3.0
langgraph>=0.2.14,<0.3.0
langgraph-checkpoint>=1.0.6
openai>=1.35.0,<2.0.0
langsmith>=0.1.90,<0.2.0
tiktoken>=0.7.0

# ── Vector DB — FAISS (pure Python, no Docker) ───────────────────────────────
faiss-cpu>=1.8.0
rank-bm25>=0.2.2

# ── Observability ────────────────────────────────────────────────────────────
structlog>=24.1.0
opentelemetry-api>=1.24.0

# ── Data ─────────────────────────────────────────────────────────────────────
pandas>=2.2.0,<3.0.0
numpy>=1.26.0,<2.0.0
scipy>=1.13.0

# ── File Parsing ─────────────────────────────────────────────────────────────
PyMuPDF>=1.24.0
chardet>=5.2.0
python-docx>=1.1.0
openpyxl>=3.1.2

# ── HTTP & Async ─────────────────────────────────────────────────────────────
httpx>=0.27.0,<0.28.0
aiohttp>=3.9.0,<4.0.0
aiofiles>=23.2.1
tenacity>=8.3.0

# ── MCP SDK ──────────────────────────────────────────────────────────────────
mcp>=1.0.0

# ── Charts ───────────────────────────────────────────────────────────────────
plotly>=5.22.0
altair>=5.3.0

# ── AI Evaluation ────────────────────────────────────────────────────────────
scikit-learn>=1.4.0,<2.0.0

# ── Security & Parsing ───────────────────────────────────────────────────────
beautifulsoup4>=4.12.3
lxml>=5.2.0
cryptography>=42.0.0

# ── Utilities ────────────────────────────────────────────────────────────────
cachetools>=5.3.3
python-dateutil>=2.9.0
pytz>=2024.1
rich>=13.7.0

# ── Testing ──────────────────────────────────────────────────────────────────
pytest>=8.2.0
pytest-asyncio>=0.23.0
pytest-mock>=3.14.0
pytest-cov>=5.0.0
responses>=0.25.0

# ─────────────────────────────────────────────────────────────────────────────
# NOT in requirements (production migration options only):
# Ollama — install separately: curl -fsSL https://ollama.ai/install.sh | sh
# Qdrant — pip install qdrant-client (swap FAISSIndexManager)
# Prometheus/Grafana — docker compose up prometheus grafana
# Pen testing tools (Burp, Nessus, Metasploit) — run on separate dedicated lab VM
# ─────────────────────────────────────────────────────────────────────────────
```

## 25.2 Environment Variables (.env) — Complete Reference

### Minimum Required to Run (Synthetic Data Only)
```
OPENAI_API_KEY=sk-your-key-here
ADMIN_PASSWORD=changeme_before_demo
LANGCHAIN_API_KEY=ls-your-key-here
```

### Full .env Reference

```bash
# ── LLM — Required ─────────────────────────────────────────────────────────
OPENAI_API_KEY=sk-your-key-here
# Required. Get from: https://platform.openai.com/api-keys
# Breaks if missing: ALL AI analysis. App loads but every Execute fails.

OPENAI_MODEL=gpt-4o-mini
# Optional. Default: gpt-4o-mini. Change to gpt-4o for higher quality (higher cost).

OPENAI_REASONING_MODEL=gpt-4o
# Optional. Default: gpt-4o. Used only when Reasoning Mode toggle is ON in Settings.

# ── Observability — Required for LangSmith tracing ──────────────────────────
LANGCHAIN_TRACING_V2=true
# Optional. Default: true. Set to false to disable LangSmith tracing entirely.

LANGCHAIN_API_KEY=ls-your-key-here
# Required for Observability tab. Get from: https://smith.langchain.com/settings
# Breaks if missing: Observability Tab 1 (LangSmith Traces) shows "Not Connected".

LANGCHAIN_PROJECT=ai-security-demo
# Optional. Default: ai-security-demo. The project name in LangSmith dashboard.

# ── Observability — Optional ────────────────────────────────────────────────
NVD_API_KEY=
# Optional. Without it: NVD rate limit = 5 req/30s. With it: 50 req/30s.
# Get from: https://nvd.nist.gov/developers/request-an-api-key
# Breaks if missing: Hallucination detection still works, but slower.

# ── Auth ────────────────────────────────────────────────────────────────────
ADMIN_USERNAME=admin
# Optional. Default: admin. Login username for the demo.

ADMIN_PASSWORD=changeme_before_demo
# Required. Change before any live demo. This is the only auth gate.

# ── Database Paths ──────────────────────────────────────────────────────────
SQLITE_DB_PATH=data/token_usage.db
# Optional. Default as shown. SQLite is stdlib — file auto-created on first run.

AUDIT_DB_PATH=data/audit_log.db
# Optional. Default as shown. Stores HITL decisions and guardrail events.

MEMORY_DB_PATH=data/memory.db
# Optional. Default as shown. Stores 48-hour short-term memory.

# ── App Behaviour ───────────────────────────────────────────────────────────
SYNTHETIC_DATA_SEED=
# Optional. Blank = random seed each startup (different numbers every time).
# Integer (e.g. 42) = fixed/reproducible — same data every startup. Recommended for demos.

# ── Ollama (Future — not active in demo phase) ───────────────────────────────
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1:8b
# Shown in Settings LLM tab. Not called in demo phase.

# ── MCP / API Tool Connections ───────────────────────────────────────────────
# All configurable via Settings → MCP/API Configuration tab in the app.
# Listed here for reference and for headless/CI configuration.

# Jira
JIRA_BASE_URL=https://your-org.atlassian.net
JIRA_EMAIL=
JIRA_API_TOKEN=
JIRA_PROJECT_KEY=SEC

# ServiceNow
SERVICENOW_INSTANCE_URL=https://your-instance.service-now.com
SERVICENOW_USERNAME=
SERVICENOW_PASSWORD=

# CTEM Tools
TENABLE_ACCESS_KEY=
TENABLE_SECRET_KEY=
# Qualys — configured via Settings UI (Basic Auth)
# Wiz — configured via Settings UI (OAuth2)
# Prisma Cloud — configured via Settings UI (API Key)
# AWS Security Hub — configured via Settings UI (AWS key + secret + region)
# Snyk — configured via Settings UI (Bearer token)

# Threat Hunting Tools
SPLUNK_HOST=
SPLUNK_PORT=8089
SPLUNK_TOKEN=
CROWDSTRIKE_CLIENT_ID=
CROWDSTRIKE_CLIENT_SECRET=
CROWDSTRIKE_BASE_URL=https://api.crowdstrike.com
SENTINEL_TENANT_ID=
SENTINEL_CLIENT_ID=
SENTINEL_CLIENT_SECRET=
SENTINEL_WORKSPACE_ID=
# SentinelOne, Elastic, PA XSIAM — configured via Settings UI

# Pen Testing Tools
BURP_BASE_URL=
BURP_API_KEY=
NESSUS_URL=
NESSUS_ACCESS_KEY=
NESSUS_SECRET_KEY=
# Shodan — configured via Settings UI
```

## 25.3 Quickstart (3 Steps)

```bash
# Step 1: Install dependencies
pip install -r requirements.txt

# Step 2: Configure environment
cp .env.example .env
# Edit .env — minimum required: OPENAI_API_KEY, ADMIN_PASSWORD, LANGCHAIN_API_KEY

# Step 3: Run
streamlit run main.py --server.port=7860
```

Works on local laptop, HuggingFace Spaces, any cloud VM.

## 25.4 Docker / HuggingFace Spaces

**docker-compose.yml:**
```yaml
version: "3.8"
services:
  app:
    build: .
    ports:
      - "7860:7860"
    env_file: .env
    volumes:
      - ./data:/app/data    # SQLite persistence
    restart: unless-stopped
```

**Dockerfile:**
```dockerfile
FROM python:3.11-slim
RUN useradd -m -u 1000 user
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl git libgomp1 \
    && rm -rf /var/lib/apt/lists/*
COPY --chown=user:user . /app/
RUN mkdir -p /app/data && chown -R user:user /app
USER user
ENV PATH="/home/user/.local/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt
EXPOSE 7860
HEALTHCHECK CMD curl --fail http://localhost:7860/_stcore/health || exit 1
ENTRYPOINT ["streamlit", "run", "main.py", "--server.port=7860", "--server.address=0.0.0.0"]
```

**.streamlit/config.toml:**
```toml
[server]
headless = true
enableCORS = false
port = 7860
maxUploadSize = 10

[theme]
base = "dark"
primaryColor = "#00d4ff"
font = "sans serif"
```

**HF Spaces note on FAISS**: FAISS rebuilds indexes on every cold start (~90 seconds).
The app shows "Initialising AI knowledge base..." spinner during this period.
SQLite data persists if HF Spaces persistent storage is enabled ($9/month).
On free tier, SQLite resets on restart — token history lost but app functions correctly.

---

# 26. token_pricing.yaml

Cost rates loaded by `TokenUsageTracker` — editable without code change:

```yaml
models:
  gpt-4o-mini:
    input_per_million: 0.15
    output_per_million: 0.60
  gpt-4o:
    input_per_million: 2.50
    output_per_million: 10.00
  text-embedding-3-small:
    input_per_million: 0.02
    output_per_million: 0.00
```

---

# 27. Demo Delivery Guide

## 27.1 Recommended Demo Flow (CXO Audience — 20 minutes)

1. **Login** → Show authentication gate + profile badge (30 sec)
2. **Executive Dashboard** → AI Readiness Index, 4 use case scores, KPI cards (3 min)
3. **CTEM Stage 3 — Prioritisation** → Execute, show key demo moment: CVSS 5.0 KEV above CVSS 9.5 (5 min)
4. **Under the Hood tab** → Show RAG pipeline stats, confidence scoring, LLM call cost (2 min)
5. **CTEM Stage 5 — Mobilisation** → Create a live Jira ticket, show ticket_ref returned (3 min)
6. **Threat Hunting Stage 3 — Investigation** → Show attack timeline reconstruction, zero rule-based alerts (3 min)
7. **Observability Page** → LangSmith traces, hallucination detection, token cost (2 min)
8. **Copilot** → "What did we find in the CTEM scan?" — show memory continuity (2 min)

## 27.2 Recommended Demo Flow (Technical Audience — 45 minutes)

Same as above, plus:
- Pen Testing Stage 1 — Reconnaissance → Show OSINT AWS key finding
- Detection Engineering Stage 2 — Logic Generation → Show Sigma → SPL/KQL translation
- Data Explorer → Browse raw synthetic datasets
- Agents Repository → Walk through all 21 agents and their relationships
- Settings → Show MCP/API tool connection framework
- Token Usage → Show cost breakdown per use case

## 27.3 Key Demo Moments (Must Not Miss)

| Use Case | Stage | Demo Moment |
|---|---|---|
| CTEM | Prioritisation | CVSS 5.0 KEV entry ranked above CVSS 9.5 non-exploited — AI writes explicit rationale |
| CTEM | Validation | CVE on port 5432 classified FP — "not internet-reachable" written rationale |
| Threat Hunting | Investigation | T1021.002 + T1078 lateral movement reconstructed with zero rule-based alerts |
| Pen Testing | Reconnaissance | Hardcoded AWS key found in GitHub commit history before any packet sent |
| Detection Eng | Logic Generation | Sigma rule generated from natural language + translated to all 4 platform formats |
| All | Under the Hood | Show RAG retrieval, confidence scoring, and LLM cost per analysis |
| All | Remediation | Live Jira/ServiceNow ticket creation with real ticket_ref returned |

---