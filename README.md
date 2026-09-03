# CTEM & DevSecOps AI Platform

An AI capability demo built with Streamlit, showcasing two agentic security workflows powered by LangGraph:

- **CTEM** — Continuous Threat Exposure Management across Scoping, Discovery, Prioritisation, Validation, and Mobilisation, including AI-generated attack-path and vulnerability-chaining analysis.
- **DevSecOps** — a lean, linear AI pipeline: a commit is reviewed for SQL injection / hardcoded secrets / vulnerable packages, the exploit chain is explained, a fix is generated and opened as a PR, automated security validation runs, and a human approval gate unlocks deployment.

Both use cases share an Executive Dashboard, an Agent Registry, a Copilot chat, synthetic data generation, token-usage tracking, and observability (audit log, LangSmith tracing).

## Running locally

Requires Python 3.10+.

**With [uv](https://docs.astral.sh/uv/) (recommended):**

```bash
uv sync
cp .env.example .env   # then fill in your OPENAI_API_KEY
uv run streamlit run main.py
```

**With pip:**

```bash
pip install -r requirements.txt
cp .env.example .env   # then fill in your OPENAI_API_KEY
streamlit run main.py
```

The app serves on `http://localhost:7860` (configured in `.streamlit/config.toml`). Default login is `admin` / `123456` (override via `ADMIN_USERNAME` / `ADMIN_PASSWORD` in `.env`).

If no `OPENAI_API_KEY` is set, the app falls back to a synthetic-response mode so the demo still runs end-to-end without live LLM calls.

## Environment variables

See [.env.example](.env.example) for the full list: `OPENAI_API_KEY`, `MODEL_NAME`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, and optional LangSmith tracing keys.

## Deployment

See [render.yaml](render.yaml) for a one-click Render Blueprint deploy, or the Dockerfile for container-based hosting (e.g. Hugging Face Spaces).
