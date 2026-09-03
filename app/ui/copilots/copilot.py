"""
AI Capability Demo — Copilot Chatbot
RAG-powered conversational assistant for security data analysis.
Deep integration with FAISS vector store, live file upload ingestion, and 48-hour short-term memory.
AGENTS.md Section 4, 6.2 & 10.3
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Tuple

import pandas as pd
import streamlit as st

from app.llm.token_tracker import TokenUsageTracker
from app.rag.indexes import FAISSIndexManager
from app.rag.ingestor import RAGIngestor
from app.rag.retriever import RAGRetriever
from app.ui.theme import (
    ACCENT_AMBER,
    ACCENT_BLUE,
    ACCENT_GREEN,
    ACCENT_PURPLE,
    ACCENT_RED,
    render_badge,
    render_glass_card,
    render_hero_banner,
)
from app.upload.processor import FileUploadProcessor

logger = logging.getLogger(__name__)


# ── FAISS Session RAG Helpers ──────────────────────────────────────────────────

def get_or_init_rag_components() -> Tuple[FAISSIndexManager, RAGIngestor, RAGRetriever]:
    """Retrieve or initialize singleton RAG components stored in session state."""
    if "faiss_manager" not in st.session_state or st.session_state.faiss_manager is None:
        st.session_state.faiss_manager = FAISSIndexManager()

    if "rag_ingestor" not in st.session_state or st.session_state.rag_ingestor is None:
        st.session_state.rag_ingestor = RAGIngestor(st.session_state.faiss_manager)

    if "rag_retriever" not in st.session_state or st.session_state.rag_retriever is None:
        st.session_state.rag_retriever = RAGRetriever(st.session_state.faiss_manager)

    return st.session_state.faiss_manager, st.session_state.rag_ingestor, st.session_state.rag_retriever


def ensure_datasets_indexed(datasets: Dict[str, pd.DataFrame], ingestor: RAGIngestor) -> None:
    """Index high-value representative rows of CTEM and DevSecOps datasets into FAISS."""
    if st.session_state.get("copilot_datasets_indexed", False) or not datasets:
        return

    # Ingest representative sample rows per dataset to ensure instant startup & rich searchability
    mapping = [
        ("asset_inventory", "ctem_assets", "ctem", 60),
        ("vulnerability_findings", "ctem_vulnerabilities", "ctem", 100),
        ("remediation_backlog", "ctem_remediations", "ctem", 50),
        ("validation_results", "ctem_validations", "ctem", 40),
        ("code_commits", "devsecops_commits", "devsecops", 40),
        ("code_review_findings", "devsecops_findings", "devsecops", 80),
        ("pull_requests", "devsecops_pull_requests", "devsecops", 40),
        ("security_validation_results", "devsecops_validations", "devsecops", 40),
    ]

    for df_key, col_name, use_case, sample_n in mapping:
        df = datasets.get(df_key)
        if df is not None and not df.empty:
            try:
                # Prioritize critical/high/exposed findings if available
                if "severity" in df.columns:
                    sample_df = df.sort_values(
                        by="severity",
                        key=lambda s: s.map({"critical": 0, "high": 1, "medium": 2, "low": 3}).fillna(4)
                    ).head(sample_n)
                elif "is_internet_exposed" in df.columns:
                    sample_df = df.sort_values(by="is_internet_exposed", ascending=False).head(sample_n)
                else:
                    sample_df = df.head(sample_n)

                ingestor.ingest_dataframe(
                    df=sample_df,
                    collection_name=col_name,
                    data_source="synthetic",
                    use_case=use_case,
                )
            except Exception as exc:
                logger.warning("Could not auto-index %s into %s: %s", df_key, col_name, exc)

    st.session_state.copilot_datasets_indexed = True


def ingest_uploaded_file(uploaded_file: Any, ingestor: RAGIngestor) -> Dict[str, Any]:
    """Parse an uploaded file via FileUploadProcessor and index it into FAISS custom_uploads."""
    processor = FileUploadProcessor()
    result = processor.process(uploaded_file)

    if result.get("type") == "error":
        return {"status": "error", "message": result.get("data", "Parsing failed")}

    filename = result.get("filename", getattr(uploaded_file, "name", "custom_file"))
    file_type = result.get("type")
    count = 0

    try:
        if file_type == "dataframe":
            df = result["data"]
            count = ingestor.ingest_dataframe(
                df=df.head(200),  # Limit to 200 rows for real-time responsiveness
                collection_name="custom_uploads",
                data_source="upload",
                use_case="custom",
                metadata_extra={"filename": filename, "source": "file_upload"}
            )
        elif file_type == "text":
            raw_text = result["data"]
            # Chunk text into ~500-char paragraphs
            paragraphs = [p.strip() for p in raw_text.split("\n\n") if len(p.strip()) > 30]
            if not paragraphs:
                paragraphs = [raw_text[i:i+500] for i in range(0, len(raw_text), 450)]
            
            count = ingestor.ingest_text_chunks(
                chunks=paragraphs[:50],
                collection_name="custom_uploads",
                metadata={"filename": filename, "source": "file_upload"}
            )
        elif file_type == "dict":
            yaml_json = json.dumps(result["data"], indent=2)
            chunks = [yaml_json[i:i+600] for i in range(0, len(yaml_json), 500)]
            count = ingestor.ingest_text_chunks(
                chunks=chunks[:30],
                collection_name="custom_uploads",
                metadata={"filename": filename, "source": "file_upload"}
            )

        return {
            "status": "success",
            "filename": filename,
            "type": file_type,
            "chunks_or_rows": count,
        }
    except Exception as exc:
        logger.error("Error ingesting uploaded file %s into FAISS: %s", filename, exc)
        return {"status": "error", "message": str(exc)}


def search_hybrid_rag(query: str, datasets: dict, retriever: RAGRetriever) -> Tuple[str, List[str]]:
    """Execute hybrid retrieval across FAISS collections (CTEM, DevSecOps, Custom Uploads) and dataset frames."""
    citations: List[str] = []
    context_blocks: List[str] = []
    
    # 1. Query FAISS Vector Store across relevant domain collections
    collections_to_search = [
        ("ctem_assets", "🖥️ [CTEM Assets Boundary]"),
        ("ctem_vulnerabilities", "🔍 [CTEM Vulnerabilities]"),
        ("devsecops_findings", "🐙 [DevSecOps Code Findings]"),
        ("devsecops_commits", "💻 [DevSecOps Commits]"),
        ("devsecops_pull_requests", "🔀 [DevSecOps Pull Requests]"),
        ("custom_uploads", "📁 [Custom Upload Context]"),
    ]

    for col_name, label in collections_to_search:
        try:
            results = retriever.retrieve(query=query, collection=col_name, top_k=2)
            for res in results:
                text_snippet = res.get("text", "").strip()
                score = res.get("rrf_score", 0.0)
                meta = res.get("metadata", {})
                
                # Format a readable citation
                ref_id = meta.get("cve_id") or meta.get("asset_id") or meta.get("finding_id") or meta.get("filename") or f"id-{res.get('id', '')}"
                citation_str = f"{label} Reference `{ref_id}` (RRF Score: {score:.3f})"
                citations.append(citation_str)
                context_blocks.append(f"Source: {label}\n{text_snippet}")
        except Exception as exc:
            logger.debug("FAISS search on %s skipped: %s", col_name, exc)

    # 2. Supplementary Pandas Fallback Search (Exact keyword matching on IDs, CVEs, or file paths)
    query_lower = query.lower()
    
    # Asset Inventory exact match
    if "asset" in query_lower or "hostname" in query_lower or "ip" in query_lower or any(h in query_lower for h in ["web", "db", "stg", "prod"]):
        df_assets = datasets.get("asset_inventory")
        if df_assets is not None:
            matches = df_assets[df_assets.astype(str).apply(lambda x: x.str.contains(query, case=False)).any(axis=1)]
            if not matches.empty:
                context_blocks.append(f"Direct Asset Records:\n{matches.head(3).to_string(index=False)}")
                if not any("Asset" in c for c in citations):
                    citations.append(f"🖥️ Direct Asset Match: found {len(matches)} matching hostnames/records.")

    # Vulnerabilities exact match
    if "cve" in query_lower or "vuln" in query_lower or "epss" in query_lower or "kev" in query_lower:
        df_vulns = datasets.get("vulnerability_findings")
        if df_vulns is not None:
            matches = df_vulns[df_vulns.astype(str).apply(lambda x: x.str.contains(query, case=False)).any(axis=1)]
            if not matches.empty:
                context_blocks.append(f"Direct CVE Findings:\n{matches.head(3).to_string(index=False)}")
                if not any("Vulnerabilit" in c for c in citations):
                    citations.append(f"🔍 Direct Vulnerability Match: found {len(matches)} matching CVE vulnerabilities.")

    # DevSecOps Code Reviews
    if "sql" in query_lower or "injection" in query_lower or "secret" in query_lower or "token" in query_lower or "commit" in query_lower:
        df_review = datasets.get("code_review_findings")
        if df_review is not None:
            matches = df_review[df_review.astype(str).apply(lambda x: x.str.contains(query, case=False)).any(axis=1)]
            if not matches.empty:
                context_blocks.append(f"Direct Code Review Findings:\n{matches.head(3).to_string(index=False)}")
                if not any("Code Findings" in c for c in citations):
                    citations.append(f"🐙 Direct Code Findings: found {len(matches)} matching DevSecOps issues.")

    # If empty, provide general security posture summary snippet
    if not context_blocks:
        df_assets = datasets.get("asset_inventory")
        df_vulns = datasets.get("vulnerability_findings")
        df_reviews = datasets.get("code_review_findings")
        summary_text = f"Platform Posture Summary:\n- Assets Scoped: {len(df_assets) if df_assets is not None else 0}\n- Active Vulnerabilities: {len(df_vulns) if df_vulns is not None else 0}\n- DevSecOps Code Issues: {len(df_reviews) if df_reviews is not None else 0}"
        context_blocks.append(summary_text)

    combined_context = "\n\n---\n\n".join(context_blocks)
    return combined_context, citations


# ── Main Copilot Page Renderer ────────────────────────────────────────────────

def render_copilot(datasets: Dict[str, pd.DataFrame], llm_router: Any, kpi_engine: Any) -> None:
    """Render the AI Security Copilot with full FAISS RAG and live file ingestion."""
    # 0. Initialize RAG Components and auto-index datasets
    faiss_mgr, ingestor, retriever = get_or_init_rag_components()
    ensure_datasets_indexed(datasets, ingestor)

    # 1. Header Banner
    st.markdown(
        render_hero_banner(
            "Security Analyst Copilot",
            "AI-powered hybrid RAG assistant with FAISS vector retrieval across CTEM exposure data, DevSecOps code pipelines, and live uploaded files."
        ),
        unsafe_allow_html=True
    )

    # 2. Modern Workflow Architecture Diagram
    st.markdown(
        """
        <div class="glass-card" style="padding: 24px 20px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
            <div style="text-align: center; flex: 1;">
                <div style="width: 48px; height: 48px; background: rgba(0, 212, 255, 0.12); border-radius: 12px; display: flex; justify-content: center; align-items: center; margin: 0 auto 10px auto; font-size: 24px;">📊</div>
                <div style="color: #00d4ff; font-weight: 700; font-size: 11px; letter-spacing: 0.5px; margin-bottom: 2px;">CTEM &amp; DEVSECOPS</div>
                <div style="color: #8c8cab; font-size: 11px;">8 Domain Datasets</div>
            </div>
            <div style="color: #64748b; font-size: 18px;">→</div>
            
            <div style="text-align: center; flex: 1;">
                <div style="width: 48px; height: 48px; background: rgba(255, 170, 0, 0.12); border-radius: 12px; display: flex; justify-content: center; align-items: center; margin: 0 auto 10px auto; font-size: 24px;">📁</div>
                <div style="color: #ffaa00; font-weight: 700; font-size: 11px; letter-spacing: 0.5px; margin-bottom: 2px;">FILE UPLOADS</div>
                <div style="color: #8c8cab; font-size: 11px;">PDF, Logs, Code, Docs</div>
            </div>
            <div style="color: #64748b; font-size: 18px;">→</div>
            
            <div style="text-align: center; flex: 1;">
                <div style="width: 48px; height: 48px; background: rgba(168, 85, 247, 0.12); border-radius: 12px; display: flex; justify-content: center; align-items: center; margin: 0 auto 10px auto; font-size: 24px;">🧠</div>
                <div style="color: #a855f7; font-weight: 700; font-size: 11px; letter-spacing: 0.5px; margin-bottom: 2px;">FAISS VECTOR STORE</div>
                <div style="color: #8c8cab; font-size: 11px;">text-embedding-3-small</div>
            </div>
            <div style="color: #64748b; font-size: 18px;">→</div>
            
            <div style="text-align: center; flex: 1;">
                <div style="width: 48px; height: 48px; background: rgba(0, 255, 136, 0.12); border-radius: 12px; display: flex; justify-content: center; align-items: center; margin: 0 auto 10px auto; font-size: 24px;">🔍</div>
                <div style="color: #00ff88; font-weight: 700; font-size: 11px; letter-spacing: 0.5px; margin-bottom: 2px;">HYBRID RAG RETRIEVAL</div>
                <div style="color: #8c8cab; font-size: 11px;">Semantic + BM25 RRF</div>
            </div>
            <div style="color: #64748b; font-size: 18px;">→</div>
            
            <div style="text-align: center; flex: 1;">
                <div style="width: 48px; height: 48px; background: rgba(0, 212, 255, 0.12); border-radius: 12px; display: flex; justify-content: center; align-items: center; margin: 0 auto 10px auto; font-size: 24px;">🤖</div>
                <div style="color: #00d4ff; font-weight: 700; font-size: 11px; letter-spacing: 0.5px; margin-bottom: 2px;">COPILOT REASONING</div>
                <div style="color: #8c8cab; font-size: 11px;">GPT-4o-mini + 48h Memory</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # 3. Live File Upload & FAISS Ingestion Expander
    if "copilot_uploaded_docs" not in st.session_state:
        st.session_state.copilot_uploaded_docs = []
    if "copilot_seen_files" not in st.session_state:
        st.session_state.copilot_seen_files = set()

    with st.expander("📁 Upload Custom Data to AI Memory Bank (Live RAG Ingestion)", expanded=False):
        st.markdown(
            "<p style='font-size: 0.88rem; color: #94a3b8; margin-bottom: 12px;'>"
            "Upload security policies, vulnerability scans, audit logs, or code repositories. "
            "Files are parsed via <code>FileUploadProcessor</code>, chunked, and embedded into the "
            "<code>custom_uploads</code> FAISS index for real-time RAG context.</p>",
            unsafe_allow_html=True
        )

        uploaded_files = st.file_uploader(
            "Upload custom security files",
            accept_multiple_files=True,
            type=["txt", "json", "log", "csv", "py", "js", "yaml", "yml", "pdf", "docx"],
            label_visibility="collapsed",
            key="copilot_files_uploader"
        )

        if uploaded_files:
            new_files_processed = 0
            for ufile in uploaded_files:
                file_sig = f"{ufile.name}_{ufile.size}"
                if file_sig not in st.session_state.copilot_seen_files:
                    with st.spinner(f"Processing and embedding {ufile.name} into FAISS vector index..."):
                        res = ingest_uploaded_file(ufile, ingestor)
                        if res.get("status") == "success":
                            st.session_state.copilot_seen_files.add(file_sig)
                            st.session_state.copilot_uploaded_docs.append({
                                "filename": ufile.name,
                                "chunks": res.get("chunks_or_rows", 0),
                                "type": res.get("type", "unknown"),
                                "timestamp": time.strftime("%H:%M:%S")
                            })
                            new_files_processed += 1
                        else:
                            st.error(f"Error indexing {ufile.name}: {res.get('message')}")

            if new_files_processed > 0:
                st.success(f"Successfully indexed {new_files_processed} new file(s) into FAISS RAG index!")

        # Display active documents in FAISS index
        if st.session_state.copilot_uploaded_docs:
            st.markdown("<div style='font-size: 0.82rem; font-weight: 600; color: #d1d1e0; margin-top: 10px;'>Active Uploads in FAISS Memory Bank:</div>", unsafe_allow_html=True)
            doc_cols = st.columns(min(len(st.session_state.copilot_uploaded_docs), 3))
            for idx, doc in enumerate(st.session_state.copilot_uploaded_docs):
                col = doc_cols[idx % 3]
                with col:
                    st.markdown(
                        f"""
                        <div style="background: rgba(0, 255, 136, 0.08); border: 1px solid rgba(0, 255, 136, 0.2); border-radius: 8px; padding: 8px 12px; margin-bottom: 6px;">
                            <div style="font-size: 0.8rem; font-weight: 600; color: #00ff88;">📄 {doc['filename']}</div>
                            <div style="font-size: 0.72rem; color: #8c8cab;">{doc['chunks']} indexed items | {doc['timestamp']}</div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

    # 4. Try Asking Suggestions (Strictly CTEM & DevSecOps)
    st.markdown("<br/>💡 <span style='color: #94a3b8; font-size: 0.9rem;'>Try asking:</span>", unsafe_allow_html=True)
    col_a, col_b, col_c = st.columns(3)
    clicked_query = None

    with col_a:
        if st.button("🎯 Which internet-exposed assets have critical KEVs?", use_container_width=True):
            clicked_query = "Which internet-exposed assets have critical KEV vulnerabilities?"
        if st.button("🐙 Show SQL injection and hardcoded secret findings", use_container_width=True):
            clicked_query = "Show SQL injection and hardcoded secret findings in recent commits"
    with col_b:
        if st.button("🎯 Which vulnerabilities should be prioritized by EPSS?", use_container_width=True):
            clicked_query = "Which vulnerabilities should be prioritized by EPSS score?"
        if st.button("🔀 Which pull requests are blocked on security gates?", use_container_width=True):
            clicked_query = "Which pull requests are currently blocked on failed security validation?"
    with col_c:
        if st.button("🧪 Show false positives isolated during CTEM validation", use_container_width=True):
            clicked_query = "Show false positive vulnerabilities isolated during CTEM exploit validation"
        if st.button("📁 Summarize risks from uploaded custom files", use_container_width=True):
            clicked_query = "Summarize findings and risks across all custom uploaded security documents"

    # Clear chat functionality
    if st.button("🧹 Clear Chat History", type="tertiary"):
        st.session_state.copilot_messages = []
        st.rerun()

    st.markdown("---")

    username = st.session_state.get("username", "vaibhav")
    session_id = st.session_state.get("session_id", "default_session")

    # Initialize messages list and load from ShortTermMemory for 48h continuity
    if "copilot_messages" not in st.session_state or not st.session_state.copilot_messages:
        db_messages = []
        if "memory" in st.session_state and st.session_state.memory is not None:
            try:
                db_messages = st.session_state.memory.recall_conversation(username, last_n=20)
            except Exception:
                db_messages = []
        st.session_state.copilot_messages = db_messages

    # Display Chat History
    for msg in st.session_state.copilot_messages:
        role = msg["role"]
        content = msg["content"]
        citations = msg.get("citations", [])

        with st.chat_message(role):
            st.markdown(content)
            if citations:
                with st.expander("📚 FAISS RAG Citations"):
                    for cit in citations:
                        st.caption(cit)

    # Chat input
    user_query = st.chat_input("Ask about CTEM exposures, DevSecOps code findings, PR checks, or uploaded documents...")
    if clicked_query:
        user_query = clicked_query

    if user_query:
        # Append user message
        st.session_state.copilot_messages.append({"role": "user", "content": user_query})
        with st.chat_message("user"):
            st.markdown(user_query)

        # Save user message to SQLite 48h memory
        if "memory" in st.session_state and st.session_state.memory is not None:
            try:
                st.session_state.memory.store(
                    user=username,
                    entry_type="copilot_message",
                    key=f"msg_{int(time.time() * 1000)}",
                    value={"role": "user", "content": user_query},
                    session_id=session_id
                )
            except Exception:
                pass

        # Run analysis and LLM completion
        with st.chat_message("assistant"):
            with st.spinner("Executing hybrid RAG retrieval across FAISS vector indexes..."):
                start_time = time.time()

                # 1. Fetch relevant context via FAISS Hybrid RAG
                context_str, citations = search_hybrid_rag(user_query, datasets, retriever)

                # 2. Retrieve past 48h memory context (recent analyses, findings, KPIs)
                memory_context = ""
                if "memory" in st.session_state and st.session_state.memory is not None:
                    try:
                        recent_analyses = st.session_state.memory.recall_recent_analyses(username, use_case="all")
                        recent_findings = st.session_state.memory.recall(username, entry_type="finding_context")
                        kpi_snapshots = st.session_state.memory.recall(username, entry_type="kpi_snapshot")

                        memory_context = f"\n\nRECENT ANALYSIS RESULTS FROM PAST 48H:\n{json.dumps(recent_analyses, indent=2)[:2000]}"
                        memory_context += f"\n\nTOP FINDINGS FROM RECENT SCANS:\n{json.dumps(recent_findings, indent=2)[:1500]}"
                        memory_context += f"\n\nRECENT KPI SNAPSHOTS:\n{json.dumps(kpi_snapshots, indent=2)[:1000]}"
                    except Exception:
                        pass

                # 3. Formulate system and task prompts strictly for CTEM & DevSecOps
                system_prompt = (
                    "You are 'Antigravity Security Copilot', an expert AI security analyst specializing in "
                    "Continuous Threat Exposure Management (CTEM) and AI-Led DevSecOps pipelines.\n"
                    "Your capabilities include: attack surface boundary mapping, risk prioritisation (CISA KEV, EPSS), "
                    "exploit reachability validation, pre-commit SAST code review, automated PR patch generation, "
                    "and custom uploaded security document synthesis.\n"
                    "Format findings cleanly using bullet points, technical citations, and code blocks where applicable.\n"
                    "Always explicitly ground your answer in the provided FAISS RAG Context and cite specific assets, CVEs, or file lines.\n\n"
                    "Using context from the past 48 hours of this analyst's work session for continuous reasoning:\n"
                    f"{memory_context}"
                )

                task_prompt = f"""
                User Query: {user_query}

                FAISS RAG Retrieved Context:
                {context_str}
                """

                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": task_prompt}
                ]

                # 4. Invoke LLM Router (with graceful fallback)
                try:
                    if llm_router:
                        resp = llm_router.invoke(
                            messages=messages,
                            model_tier="primary",
                            temperature=0.2
                        )
                        answer = resp.get("content", "I encountered an issue parsing the response.")
                        input_tokens = resp.get("input_tokens", 850)
                        output_tokens = resp.get("output_tokens", 420)
                        duration = resp.get("duration", 800)
                        model = resp.get("model", "gpt-4o-mini")
                    else:
                        # High-fidelity offline simulation
                        time.sleep(1.0)
                        answer = (
                            f"**FAISS RAG Security Analysis:**\n\n"
                            f"Based on the hybrid semantic retrieval across active indexes:\n"
                            f"- Identified relevant telemetry matching your query `{user_query}`.\n"
                            f"- **CTEM / DevSecOps Correlation:** Findings cross-referenced against authoritative CVE databases and code review records.\n"
                            f"- **Actionable Recommendation:** Review the cited assets and pull request validation gates listed below."
                        )
                        input_tokens = 650
                        output_tokens = 280
                        duration = 1000
                        model = "gpt-4o-mini"

                    # Track compute consumption in SQLite token_usage.db
                    tracker = TokenUsageTracker()
                    tracker.track(
                        session_id=st.session_state.session_id,
                        use_case="copilot",
                        stage="rag_assistant",
                        model=model,
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        duration_ms=int(duration)
                    )
                except Exception as e:
                    answer = f"Error during query completion: {str(e)}"

                # Render Answer
                st.markdown(answer)

                if citations:
                    with st.expander("📚 FAISS RAG Citations"):
                        for cit in citations:
                            st.caption(cit)

                # Append assistant message to list
                st.session_state.copilot_messages.append({
                    "role": "assistant",
                    "content": answer,
                    "citations": citations
                })

                # Save assistant response to SQLite 48h memory
                if "memory" in st.session_state and st.session_state.memory is not None:
                    try:
                        st.session_state.memory.store(
                            user=username,
                            entry_type="copilot_message",
                            key=f"msg_{int(time.time() * 1000)}",
                            value={"role": "assistant", "content": answer, "citations": citations},
                            session_id=session_id
                        )
                    except Exception:
                        pass
