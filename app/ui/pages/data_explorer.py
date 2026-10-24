"""
AI Capability Demo — Data Explorer Page
Browse and analyze all 12 enterprise-grade security datasets.
AGENTS.md Section 4 & 5
"""

import streamlit as st
import pandas as pd
from app.ui.theme import (
    render_hero_banner, render_glass_card, render_badge,
    ACCENT_BLUE, ACCENT_GREEN, ACCENT_PURPLE,
)
from app.data.synthetic_banner import render_sidebar_data_badge

# Map categories and color accents
UC_INFO = {
    "CTEM": {
        "accent": ACCENT_BLUE,
        "datasets": {
            "asset_inventory": "🖥️ Asset Inventory (2,000 assets)",
            "vulnerability_findings": "🔍 Vulnerability Findings (5,000 findings)",
            "remediation_backlog": "📋 Remediation Backlog (1,000 items)",
            "validation_results": "🧪 Validation Results (500 runs)",
        }
    },
    "DevSecOps": {
        "accent": ACCENT_GREEN,
        "datasets": {
            "code_commits": "💻 Code Commits (150 commits)",
            "code_review_findings": "🔍 AI Code Review Findings (250 findings)",
            "pull_requests": "🔀 Pull Requests (150 PRs)",
            "security_validation_results": "✅ Security Validation Results (300 checks)",
        }
    },
    "Exposure Remediation": {
        "accent": ACCENT_PURPLE,
        "datasets": {
            "exposure_signals": "📡 Exposure Signals (scanner findings with threat context)",
            "service_identity_context": "🧩 Service & Identity Context (business service, owner, privileged identity)",
            "change_records": "📝 Change Records (ITSM changes and approvals)",
            "rescan_results": "🔁 Rescan Results (verified exposure before/after)",
            "cisa_kev_catalog": "🛡️ CISA KEV Catalog (authoritative, live feed)",
            "mitre_attack_techniques": "🧬 MITRE ATT&CK Techniques in Use (authoritative)",
        }
    }
}

# Authoritative reference datasets are not synthetic: they come from CISA and MITRE, not the data generator.
REFERENCE_DATASETS = {"cisa_kev_catalog", "mitre_attack_techniques"}


def _load_reference_dataset(key: str):
    """Return (DataFrame, provenance note) for an authoritative reference dataset."""
    if key == "cisa_kev_catalog":
        from app.data.live_intel import fetch_kev_catalog, fetch_kev_dataframe
        df = fetch_kev_dataframe()
        if df is not None:
            meta = fetch_kev_catalog()
            return df, f"Live CISA Known Exploited Vulnerabilities catalog v{meta['version']}, fetched {meta['fetched_at']}. Source: cisa.gov."
        from app.exposure_remediation import reference
        snap = reference._load("kev_snapshot.yaml")
        df = pd.DataFrame(list(snap.get("entries", {}).values()))
        if "cwes" in df.columns:
            df["cwes"] = df["cwes"].apply(lambda v: ", ".join(v) if isinstance(v, list) else v)
        return df, f"Live feed unreachable: showing the saved snapshot of the {len(df)} KEV entries used by the scenarios (catalog v{snap.get('catalog_version')}, retrieved {snap.get('retrieved_on')})."
    from app.exposure_remediation import reference
    meta = reference.attack_meta()
    df = pd.DataFrame(reference.attack_techniques())
    df["tactics"] = df["tactics"].apply(lambda v: ", ".join(v))
    df = df[["id", "name", "tactics", "description", "url", "modified"]]
    return df, f"Official MITRE ATT&CK Enterprise v{meta['version']} records for the techniques used by the scenarios (extracted {meta['extracted_on']}). Source: attack.mitre.org."

def render_data_explorer(datasets):
    """Render the raw dataset browser."""
    if not datasets:
        st.error("No datasets loaded in the current session. Please check data generator.")
        return

    st.markdown(
        render_hero_banner("Data Explorer", "Inspect and search the underlying telemetry datasets"),
        unsafe_allow_html=True
    )

    # 1. Select Use Case Category
    categories = list(UC_INFO.keys())
    selected_uc = st.selectbox(
        "Select Security Use Case Layer",
        categories,
        index=0,
        help="Filter datasets by their security domain"
    )

    info = UC_INFO[selected_uc]
    accent_color = info["accent"]
    dataset_options = info["datasets"]

    # 2. Select Specific Dataset
    selected_ds_key = st.selectbox(
        "Select Specific Dataset to Browse",
        list(dataset_options.keys()),
        format_func=lambda k: dataset_options[k],
        help="Choose the specific table to browse"
    )

    # Retrieve DataFrame
    reference_note = ""
    if selected_ds_key in REFERENCE_DATASETS:
        df, reference_note = _load_reference_dataset(selected_ds_key)
    elif selected_ds_key not in datasets:
        st.warning(f"Dataset '{selected_ds_key}' not found in registry.")
        return
    else:
        df = datasets[selected_ds_key]

    # Render a statistical summary inside a glassmorphic card
    num_rows = len(df)
    num_cols = len(df.columns)
    
    description = (
        f"<strong>Authoritative reference data, not synthetic.</strong> {reference_note}" if reference_note else
        "This dataset represents fully synthetic, high-fidelity security telemetry generated for the enterprise demonstration. "
        "It aligns with schema standards such as MITRE ATT&CK, NIST CSF 2.0, CVE, and OSSEM."
    )
    summary_html = f"""
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <h4 style="margin: 0; color: {accent_color};">{dataset_options[selected_ds_key]}</h4>
        <div>
            <span style="margin-right: 15px;">📊 <strong>Rows:</strong> {num_rows:,}</span>
            <span>🧩 <strong>Columns:</strong> {num_cols}</span>
        </div>
    </div>
    <div style="font-size: 0.85rem; color: #a0a0c0; line-height: 1.5;">
        {description}
    </div>
    """
    
    st.markdown(render_glass_card(summary_html, accent_color), unsafe_allow_html=True)

    # Search & Filter controls
    col_search, col_download = st.columns([3, 1])
    
    with col_search:
        search_query = st.text_input(
            "🔍 Quick Search / Filter Rows", 
            placeholder="Type search terms (e.g. hostname, CVE, IP, critical)...",
            help="Filter rows where any cell matches the text"
        )
        
    # Apply search filter if present
    filtered_df = df
    if search_query:
        # Search across all columns by converting cells to string and checking if search query is a substring
        mask = df.astype(str).apply(lambda x: x.str.contains(search_query, case=False)).any(axis=1)
        filtered_df = df[mask]
        st.caption(f"Filtered down to **{len(filtered_df):,}** out of **{num_rows:,}** rows.")

    with col_download:
        csv_data = filtered_df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Export to CSV",
            data=csv_data,
            file_name=f"{selected_ds_key}_export.csv",
            mime="text/csv",
            use_container_width=True,
            help="Download the filtered subset as a CSV file"
        )

    # Display Dataframe
    st.dataframe(
        filtered_df,
        use_container_width=True,
        hide_index=True
    )

    # Display Schema details
    with st.expander("🧩 View Dataset Schema & Fields Documentation"):
        schema_data = []
        for col in df.columns:
            sample_val = df[col].iloc[0] if len(df) > 0 else "N/A"
            dtype = str(df[col].dtype)
            schema_data.append({
                "Field Name": col,
                "Data Type": dtype,
                "Sample Value": str(sample_val)
            })
        st.table(pd.DataFrame(schema_data))
