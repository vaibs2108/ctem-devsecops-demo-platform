"""
FAISS Collections Definitions — All 17 collections for the AI Capability Demo.
AGENTS.md Section 4 & 10.3.
"""
from __future__ import annotations

from typing import Dict, List, Any

FAISS_COLLECTIONS: Dict[str, Dict[str, Any]] = {
    # CTEM
    "ctem_assets": {"vector_size": 1536, "distance": "Cosine"},
    "ctem_vulnerabilities": {"vector_size": 1536, "distance": "Cosine"},
    "ctem_remediations": {"vector_size": 1536, "distance": "Cosine"},
    "ctem_validations": {"vector_size": 1536, "distance": "Cosine"},
    # DevSecOps
    "devsecops_commits": {"vector_size": 1536, "distance": "Cosine"},
    "devsecops_findings": {"vector_size": 1536, "distance": "Cosine"},
    "devsecops_pull_requests": {"vector_size": 1536, "distance": "Cosine"},
    "devsecops_validations": {"vector_size": 1536, "distance": "Cosine"},
    # Custom User Uploads
    "custom_uploads": {"vector_size": 1536, "distance": "Cosine"},
    # Frameworks
    "mitre_attack": {"vector_size": 1536, "distance": "Cosine"},
    "nist_csf": {"vector_size": 1536, "distance": "Cosine"},
    "owasp_top10": {"vector_size": 1536, "distance": "Cosine"},
    "cisa_kev": {"vector_size": 1536, "distance": "Cosine"},
}


def get_collection_for_usecase(use_case: str, data_type: str) -> str:
    """Return collection name for use-case and data-type."""
    mapping = {
        ("ctem", "assets"): "ctem_assets",
        ("ctem", "findings"): "ctem_vulnerabilities",
        ("ctem", "vulnerabilities"): "ctem_vulnerabilities",
        ("ctem", "remediations"): "ctem_remediations",
        ("ctem", "validations"): "ctem_validations",
        ("devsecops", "commits"): "devsecops_commits",
        ("devsecops", "findings"): "devsecops_findings",
        ("devsecops", "pull_requests"): "devsecops_pull_requests",
        ("devsecops", "validations"): "devsecops_validations",
        ("upload", "custom"): "custom_uploads",
    }
    return mapping.get((use_case.lower(), data_type.lower()), f"{use_case}_{data_type}")


def get_collections_for_usecase(use_case: str) -> List[str]:
    """Return all collections associated with a specific use-case."""
    prefix = use_case.lower()
    return [k for k in FAISS_COLLECTIONS.keys() if k.startswith(prefix)]

