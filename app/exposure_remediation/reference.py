"""
Authoritative reference data for the Exposure Remediation use case.

- regulations.yaml        : frameworks/controls with applicability rules (correlated against scenario facts)
- attack_techniques.yaml  : real MITRE ATT&CK technique records (extracted from the official STIX data)
- kev_snapshot.yaml       : real CISA KEV entries for the scenario CVEs (fallback for the live feed)
"""
from __future__ import annotations

import copy
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

_DIR = Path(__file__).resolve().parent / "reference"
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


@lru_cache(maxsize=None)
def _load(name: str) -> Dict[str, Any]:
    with open(_DIR / name, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def regulations() -> Dict[str, Any]:
    return _load("regulations.yaml")


def attack_meta() -> Dict[str, Any]:
    d = _load("attack_techniques.yaml")
    return {"source": d.get("source", ""), "version": d.get("attack_version", ""), "extracted_on": d.get("extracted_on", "")}


def attack_techniques() -> List[Dict[str, Any]]:
    return copy.deepcopy(_load("attack_techniques.yaml").get("techniques", []))


def attack_cards(exposure_path: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Real ATT&CK records for the technique IDs that appear in an exposure path (order preserved)."""
    index = {t["id"]: t for t in attack_techniques()}
    seen: List[str] = []
    for hop in exposure_path:
        tid = str(hop.get("technique_or_cve", ""))
        if _TECHNIQUE_RE.match(tid) and tid not in seen:
            seen.append(tid)
    return [index[t] for t in seen if t in index]


def kev_snapshot_meta() -> Dict[str, Any]:
    d = _load("kev_snapshot.yaml")
    return {"catalog_version": d.get("catalog_version", ""), "date_released": d.get("date_released", ""), "retrieved_on": d.get("retrieved_on", ""),
            "url": d.get("url", "")}


def kev_snapshot_entry(cve: str) -> Optional[Dict[str, Any]]:
    entry = _load("kev_snapshot.yaml").get("entries", {}).get(cve)
    return copy.deepcopy(entry) if entry else None


def attach_kev_reference(threat: Dict[str, Any], cve: str) -> Dict[str, Any]:
    """Make sure the threat dict carries a real KEV record and its provenance (live if already attached)."""
    threat = copy.deepcopy(threat)
    if threat.get("kev_record"):
        return threat
    entry = kev_snapshot_entry(cve)
    if entry:
        meta = kev_snapshot_meta()
        threat["kev_record"] = entry
        threat["kev_source"] = {"mode": "snapshot", "catalog_version": meta["catalog_version"], "as_of": meta["retrieved_on"]}
    return threat


# ── regulations: applicability ───────────────────────────────────────────────

def framework_catalog() -> List[Dict[str, Any]]:
    return [{"id": f["id"], "name": f["name"], "kind": f.get("kind", "standard"), "full_name": f.get("full_name", "")} for f in regulations()["frameworks"]]


def _facts(scenario: Dict[str, Any]) -> Dict[str, Any]:
    threat, asset, service = scenario["threat"], scenario["asset"], scenario["service"]
    rec = next((o for o in scenario["options"] if o["id"] == scenario["recommended_option"]), scenario["options"][0])
    record = threat.get("kev_record") or {}
    return {
        "kev": bool(threat.get("kev")),
        "kev_forensic_triage": str(record.get("forensicTriage", "")).lower() == "yes",
        "internet_exposed": bool(asset.get("internet_exposed")),
        "scope": [s.lower() for s in service.get("regulatory_scope", [])],
        "option_type": rec["type"],
    }


def _matches(rule: Dict[str, Any], facts: Dict[str, Any]) -> bool:
    if rule.get("always"):
        return True
    if "kev" in rule and facts["kev"] != rule["kev"]:
        return False
    if "kev_forensic_triage" in rule and facts["kev_forensic_triage"] != rule["kev_forensic_triage"]:
        return False
    if "internet_exposed" in rule and facts["internet_exposed"] != rule["internet_exposed"]:
        return False
    if "regulatory_scope_any" in rule and not any(tok.lower() in s for tok in rule["regulatory_scope_any"] for s in facts["scope"]):
        return False
    if "option_types_any" in rule and facts["option_type"] not in rule["option_types_any"]:
        return False
    return True


def evaluate_controls(scenario: Dict[str, Any], framework_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """One row per control of the selected frameworks, with an Applies / Not applicable status and the reason."""
    facts = _facts(scenario)
    rows: List[Dict[str, Any]] = []
    for fw in regulations()["frameworks"]:
        if framework_ids is not None and fw["id"] not in framework_ids:
            continue
        for c in fw["controls"]:
            applies = _matches(c.get("applies_when", {}), facts)
            rows.append({
                "framework_id": fw["id"], "framework": fw["name"], "control_id": str(c["id"]), "title": c["title"],
                "obligation": " ".join(str(c["obligation"]).split()), "evidence": c.get("evidence", ""),
                "status": "applies" if applies else "not_applicable",
                "reason": "" if applies else c.get("not_applicable_reason", "Rule not met"),
                "source": fw.get("source", ""),
            })
    return rows


def default_framework_ids(scenario: Dict[str, Any]) -> List[str]:
    """Frameworks with at least one control that applies to this scenario."""
    applicable = {r["framework_id"] for r in evaluate_controls(scenario) if r["status"] == "applies"}
    return [f["id"] for f in regulations()["frameworks"] if f["id"] in applicable]


# ── constraints ──────────────────────────────────────────────────────────────

def constraint_catalog() -> List[Dict[str, Any]]:
    return regulations()["constraints"]


def _has_downtime(opt: Dict[str, Any]) -> bool:
    d = str(opt.get("downtime", "None")).lower()
    return not (d.startswith("none") or "no customer impact" in d)


def constraint_conflicts(scenario: Dict[str, Any], constraint_ids: List[str]) -> Dict[str, List[str]]:
    """{option_id: [constraint labels that conflict with it]} (informational, never changes the plan)."""
    labels = {c["id"]: c for c in constraint_catalog()}
    out: Dict[str, List[str]] = {}
    for opt in scenario["options"]:
        tags = set()
        if _has_downtime(opt):
            tags.add("downtime")
        if opt["type"] in ("patch", "config") and _has_downtime(opt):
            tags.add("disruptive")
        if opt["type"] == "patch":
            tags.add("patch")
        hits = [labels[c]["label"] for c in constraint_ids if c in labels and tags & set(labels[c].get("conflicts_with", []))]
        if hits:
            out[opt["id"]] = hits
    return out
