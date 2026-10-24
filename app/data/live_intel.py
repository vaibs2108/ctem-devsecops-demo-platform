"""
Optional live threat-intel enrichment (CISA KEV + FIRST EPSS). Both are free, unauthenticated feeds.

Every call is time-boxed and failure-tolerant: on any error the caller keeps its snapshot values.
Results are cached in-process (24h on success, 5 min on failure) so Streamlit reruns never
re-hit the network.
"""
from __future__ import annotations

import copy
import json
import logging
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Tuple

import pandas as pd

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
_OK_TTL = 24 * 3600
_FAIL_TTL = 300
_cache: Dict[str, Tuple[float, Any]] = {}


def _cached(key: str, fn: Callable[[], Any]) -> Any:
    hit = _cache.get(key)
    if hit and hit[0] > time.time():
        return hit[1]
    try:
        value = fn()
        _cache[key] = (time.time() + _OK_TTL, value)
        return value
    except Exception as exc:  # network/JSON errors must never break the demo
        logger.warning("Live intel fetch '%s' failed: %s", key, exc)
        _cache[key] = (time.time() + _FAIL_TTL, None)
        return None


def _get_json(url: str, timeout: float) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (ctem-devsecops-demo)"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def fetch_kev_catalog() -> Optional[Dict[str, Any]]:
    """Whole KEV catalog: {"version", "date_released", "fetched_at", "entries": {cve: record}}."""
    def load() -> Dict[str, Any]:
        data = _get_json(KEV_URL, timeout=8)
        return {
            "version": data.get("catalogVersion", ""), "date_released": data.get("dateReleased", ""),
            "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "entries": {v["cveID"]: v for v in data["vulnerabilities"]},
        }
    return _cached("kev", load)


def fetch_kev_index() -> Optional[Dict[str, Dict[str, Any]]]:
    catalog = fetch_kev_catalog()
    return catalog["entries"] if catalog else None


def fetch_kev_dataframe() -> Optional[pd.DataFrame]:
    """The live KEV catalog as a table (None when the feed is unreachable)."""
    catalog = fetch_kev_catalog()
    if not catalog:
        return None
    df = pd.DataFrame(list(catalog["entries"].values()))
    if "cwes" in df.columns:
        df["cwes"] = df["cwes"].apply(lambda v: ", ".join(v) if isinstance(v, list) else v)
    cols = ["cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "dueDate", "knownRansomwareCampaignUse",
            "forensicTriage", "requiredAction", "cwes", "notes", "shortDescription"]
    return df[[c for c in cols if c in df.columns]].sort_values("dateAdded", ascending=False).reset_index(drop=True)


def fetch_epss(cve: str) -> Optional[Dict[str, Any]]:
    def load() -> Dict[str, Any]:
        data = _get_json(f"{EPSS_URL}?cve={urllib.parse.quote(cve)}", timeout=4)
        row = data["data"][0]
        return {"epss": float(row["epss"]), "percentile": float(row["percentile"]), "date": row["date"]}
    return _cached(f"epss:{cve}", load)


def enrich_threat(cve: str, snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of the threat dict, refreshed from live feeds where they respond."""
    threat = copy.deepcopy(snapshot)
    live_parts = 0
    catalog = fetch_kev_catalog()
    if catalog is not None:
        entry = catalog["entries"].get(cve)
        threat["kev"] = entry is not None
        if entry:
            threat["kev_date_added"] = entry.get("dateAdded", threat.get("kev_date_added"))
            threat["ransomware_use"] = entry.get("knownRansomwareCampaignUse", threat.get("ransomware_use"))
            threat["kev_record"] = entry
            threat["kev_source"] = {"mode": "live", "catalog_version": catalog["version"], "as_of": catalog["fetched_at"]}
        live_parts += 1
    epss = fetch_epss(cve)
    if epss is not None:
        threat["epss"] = round(epss["epss"], 5)
        threat["epss_percentile"] = round(epss["percentile"], 5)
        threat["epss_as_of"] = epss["date"]
        live_parts += 1
    threat["intel_status"] = {2: "live", 1: "partial"}.get(live_parts, "snapshot")
    threat["live"] = live_parts > 0
    return threat
