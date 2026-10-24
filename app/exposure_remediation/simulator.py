"""
Simulated customer environment for the Exposure Remediation use case.

Holds host state (packages, services, rules, artifacts), a small ITSM change-record state
machine, an Ansible-style task executor that mutates host state, and a verification rescan
that reads the SAME state. The rescan outcome is therefore caused by what was executed,
not scripted per scenario.
"""
from __future__ import annotations

import copy
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

ITSM_STATES = ["New", "Assess", "Authorize", "Scheduled", "Implement", "Review", "Closed"]
_MODULE_SECONDS = {
    "setup": 2, "assert": 1, "postgresql_db": 38, "archive": 24, "service": 6, "get_url": 11, "command": 47,
    "uri": 4, "find": 9, "elb_target": 7, "copy": 3, "panos_op": 3, "panos_content": 52,
    "panos_security_profile": 5, "panos_interface": 4, "panos_commit": 41,
}


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def parse_version(text: str) -> Tuple[int, ...]:
    """'8.4.1' -> (8,4,1); '10.2.6-h3' -> (10,2,6,3); '2.17.1' -> (2,17,1)."""
    base, _, hotfix = text.partition("-h")
    nums = tuple(int(p) for p in re.findall(r"\d+", base))
    return nums + (int(hotfix),) if hotfix else nums


def _cmp(a: Tuple[int, ...], op: str, b: Tuple[int, ...]) -> bool:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return {"<": a < b, "==": a == b, ">=": a >= b, ">": a > b, "<=": a <= b}[op]


def residual_exposure(before: int, status: str) -> int:
    """Contextual exposure score after the rescan outcome."""
    if status == "remediated":
        return max(2, round(before * 0.04))
    if status == "mitigated":
        return round(before * 0.30)
    return before


class SimulatedEnvironment:
    def __init__(self, scenario: Dict[str, Any], now: Optional[datetime] = None) -> None:
        sim = scenario["sim"]
        self.host: Dict[str, Any] = copy.deepcopy(sim["host"])
        self.vuln_check: Dict[str, Any] = copy.deepcopy(sim["vuln_check"])
        self.cve: str = scenario["signal"]["cve"]
        self.clock: datetime = (now or datetime.now(timezone.utc)).replace(microsecond=0)
        self.changes: Dict[str, Dict[str, Any]] = {}

    # ── ITSM ────────────────────────────────────────────────────────────────
    def open_change(self, spec: Dict[str, Any], package: Dict[str, Any], opened_by: str) -> Dict[str, Any]:
        rec = {
            "change_id": spec["change_id"], "short_description": spec["short_description"],
            "type": package["change_type"], "assignment_group": spec["assignment_group"], "cab": spec["cab"],
            "risk": package["risk_assessment"], "state": "New", "history": [],
        }
        self.changes[rec["change_id"]] = rec
        self._record(rec, "New", opened_by, "Change drafted from the AI change package")
        return rec

    def transition(self, change_id: str, state: str, actor: str, note: str) -> None:
        rec = self.changes[change_id]
        rec["state"] = state
        self._record(rec, state, actor, note)

    def _record(self, rec: Dict[str, Any], state: str, actor: str, note: str) -> None:
        self.clock += timedelta(seconds=7)
        rec["history"].append({"at": _iso(self.clock), "state": state, "actor": actor, "note": note})

    def tick(self, seconds: int) -> None:
        self.clock += timedelta(seconds=seconds)

    def enter_window(self, window: Dict[str, str]) -> str:
        start = _parse_iso(window["start"])
        if self.clock < start:
            self.clock = start
        return f"Maintenance window '{window['label']}' open ({window['start']} - {window['end']})"

    # ── executor ────────────────────────────────────────────────────────────
    def execute(self, change_id: str, tasks: List[Dict[str, Any]]) -> Dict[str, Any]:
        host = self.host["hostname"]
        rec = self.changes[change_id]
        lines: List[Tuple[str, str]] = [("play", f"PLAY [{rec['short_description']}] " + "*" * 12)]
        ok = changed = failed = 0
        for task in tasks:
            lines.append(("task", f"TASK [{task['name']}] " + "*" * 10))
            effect = task.get("effect") or {}
            passed, detail = self._apply(effect)
            self.tick(_MODULE_SECONDS.get(task.get("module", ""), 3))
            if not passed:
                failed += 1
                lines.append(("failed", f"fatal: [{host}]: FAILED! => {detail}"))
                break
            if task.get("changed"):
                changed += 1
                lines.append(("changed", f"changed: [{host}]{detail}"))
            else:
                ok += 1
                lines.append(("ok", f"ok: [{host}]{detail}"))
        total_ok = ok + changed
        lines.append(("play", "PLAY RECAP " + "*" * 12))
        lines.append(("recap", f"{host:<18}: ok={total_ok} changed={changed} unreachable=0 failed={failed} skipped=0"))
        return {"lines": lines, "ok": total_ok, "changed": changed, "failed": failed, "finished_at": _iso(self.clock)}

    def _apply(self, effect: Dict[str, Any]) -> Tuple[bool, str]:
        h = self.host
        detail = ""
        if "assert_version" in effect:
            pkg, op, target = effect["assert_version"]
            current = h["packages"].get(pkg, "0")
            if not _cmp(parse_version(current), op, parse_version(target)):
                return False, f'{{"msg": "Assertion failed: {pkg} {current} {op} {target}"}}'
            detail = f' => {{"msg": "{pkg} {current} {op} {target} - assertion passed"}}'
        if "package" in effect:
            pkg, version = effect["package"]
            h["packages"][pkg] = version
            detail = f' => {{"name": "{pkg}", "version": "{version}"}}'
        if "service" in effect:
            name, state = effect["service"]
            h["services"][name] = state
            detail = f' => {{"name": "{name}", "state": "{state}"}}'
        if "rule" in effect:
            for rule in effect["rule"]:
                if rule not in h["rules"]:
                    h["rules"].append(rule)
            detail = f' => {{"rules_added": {effect["rule"]}}}'
        if "content_version" in effect:
            h["content_version"] = effect["content_version"]
            detail = f' => {{"content_version": "{effect["content_version"]}"}}'
        if "replace_artifact" in effect:
            old, new_list = effect["replace_artifact"]
            h["artifacts"] = [a for a in h["artifacts"] if not a.startswith(old)] + list(new_list)
            detail = f' => {{"dest": "{new_list[0]}", "state": "file"}}'
        return True, detail

    # ── verification rescan ─────────────────────────────────────────────────
    def rescan(self, deep: bool = True) -> Dict[str, Any]:
        """deep=False models the original inventory-based detection (top-level archives only)."""
        check = self.vuln_check
        self.tick(95)
        kind = check["type"]
        method = check["method"]
        if kind == "version_by_train":
            result = self._scan_version_by_train(check)
        elif kind == "version_by_train_with_mitigation":
            result = self._scan_panos(check)
        else:
            result = self._scan_artifacts(check, deep)
            if not deep:
                method = "Package inventory agent (top-level archives only)"
        result.update({"cve": self.cve, "host": self.host["hostname"], "method": method, "scanned_at": _iso(self.clock)})
        return result

    def _scan_version_by_train(self, c: Dict[str, Any]) -> Dict[str, Any]:
        pkg = c["package"]
        installed = self.host["packages"].get(pkg, "0")
        v = parse_version(installed)
        trains = {tuple(int(x) for x in k.split(".")): parse_version(val) for k, val in c["fixed_trains"].items()}
        if v < parse_version(c["min_affected"]):
            vulnerable = False
        elif v[:2] in trains:
            vulnerable = v < trains[v[:2]]
        else:
            vulnerable = v[:2] < max(trains)
        if vulnerable:
            return {"status": "vulnerable", "finding_state": "OPEN", "evidence": [f"{pkg} {installed} is in the affected range"],
                    "headline": f"{pkg} {installed} is still below the fixed release for its train."}
        fixed = ".".join(str(x) for x in trains.get(v[:2], v))
        return {"status": "remediated", "finding_state": "FIXED", "evidence": [f"{pkg} {installed} >= fixed release {fixed}"],
                "headline": f"{pkg} {installed} is at or above the fixed release ({fixed})."}

    def _scan_panos(self, c: Dict[str, Any]) -> Dict[str, Any]:
        installed = self.host["packages"]["panos"]
        v = parse_version(installed)
        v = v + (0,) * (4 - len(v))
        train = ".".join(str(x) for x in v[:3])
        fixed_h = c["fixed"].get(train)
        affected = fixed_h is not None and v[3] < int(fixed_h[1:])
        if not affected:
            return {"status": "remediated", "finding_state": "FIXED", "evidence": [f"PAN-OS {installed} is a fixed build"],
                    "headline": f"PAN-OS {installed} is a fixed build."}
        content_ok = parse_version(self.host.get("content_version", "0-0").replace("-", ".")) >= parse_version("8836.8695")
        mitigated = content_ok and all(r in self.host["rules"] for r in c["mitigation_rules"])
        if mitigated:
            return {"status": "mitigated", "finding_state": "MITIGATED",
                    "evidence": [f"PAN-OS {installed} still below fixed build 10.2.6-h3", "Detection probe blocked: Threat ID 95187 hit logged",
                                 "Vulnerability Protection profile bound to the GlobalProtect interface"],
                    "headline": f"Affected build {installed} is still installed, but the detection probe was blocked by Threat ID 95187."}
        return {"status": "vulnerable", "finding_state": "OPEN", "evidence": [f"PAN-OS {installed} is affected and no effective mitigation is active"],
                "headline": f"PAN-OS {installed} is affected and the probe reached the vulnerable code path."}

    def _scan_artifacts(self, c: Dict[str, Any], deep: bool = True) -> Dict[str, Any]:
        pattern = re.compile(c["pattern"])
        fixed = parse_version(c["fixed_version"])
        entries = [a for a in self.host["artifacts"] if deep or "!/" not in a]
        bad = []
        for path in entries:
            m = pattern.search(path)
            if m and parse_version(m.group(1)) < fixed:
                bad.append(path)
        inspected = len(entries)
        scope = "nested archives included" if deep else "nested archives not inspected"
        if bad:
            noun = "copy" if len(bad) == 1 else "copies"
            return {"status": "vulnerable", "finding_state": "OPEN",
                    "evidence": [f"Vulnerable copy: {p}" for p in bad] + [f"{inspected} classpath entries inspected, {scope}"],
                    "headline": f"{len(bad)} vulnerable log4j-core {noun} on the classpath" + (f": {bad[0].split('/')[-1]}" if len(bad) == 1 else ".")}
        return {"status": "remediated", "finding_state": "FIXED",
                "evidence": [f"{inspected} classpath entries inspected, {scope}", "No log4j-core below 2.17.1 found"],
                "headline": "No log4j-core below 2.17.1 found, including nested archives."}
