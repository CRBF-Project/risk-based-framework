"""Normalises the raw tool output into one wide findings table.

Responsibility: read raw/, produce findings.csv. Runs in seconds and can be
re-run as often as needed without touching the tools.

Row unit follows Ponta et al. (2020): one row per
(project, module, dependency, vulnerability), with one boolean column per
configuration recording whether that configuration reported the finding.

Usage
    python3 parse.py --data ../data
"""

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

from cvss import base_score

CONFIGS = ("c1", "c2", "c3")

FIELDS = [
    "project_id", "commit_hash", "module_artifact_id",
    "group_id", "artifact_id", "version", "dependency_type", "cve_id",
    "c1_reported", "c2_reported", "c3_reported",
    "c1_rank", "c2_rank", "c3_rank",
    "c2_reachable", "c3_reachable", "c3_reach_status", "c3_evidence",
    "c3_decision", "cvss", "epss", "c3_risk_score",
    "c1_error", "c2_error", "c3_error",
    "category",
]


def split_coordinates(name):
    """Split a Maven package name into (group_id, artifact_id)."""
    if ":" in name:
        group, _, artifact = name.partition(":")
        return group.strip(), artifact.strip()
    return "", name.strip()


def canonical_id(vulnerability):
    """Prefer the CVE identifier over the GHSA identifier, upper-cased.

    Both tools must refer to the same vulnerability by the same name, or the
    join produces spurious disagreement. OSV records carry CVE identifiers in
    the aliases list when the primary identifier is a GHSA. Case is normalised
    because OSV-Scanner emits GHSA identifiers in lower case while the
    framework emits them in upper case.
    """
    aliases = [str(a).upper() for a in vulnerability.get("aliases", []) or []]
    primary = str(vulnerability.get("id", "")).upper()
    if primary.startswith("CVE-"):
        return primary
    for alias in aliases:
        if alias.startswith("CVE-"):
            return alias
    return primary


def cvss_vector(vulnerability):
    for entry in vulnerability.get("severity", []) or []:
        if str(entry.get("type", "")).startswith("CVSS_V3"):
            return entry.get("score", "")
    for affected in vulnerability.get("affected", []) or []:
        for entry in affected.get("severity", []) or []:
            if str(entry.get("type", "")).startswith("CVSS_V3"):
                return entry.get("score", "")
    return ""


# --------------------------------------------------------------------------
# Adapters. One per configuration. Each returns a list of finding dicts.
# Only these three functions know a tool's output format.
# --------------------------------------------------------------------------

def parse_osv(document, project_id, with_reachability):
    """Adapter for OSV-Scanner JSON. Covers configurations 1 and 2."""
    findings = []
    for result in document.get("results", []) or []:
        source = str(result.get("source", {}).get("path", ""))
        module = Path(source).parent.name if source else ""

        for package in result.get("packages", []) or []:
            info = package.get("package", {})
            group_id, artifact_id = split_coordinates(info.get("name", ""))
            version = info.get("version", "")

            # OSV-Scanner precomputes a numeric severity per group. Prefer it:
            # many advisories now carry only a CVSS v4 vector, which the v3
            # calculator cannot score, and this value covers both.
            max_severity = {}
            called_ids = set()
            for group in package.get("groups", []) or []:
                severity = group.get("max_severity", "")
                for identifier in (group.get("ids", []) or []) + (group.get("aliases", []) or []):
                    if severity not in ("", None):
                        max_severity[str(identifier).upper()] = severity
                analysis = (group.get("experimental_analysis")
                            or group.get("experimentalAnalysis")
                            or {})
                for key, value in analysis.items():
                    if isinstance(value, dict) and value.get("called"):
                        called_ids.add(key)
                        called_ids.update(group.get("ids", []) or [])

            for vulnerability in package.get("vulnerabilities", []) or []:
                raw_id = vulnerability.get("id", "")
                called = raw_id in called_ids or bool(
                    called_ids and set(vulnerability.get("aliases", [])) & called_ids
                )
                # Configuration 1 performs no reachability analysis, so every
                # vulnerability it knows about is reported.
                reported = True if not with_reachability else called
                findings.append({
                    "project_id": project_id,
                    "module_artifact_id": module,
                    "group_id": group_id,
                    "artifact_id": artifact_id,
                    "version": version,
                    "dependency_type": "",
                    "cve_id": canonical_id(vulnerability),
                    "reported": reported,
                    "reachable": called if with_reachability else "",
                    "evidence": "",
                    "cvss_vector": cvss_vector(vulnerability),
                    "cvss_score": max_severity.get(
                        str(raw_id).upper(),
                        max_severity.get(canonical_id(vulnerability), ""),
                    ),
                    "epss": "",
                    "risk_score": "",
                })
    return findings


def parse_framework(document, project_id):
    """Adapter for the proposed framework's risk-report.json. Configuration 3.

    Structure of the report:
        findings[]              one entry per vulnerable artifact
          .artifact             "groupId:artifactId:version"
          .vulnerabilities[]    .id, .aliases, .cvss.score, .epss.score
          .reachability         .reachable, .status, .reachableMethods[]
          .remediation          .decision, .riskReduction, .recommendedVersion

    Reachability, remediation and risk are recorded per artifact, not per
    vulnerability, so every vulnerability of an artifact inherits the same
    values. See the note in the README before drawing conclusions from this.
    """
    findings = []
    for entry in document.get("findings", []) or []:
        parts = str(entry.get("artifact", "")).split(":")
        group_id = parts[0] if len(parts) > 0 else ""
        artifact_id = parts[1] if len(parts) > 1 else ""
        version = parts[2] if len(parts) > 2 else ""

        reachability = entry.get("reachability", {}) or {}
        reachable = bool(reachability.get("reachable"))
        methods = reachability.get("reachableMethods", []) or []
        remediation = entry.get("remediation", {}) or {}

        for vulnerability in entry.get("vulnerabilities", []) or []:
            cvss = vulnerability.get("cvss", {}) or {}
            epss = vulnerability.get("epss", {}) or {}
            vector = cvss.get("vector", "")
            findings.append({
                "project_id": project_id,
                "module_artifact_id": document.get("projectName", ""),
                "group_id": group_id,
                "artifact_id": artifact_id,
                "version": version,
                "dependency_type": "",
                "cve_id": canonical_id(vulnerability),
                "reported": reachable,
                "reachable": reachable,
                "reach_status": reachability.get("status", ""),
                "evidence": " | ".join(methods),
                "cvss_vector": "" if vector in ("", "UNKNOWN") else vector,
                "cvss_score": cvss.get("score", ""),
                "epss": epss.get("score", ""),
                "risk_score": remediation.get("riskReduction", ""),
                "decision": remediation.get("decision", ""),
            })
    return findings


ADAPTERS = {
    "c1": lambda doc, pid: parse_osv(doc, pid, with_reachability=False),
    "c2": lambda doc, pid: parse_osv(doc, pid, with_reachability=True),
    "c3": parse_framework,
}


def key_of(finding):
    """Join key for a finding.

    The module is deliberately excluded. OSV-Scanner derives the module name
    from the path of the descriptor it scanned, while the framework reports the
    Maven artifactId, so including it would split rows that describe the same
    finding. Module is kept as an informational column (first non-empty value
    wins). This is a documented simplification: two modules of the same project
    depending on the same vulnerable version collapse into one row. State it in
    the limitations of the evaluation chapter.
    """
    return (
        finding["project_id"],
        finding["group_id"],
        finding["artifact_id"],
        finding["version"],
        finding["cve_id"],
    )


def assign_ranks(rows, config):
    """Rank each configuration's reported findings within each project.

    Configurations 1 and 2 impose no ordering of their own, so they are ranked
    by descending CVSS base score with the vulnerability identifier as
    tie-breaker. This models what a developer would do with an unordered
    report and makes the ordering deterministic. Configuration 3 is ranked by
    its own risk score. Record this decision in notas-defesa.md.
    """
    by_project = defaultdict(list)
    for row in rows:
        if row[f"{config}_reported"] == "true":
            by_project[row["project_id"]].append(row)

    for project_rows in by_project.values():
        if config == "c3":
            def sort_key(row):
                score = row["c3_risk_score"]
                return (-float(score) if score not in ("", None) else 0.0,
                        row["cve_id"])
        else:
            def sort_key(row):
                score = row["cvss"]
                return (-float(score) if score not in ("", None) else 0.0,
                        row["cve_id"])
        for position, row in enumerate(sorted(project_rows, key=sort_key), start=1):
            row[f"{config}_rank"] = position


def categorise(row):
    """Label the agreement pattern, following Ponta et al.'s categories.

    The disagreement categories are where the sampling effort goes.
    C1 alone   — discarded by both reachability analyses
    C1,C2      — package-level reachable, method-level not: the core claim
    C1,C3      — method-level reachable, package-level missed it
    C1,C2,C3   — all three agree
    """
    reported = [c.upper() for c in CONFIGS if row[f"{c}_reported"] == "true"]
    return "+".join(reported) if reported else "NONE"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="../data")
    parser.add_argument("--projects", default="projects.csv")
    args = parser.parse_args()

    data_dir = Path(args.data).resolve()
    raw_dir = data_dir / "raw"

    commits = {}
    try:
        with open(args.projects, newline="", encoding="utf-8") as handle:
            for project in csv.DictReader(handle):
                commits[project["project_id"]] = project.get("commit_hash", "")
    except FileNotFoundError:
        pass

    rows = {}
    for project_dir in sorted(p for p in raw_dir.iterdir() if p.is_dir()):
        project_id = project_dir.name
        for config in CONFIGS:
            path = project_dir / f"{config}.json"
            if not path.exists():
                # Mark the whole project as errored for this configuration.
                for row in rows.values():
                    if row["project_id"] == project_id:
                        row[f"{config}_error"] = "true"
                continue
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                print(f"{project_id}/{config}: unparseable ({exc})")
                continue

            for finding in ADAPTERS[config](document, project_id):
                key = key_of(finding)
                if key not in rows:
                    rows[key] = {field: "" for field in FIELDS}
                    rows[key].update({
                        "project_id": finding["project_id"],
                        "commit_hash": commits.get(project_id, ""),
                        "module_artifact_id": finding["module_artifact_id"],
                        "group_id": finding["group_id"],
                        "artifact_id": finding["artifact_id"],
                        "version": finding["version"],
                        "cve_id": finding["cve_id"],
                    })
                    for other in CONFIGS:
                        rows[key][f"{other}_reported"] = "false"
                        rows[key][f"{other}_error"] = "false"

                row = rows[key]
                if not row["module_artifact_id"] and finding["module_artifact_id"]:
                    row["module_artifact_id"] = finding["module_artifact_id"]
                row[f"{config}_reported"] = "true" if finding["reported"] else "false"
                if config in ("c2", "c3") and finding["reachable"] != "":
                    row[f"{config}_reachable"] = str(finding["reachable"]).lower()
                if finding["dependency_type"]:
                    row["dependency_type"] = finding["dependency_type"]
                if finding["evidence"]:
                    row["c3_evidence"] = finding["evidence"]
                if finding.get("reach_status"):
                    row["c3_reach_status"] = finding["reach_status"]
                if finding.get("decision"):
                    row["c3_decision"] = finding["decision"]
                if finding["epss"] != "":
                    row["epss"] = finding["epss"]
                if finding["risk_score"] != "":
                    row["c3_risk_score"] = finding["risk_score"]
                if not row["cvss"]:
                    # The framework reports a numeric score directly; OSV only
                    # gives a vector, so it has to be computed.
                    reported_score = finding.get("cvss_score", "")
                    if reported_score not in ("", None) and float(reported_score) > 0:
                        row["cvss"] = reported_score
                    elif finding["cvss_vector"]:
                        score = base_score(finding["cvss_vector"])
                        row["cvss"] = "" if score is None else score

    ordered = list(rows.values())
    for config in CONFIGS:
        assign_ranks(ordered, config)
    for row in ordered:
        row["category"] = categorise(row)

    ordered.sort(key=lambda r: (r["project_id"], r["group_id"],
                                r["artifact_id"], r["cve_id"]))

    output = data_dir / "findings.csv"
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(ordered)

    counts = defaultdict(int)
    for row in ordered:
        counts[row["category"]] += 1
    print(f"{len(ordered)} findings written to {output}")
    for category, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {category:<12} {count}")


if __name__ == "__main__":
    main()