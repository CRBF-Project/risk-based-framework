"""Runs the three evaluation configurations over a set of Maven projects.

Responsibility: execute tools, preserve raw output, record run metadata.
This script does NOT interpret results. Parsing belongs to parse.py, so that
a parsing error can be fixed without re-running any tool.

Inputs
    projects.csv        one row per subject project

Outputs
    raw/<project_id>/c<n>.json      untouched tool output, never overwritten
    raw/<project_id>/c<n>.log       stderr and the exact command
    runs.csv                        one row per (project, configuration)

Usage
    python3 run.py --projects projects.csv --out ../data --workdir ../checkouts
    python3 run.py ... --only c1 c3       run a subset of configurations
    python3 run.py ... --project pdfbox   run a single project
"""

import argparse
import csv
import json
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

CONFIGS = ("c1", "c2", "c3")

RUNS_FIELDS = [
    "run_id", "project_id", "commit_hash", "config", "tool_version",
    "command", "started_at", "duration_s", "exit_code", "raw_path", "note",
]

# Per-configuration timeout in seconds. Static analysis on a large project can
# run for a long time; a timeout keeps one project from consuming the session.
TIMEOUT_S = 1800


def log(message):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}", flush=True)


def run_command(command, cwd, timeout=TIMEOUT_S):
    """Run a shell command and return (exit_code, stdout, stderr, duration)."""
    started = time.time()
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return completed.returncode, completed.stdout, completed.stderr, time.time() - started
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s", time.time() - started


def tool_version(config):
    """Record the tool version so the run is reproducible."""
    command = "mvn --version" if config == "c3" else "osv-scanner --version"
    code, out, _, _ = run_command(command, cwd=Path.cwd(), timeout=60)
    if code != 0:
        return "unknown"
    return out.strip().splitlines()[0] if out.strip() else "unknown"


# --------------------------------------------------------------------------
# Command construction
#
# Confirm every flag against the tool version actually installed before the
# collection run. The c2 form is the one verified on the probe: reachability
# analysis applied to an uber-JAR with Main-Class declared.
# --------------------------------------------------------------------------

def build_commands(project, out_dir):
    """Return {config: (command, raw_output_path)} for one project."""
    project_id = project["project_id"]
    raw_dir = out_dir / "raw" / project_id
    raw_dir.mkdir(parents=True, exist_ok=True)

    uberjar = project.get("uberjar_path") or "target/uber.jar"
    plugin_goal = project.get("plugin_goal") or (
        "org.crbf:risk-based-framework-maven-plugin:1.0-SNAPSHOT:analyse"
    )

    return {
        "c1": (
            "osv-scanner scan source"
            " --format json"
            f" --output {shlex.quote(str(raw_dir / 'c1.json'))}"
            " .",
            raw_dir / "c1.json",
        ),
        "c2": (
            "osv-scanner scan source"
            " --call-analysis=jar"
            " --experimental-plugins=artifact"
            " --format json"
            f" --output {shlex.quote(str(raw_dir / 'c2.json'))}"
            f" {shlex.quote(uberjar)}",
            raw_dir / "c2.json",
        ),
        # The two -D flags below are a guess at the plugin's output parameters.
        # If the plugin writes to a fixed path instead, clear plugin_out_args in
        # projects.csv and set plugin_report_path to that path; run.py will copy
        # the report into raw/ after the goal finishes.
        "c3": (
            f"mvn -B -fn {shlex.quote(plugin_goal)} "
            + (project.get("plugin_out_args") or "").format(
                out=str(raw_dir / "c3.json")
            ),
            raw_dir / "c3.json",
        ),
    }


def project_root(project, workdir):
    """Directory holding the POM. Not always the repository root."""
    return workdir / project["project_id"] / (project.get("pom_dir") or ".")


def prepare_project(project, workdir):
    """Clone at the pinned commit and build. Returns (path, error_or_None)."""
    project_id = project["project_id"]
    path = workdir / project_id

    if not path.exists():
        log(f"{project_id}: cloning")
        code, _, err, _ = run_command(
            f"git clone --quiet {shlex.quote(project['repo_url'])} {shlex.quote(str(path))}",
            cwd=workdir,
        )
        if code != 0:
            return path, f"clone failed: {err.strip()[:200]}"

    commit = project.get("commit_hash", "").strip()
    if commit:
        code, _, err, _ = run_command(
            f"git checkout --quiet {shlex.quote(commit)}", cwd=path
        )
        if code != 0:
            return path, f"checkout failed: {err.strip()[:200]}"

    root = project_root(project, workdir)
    if not (root / "pom.xml").exists():
        return root, f"no pom.xml in {root}"

    build_cmd = project.get("build_cmd") or "mvn -B -DskipTests package"
    log(f"{project_id}: building")
    code, _, err, duration = run_command(build_cmd, cwd=root)
    if code != 0:
        return root, f"build failed after {duration:.0f}s: {err.strip()[-200:]}"

    return root, None


def append_run(runs_path, row):
    exists = runs_path.exists()
    with runs_path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=RUNS_FIELDS)
        if not exists:
            writer.writeheader()
        writer.writerow(row)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--projects", default="projects.csv")
    parser.add_argument("--out", default="../data")
    parser.add_argument("--workdir", default="../checkouts")
    parser.add_argument("--only", nargs="+", default=list(CONFIGS),
                        choices=list(CONFIGS))
    parser.add_argument("--project", default=None,
                        help="run a single project_id")
    args = parser.parse_args()

    out_dir = Path(args.out).resolve()
    workdir = Path(args.workdir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    workdir.mkdir(parents=True, exist_ok=True)
    runs_path = out_dir / "runs.csv"

    with open(args.projects, newline="", encoding="utf-8") as handle:
        projects = list(csv.DictReader(handle))
    if args.project:
        projects = [p for p in projects if p["project_id"] == args.project]
    if not projects:
        sys.exit("no projects selected")

    versions = {config: tool_version(config) for config in args.only}
    log(f"tool versions: {versions}")

    for project in projects:
        project_id = project["project_id"]
        log(f"=== {project_id}")

        path, error = prepare_project(project, workdir)
        if error:
            # A build failure must not stop the batch. Record it: projects that
            # failed to build are excluded from the comparison and the exclusion
            # has to be reported in the evaluation chapter.
            log(f"{project_id}: SKIPPED — {error}")
            for config in args.only:
                append_run(runs_path, {
                    "run_id": f"{project_id}:{config}",
                    "project_id": project_id,
                    "commit_hash": project.get("commit_hash", ""),
                    "config": config,
                    "tool_version": versions.get(config, ""),
                    "command": "",
                    "started_at": datetime.now(timezone.utc).isoformat(),
                    "duration_s": 0,
                    "exit_code": -1,
                    "raw_path": "",
                    "note": error,
                })
            continue

        commands = build_commands(project, out_dir)
        for config in args.only:
            command, raw_path = commands[config]
            log(f"{project_id}: {config}")
            started = datetime.now(timezone.utc).isoformat()
            run_started_at = time.time()
            code, _, err, duration = run_command(command, cwd=path)

            note = ""
            if config == "c3":
                fallback = project.get("plugin_report_path", "").strip()
                if fallback and not raw_path.exists():
                    source = path / fallback
                    # Refuse a report older than this run: it is a leftover from
                    # a previous build and would be recorded as fresh data.
                    if not source.exists():
                        note = f"report not found at {fallback}"
                    elif source.stat().st_mtime < run_started_at:
                        note = f"stale report at {fallback}, not copied"
                    else:
                        raw_path.write_bytes(source.read_bytes())

            if not raw_path.exists():
                note = f"no output produced: {err.strip()[-200:]}"
            else:
                # OSV-Scanner exits non-zero when it finds vulnerabilities.
                # A non-zero exit with valid output is not an error.
                try:
                    json.loads(raw_path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError) as exc:
                    note = f"unparseable output: {exc}"

            (raw_path.parent / f"{config}.log").write_text(
                f"$ {command}\nexit={code}\n\n{err}", encoding="utf-8"
            )

            append_run(runs_path, {
                "run_id": f"{project_id}:{config}",
                "project_id": project_id,
                "commit_hash": project.get("commit_hash", ""),
                "config": config,
                "tool_version": versions.get(config, ""),
                "command": command,
                "started_at": started,
                "duration_s": round(duration, 1),
                "exit_code": code,
                "raw_path": os.path.relpath(raw_path, out_dir),
                "note": note,
            })
            log(f"{project_id}: {config} done in {duration:.0f}s (exit {code}) {note}")

    log(f"runs recorded in {runs_path}")


if __name__ == "__main__":
    main()