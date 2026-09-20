"""Runs the three evaluation configurations over a set of Maven projects.

Responsibility:
    Execute the three configurations, preserve raw outputs, and record run
    metadata. This script does not interpret results; result processing belongs
    to parse.py so that parsing logic can be changed without re-running the
    experiment.

Configurations:
    C1 = OSV-Scanner v2 without call-graph analysis
    C2 = OSV-Scanner v2 with Java call-graph analysis
    C3 = CRBF

Inputs:
    projects.csv        one row per subject project

Outputs:
    raw/<project_id>/c<n>.json
    raw/<project_id>/c<n>.log
    runs.csv

Usage:
    python3 run.py --projects projects.csv --out ../data --workdir ../checkouts

    # Run only selected configurations
    python3 run.py --projects projects.csv --out ../data \
        --workdir ../checkouts --only c1 c3

    # Run a single project
    python3 run.py --projects projects.csv --out ../data \
        --workdir ../checkouts --project spring-boot-security-jwt
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
    "run_id",
    "project_id",
    "commit_hash",
    "config",
    "tool_version",
    "command",
    "started_at",
    "duration_s",
    "exit_code",
    "raw_path",
    "note",
]

# Maximum duration of one complete configuration execution.
TIMEOUT_S = 1800

# Internal timeout used by CRBF for WALA call-graph construction.
CALL_GRAPH_TIMEOUT_S = 600


def log(message):
    print(
        f"[{datetime.now().strftime('%H:%M:%S')}] {message}",
        flush=True,
    )


def run_command(command, cwd, timeout=TIMEOUT_S):
    """Run a shell command.

    Returns:
        (exit_code, stdout, stderr, duration_seconds)
    """
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

        return (
            completed.returncode,
            completed.stdout,
            completed.stderr,
            time.time() - started,
        )

    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""

        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")

        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")

        stderr += f"\ntimeout after {timeout}s"

        return (
            124,
            stdout,
            stderr,
            time.time() - started,
        )


def tool_version(config):
    """Record the installed tool version used by each configuration."""

    if config in ("c1", "c2"):
        command = "osv-scanner --version"
    else:
        command = "mvn --version"

    code, stdout, _, _ = run_command(
        command,
        cwd=Path.cwd(),
        timeout=60,
    )

    if code != 0:
        return "unknown"

    return (
        stdout.strip().splitlines()[0]
        if stdout.strip()
        else "unknown"
    )


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------

def build_commands(project, out_dir):
    """Return {config: (command, raw_output_path)} for one project."""

    project_id = project["project_id"]

    raw_dir = out_dir / "raw" / project_id
    raw_dir.mkdir(parents=True, exist_ok=True)

    uberjar = (
        project.get("uberjar_path")
        or "target/uber.jar"
    ).strip()

    plugin_goal = (
        project.get("plugin_goal")
        or "org.crbf:risk-based-framework-maven-plugin:1.0-SNAPSHOT:analyse"
    ).strip()

    plugin_out_args = (
        project.get("plugin_out_args")
        or ""
    ).strip()

    # C1 and C2 intentionally differ only by --call-analysis=jar.
    #
    # This allows the effect of OSV-Scanner's reachability analysis to be
    # isolated while holding the scanner, artifact and remaining options fixed.
    c1_command = (
        "osv-scanner scan source"
        " --experimental-plugins=artifact"
        " --all-packages"
        " --format=json"
        f" --output-file {shlex.quote(str(raw_dir / 'c1.json'))}"
        f" {shlex.quote(uberjar)}"
    )

    c2_command = (
        "osv-scanner scan source"
        " --experimental-plugins=artifact"
        " --all-packages"
        " --call-analysis=jar"
        " --format=json"
        f" --output-file {shlex.quote(str(raw_dir / 'c2.json'))}"
        f" {shlex.quote(uberjar)}"
    )

    # CRBF uses a fixed call-graph timeout across evaluated projects.
    c3_command = (
        "mvn -B "
        f"-Dcontextframework.callGraphTimeoutSeconds={CALL_GRAPH_TIMEOUT_S} "
        f"{shlex.quote(plugin_goal)}"
    )

    if plugin_out_args:
        c3_command += " " + plugin_out_args.format(
            out=str(raw_dir / "c3.json")
        )

    return {
        "c1": (
            c1_command,
            raw_dir / "c1.json",
        ),
        "c2": (
            c2_command,
            raw_dir / "c2.json",
        ),
        "c3": (
            c3_command,
            raw_dir / "c3.json",
        ),
    }


def project_root(project, workdir):
    """Return the directory containing the project's pom.xml."""

    return (
        workdir
        / project["project_id"]
        / (project.get("pom_dir") or ".")
    )


def prepare_project(project, workdir):
    """Clone, checkout the pinned commit and build the project.

    Returns:
        (project_root, error_or_none)
    """

    project_id = project["project_id"]
    repository_path = workdir / project_id

    # ------------------------------------------------------------------
    # Clone
    # ------------------------------------------------------------------

    if not repository_path.exists():
        log(f"{project_id}: cloning")

        clone_command = (
            f"git clone --quiet "
            f"{shlex.quote(project['repo_url'])} "
            f"{shlex.quote(str(repository_path))}"
        )

        code, _, stderr, _ = run_command(
            clone_command,
            cwd=workdir,
        )

        if code != 0:
            return (
                repository_path,
                f"clone failed: {stderr.strip()[:200]}",
            )

    # ------------------------------------------------------------------
    # Checkout fixed commit
    # ------------------------------------------------------------------

    commit = project.get("commit_hash", "").strip()

    if commit:
        code, _, stderr, _ = run_command(
            f"git checkout --quiet {shlex.quote(commit)}",
            cwd=repository_path,
        )

        if code != 0:
            return (
                repository_path,
                f"checkout failed: {stderr.strip()[:200]}",
            )

    root = project_root(project, workdir)

    if not (root / "pom.xml").exists():
        return (
            root,
            f"no pom.xml in {root}",
        )

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    build_cmd = (
        project.get("build_cmd")
        or "mvn -B clean package -DskipTests"
    ).strip()

    log(f"{project_id}: building")

    code, _, stderr, duration = run_command(
        build_cmd,
        cwd=root,
    )

    if code != 0:
        return (
            root,
            (
                f"build failed after {duration:.0f}s: "
                f"{stderr.strip()[-200:]}"
            ),
        )

    # Ensure the exact pinned commit is the one actually analysed.
    if commit:
        code, stdout, stderr, _ = run_command(
            "git rev-parse HEAD",
            cwd=repository_path,
            timeout=60,
        )

        if code != 0:
            return (
                root,
                f"could not verify commit: {stderr.strip()[:200]}",
            )

        actual_commit = stdout.strip()

        if actual_commit != commit:
            return (
                root,
                (
                    f"commit mismatch: expected {commit}, "
                    f"got {actual_commit}"
                ),
            )

    return root, None


def append_run(runs_path, row):
    """Append one execution record to runs.csv."""

    exists = runs_path.exists()

    with runs_path.open(
        "a",
        newline="",
        encoding="utf-8",
    ) as handle:

        writer = csv.DictWriter(
            handle,
            fieldnames=RUNS_FIELDS,
        )

        if not exists:
            writer.writeheader()

        writer.writerow(row)


def write_log(
    log_path,
    command,
    exit_code,
    stdout,
    stderr,
):
    """Persist the exact command and complete process output."""

    content = (
        f"$ {command}\n"
        f"exit={exit_code}\n"
        "\n"
        "===== STDOUT =====\n"
        f"{stdout}\n"
        "\n"
        "===== STDERR =====\n"
        f"{stderr}\n"
    )

    log_path.write_text(
        content,
        encoding="utf-8",
    )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--projects",
        default="projects.csv",
    )

    parser.add_argument(
        "--out",
        default="../data",
    )

    parser.add_argument(
        "--workdir",
        default="../checkouts",
    )

    parser.add_argument(
        "--only",
        nargs="+",
        default=list(CONFIGS),
        choices=list(CONFIGS),
    )

    parser.add_argument(
        "--project",
        default=None,
        help="run a single project_id",
    )

    args = parser.parse_args()

    out_dir = Path(args.out).resolve()
    workdir = Path(args.workdir).resolve()

    out_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    workdir.mkdir(
        parents=True,
        exist_ok=True,
    )

    runs_path = out_dir / "runs.csv"

    # ------------------------------------------------------------------
    # Load project manifest
    # ------------------------------------------------------------------

    with open(
        args.projects,
        newline="",
        encoding="utf-8",
    ) as handle:

        projects = list(csv.DictReader(handle))

    if args.project:
        projects = [
            project
            for project in projects
            if project["project_id"] == args.project
        ]

    if not projects:
        sys.exit("no projects selected")

    # ------------------------------------------------------------------
    # Tool versions
    # ------------------------------------------------------------------

    versions = {
        config: tool_version(config)
        for config in args.only
    }

    log(f"tool versions: {versions}")

    # ------------------------------------------------------------------
    # Projects
    # ------------------------------------------------------------------

    for project in projects:
        project_id = project["project_id"]

        log(f"=== {project_id}")

        path, error = prepare_project(
            project,
            workdir,
        )

        # --------------------------------------------------------------
        # Build failure / invalid candidate
        # --------------------------------------------------------------

        if error:
            log(
                f"{project_id}: SKIPPED — {error}"
            )

            for config in args.only:
                append_run(
                    runs_path,
                    {
                        "run_id": f"{project_id}:{config}",
                        "project_id": project_id,
                        "commit_hash": project.get(
                            "commit_hash",
                            "",
                        ),
                        "config": config,
                        "tool_version": versions.get(
                            config,
                            "",
                        ),
                        "command": "",
                        "started_at": datetime.now(
                            timezone.utc
                        ).isoformat(),
                        "duration_s": 0,
                        "exit_code": -1,
                        "raw_path": "",
                        "note": error,
                    },
                )

            continue

        commands = build_commands(
            project,
            out_dir,
        )

        # --------------------------------------------------------------
        # C1 / C2 / C3
        # --------------------------------------------------------------

        for config in args.only:
            command, raw_path = commands[config]

            log(f"{project_id}: {config}")

            # Remove the previous raw result before executing the
            # configuration. This prevents stale data from being
            # interpreted as the output of the current run.
            if raw_path.exists():
                raw_path.unlink()

            # CRBF normally writes its report into the analysed project.
            # Remove an earlier report before running C3 so that any report
            # found afterwards must belong to this execution.
            if config == "c3":
                fallback = (
                    project.get("plugin_report_path")
                    or "target/risk-report.json"
                ).strip()

                source_report = path / fallback

                if source_report.exists():
                    source_report.unlink()

            started_at = datetime.now(
                timezone.utc
            ).isoformat()

            code, stdout, stderr, duration = run_command(
                command,
                cwd=path,
            )

            note = ""

            # ----------------------------------------------------------
            # C3 report collection
            # ----------------------------------------------------------

            if config == "c3" and not raw_path.exists():
                fallback = (
                    project.get("plugin_report_path")
                    or "target/risk-report.json"
                ).strip()

                source = path / fallback

                if not source.exists():
                    note = (
                        f"report not found at {fallback}"
                    )
                else:
                    raw_path.write_bytes(
                        source.read_bytes()
                    )

            # ----------------------------------------------------------
            # Validate raw output for all configurations
            # ----------------------------------------------------------

            if not raw_path.exists():
                if not note:
                    note = (
                        "no output produced: "
                        f"{stderr.strip()[-200:]}"
                    )
            else:
                try:
                    json.loads(
                        raw_path.read_text(
                            encoding="utf-8"
                        )
                    )

                except (
                    json.JSONDecodeError,
                    OSError,
                ) as exc:

                    note = (
                        f"unparseable output: {exc}"
                    )

            # ----------------------------------------------------------
            # Preserve execution log
            # ----------------------------------------------------------

            log_path = (
                raw_path.parent
                / f"{config}.log"
            )

            write_log(
                log_path,
                command,
                code,
                stdout,
                stderr,
            )

            # ----------------------------------------------------------
            # Run metadata
            # ----------------------------------------------------------

            append_run(
                runs_path,
                {
                    "run_id": (
                        f"{project_id}:{config}"
                    ),
                    "project_id": project_id,
                    "commit_hash": project.get(
                        "commit_hash",
                        "",
                    ),
                    "config": config,
                    "tool_version": versions.get(
                        config,
                        "",
                    ),
                    "command": command,
                    "started_at": started_at,
                    "duration_s": round(
                        duration,
                        1,
                    ),
                    "exit_code": code,
                    "raw_path": os.path.relpath(
                        raw_path,
                        out_dir,
                    ),
                    "note": note,
                },
            )

            log(
                f"{project_id}: {config} "
                f"done in {duration:.0f}s "
                f"(exit {code}) "
                f"{note}"
            )

    log(
        f"runs recorded in {runs_path}"
    )


if __name__ == "__main__":
    main()