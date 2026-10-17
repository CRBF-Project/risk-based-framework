# CRBF Evaluation

## Requirements

- Python 3.10+, Git, Maven 3.9.16 and Java 17.
- OSV-Scanner 2.7.0.
- Internet access to GitHub, Maven repositories, OSV and EPSS.
- Goblin Weaver running at `http://localhost:8080` by default.

## Structure

```text
evaluation/
  scripts/        # Scripts and projects pinned to fixed commits
  tests/          # Script tests
  results/
    raw/          # Tool reports and SBOMs per project
    normalised/   # CSV files for comparison
    summaries/    # Per-project summaries
    diagnostics/  # Inventory and coordinate differences
    summary.json  # Global summary
    projects.csv  # Evaluated projects
    runs.csv      # Commands, durations and statuses
  archive/        # Complete data and local logs; excluded from Git
  checkouts/      # Project checkouts; excluded from Git
```

## Run

From the repository root, select Java 17 and install the plugin:

```bash
export JAVA_HOME=/path/to/jdk17
export PATH="$JAVA_HOME/bin:$PATH"
mvn -DskipTests install
```

Run all six projects with an effort budget of 30:

```bash
python3 evaluation/scripts/run.py \
  --osv /path/to/osv-scanner-2.7.0 \
  --java-home "$JAVA_HOME" \
  --out evaluation/archive/new-run
```

The new run's output and checkout directories must not already exist.
To run a single project, add `--project my-blog`.

Create a copy for publication in a new or empty directory:

```bash
python3 evaluation/scripts/parse.py \
  --data evaluation/archive/new-run \
  --publish --out /tmp/public-evaluation
```

Regenerate the saved normalised results without running the tools or requiring
external services:

```bash
python3 evaluation/scripts/parse.py --data evaluation/results
```
