# Evaluate CRBF

This folder contains the scripts used for evaluating CRBF reports and data needed for it (created and used in August 2026). The folder is structured as follows:

1. **Data** folder: contains input data, 

Two stages, deliberately separated.
 
| Stage | Script | Cost | Output |
|---|---|---|---|
| Execute | `run.py` | slow, hard to repeat | `raw/<project>/c<n>.json`, `runs.csv` |
| Normalise | `parse.py` | seconds, repeatable | `findings.csv` |
 
Raw output is never overwritten. A parsing mistake is fixed by re-running
`parse.py`, not by re-running the tools.
 
## Order of work
 
```
python3 cvss.py                      # self-test, must exit 0
python3 run.py   --projects projects.csv --out ../data --workdir ../checkouts
python3 parse.py --data ../data --projects projects.csv
```
 
Start with one project and `--only c1` to confirm the flags before the batch.
 
## projects.csv
 
```
project_id,repo_url,commit_hash,build_cmd,uberjar_path,plugin_goal
```
 
## Verify before the collection run
 
1. The `osv-scanner` flags in `build_commands`, against the installed version.
2. The plugin goal and output flags for configuration 3.
3. `parse_framework` against a real report from the framework.
4. That the uber-JAR declares `Main-Class`; configuration 2 depends on it.
5. That `cvss.py` exits 0.
## Decisions recorded here
 
- Configurations 1 and 2 are ranked by descending CVSS base score, with the
  vulnerability identifier as tie-breaker. Neither tool orders its own output.
- Vulnerability identity is canonicalised to the CVE identifier where an alias
  exists, so that GHSA and CVE records join correctly.
- A build failure records an errored run and the batch continues.
