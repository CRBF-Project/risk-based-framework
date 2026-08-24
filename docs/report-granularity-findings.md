# Report granularity and export format — findings

Investigation only. No source files were modified. All line numbers refer to
the state of the repository on 2026-08-23 (branch `main`).

---

## Summary

Reachability **is** computed per vulnerability, not per artifact — one
`VulnerabilityReachability` object is produced for every CVE. But the report
assembler collapses that list back down to a single value per artifact before
serialisation, and the per-vulnerability detail (including a `vulnerableMethods`
field that is sometimes populated) is discarded at that point, not before.

Separately, and more importantly for the dissertation's comparative claim:
there is no CVE-to-vulnerable-method database anywhere in the codebase, and
none exists publicly that OSV could supply. The "method-level" distinction the
framework claims over OSV-Scanner is produced by a regex heuristic that greps
the CVE's free-text summary/description for CamelCase tokens and matches them
against class names inside the vulnerable JAR. When that heuristic finds
nothing — which, empirically, is the common case — the framework falls back to
"every method of this JAR that the call graph reaches", i.e. exactly the
package/JAR-level granularity OSV-Scanner already provides. So even fixing the
report's serialisation would not, by itself, give the framework method-level
resolution for most findings; it would just make honest the fact that most
findings are class/JAR-level, with a minority genuinely class-level and a
smaller minority carrying an unverified guess at the specific method.

I also found that `evaluation/scripts/parse.py`, written for this same
dissertation, already documents the per-artifact collapse in its own
docstring and explicitly calls it "the core claim" at risk (see §6). That
file is worth reading before deciding what to build.

---

## Q1 — Where does reachability granularity actually live?

**Reachability is computed once per vulnerability.** The port contract is
explicit about this:

- [`AnalyseReachabilityPort.analyseReachability`](../risk-based-framework-core/src/main/java/org/crbf/application/port/out/AnalyseReachabilityPort.java#L34-L37) — `@return One {@link VulnerabilityReachability} per vulnerability.`
- [`SootUpReachabilityAdapter.analyseReachability`](../risk-based-framework-core/src/main/java/org/crbf/adapter/out/soot/SootUpReachabilityAdapter.java#L124-L126) computes `reachableFromJar` **once** per artifact (lines 108–110, before the vulnerability loop), then maps each vulnerability individually through `classifyVulnerability` (lines 143–170), which can return a **different** `ReachabilityStatus` per CVE (`REACHABLE_CONFIRMED` vs `REACHABLE_PROBABLE`) depending on whether that CVE's own text yielded a class-name match.
- [`AnalyseDependencyRiskService.analyseArtifact`](../risk-based-framework-core/src/main/java/org/crbf/application/service/AnalyseDependencyRiskService.java#L151-L153) calls this once per artifact, receiving `List<VulnerabilityReachability> reachabilityResults` — one entry per CVE.

**This per-vulnerability list is then collapsed to a single artifact-level
value, and the collapse happens at two points:**

1. [`AnalyseDependencyRiskService.aggregateReachability`](../risk-based-framework-core/src/main/java/org/crbf/application/service/AnalyseDependencyRiskService.java#L230-L243) takes the **max** `ReachabilityStatus.severity()` across all of an artifact's `VulnerabilityReachability` results. The method's own comment (lines 230–237) states this plainly: *"different CVEs of the same artifact can have different status ... Taking the maximum ensures the artifact-level decision ... reflects the highest-confidence reachability signal available."* This single status becomes `RemediationCandidate.reachabilityStatus` ([RemediationCandidate.java:41](../risk-based-framework-core/src/main/java/org/crbf/domain/model/optimisation/RemediationCandidate.java#L41)) — used for Z3's objective function, which is legitimate: the optimiser decides per artifact (an upgrade is all-or-nothing for a GAV), so an artifact-level input is correct there.
2. [`RiskReportAssembler.toReachabilitySummary`](../risk-based-framework-core/src/main/java/org/crbf/application/service/RiskReportAssembler.java#L92-L102) is the point that matters for the report. It builds **one** `ReachabilitySummary` per `ArtifactFinding` from `candidate.reachabilityStatus()` (the aggregate) and `candidate.reachabilityReports()` **flat-mapped and deduplicated across every vulnerability** (`.flatMap(r -> r.reachableMethodIds().stream())...distinct()`). The per-CVE status differences and the per-CVE `vulnerableMethods` set (populated only for `REACHABLE_CONFIRMED`, see Q2) are both dropped here — `ReachabilitySummary` ([ReachabilitySummary.java](../risk-based-framework-core/src/main/java/org/crbf/application/model/report/ReachabilitySummary.java)) and `CveSummary` ([CveSummary.java](../risk-based-framework-core/src/main/java/org/crbf/application/model/report/CveSummary.java)) have no field to carry it, and `ArtifactFinding` ([ArtifactFinding.java](../risk-based-framework-core/src/main/java/org/crbf/application/model/report/ArtifactFinding.java)) attaches `reachability` once, next to `vulnerabilities`, not inside each vulnerability.

So: **computed per vulnerability, discarded at report-assembly time** (step 2), after already being lossily aggregated for the optimiser (step 1, which is defensible on its own terms).

**Confirmed live** in the repository's own last analysis run,
[`risk-based-framework-core/target/risk-report.json`](../risk-based-framework-core/target/risk-report.json): the `com.fasterxml.jackson.core:jackson-databind:2.16.1` finding (lines 6–122) lists 5 CVEs under one `reachability` block (lines 99–103), and `ch.qos.logback:logback-core:1.5.6` (lines 267–397) lists 6 CVEs under one `reachability` block (lines 377–381) — the exact pattern described in the brief. (The brief's specific `plexus-utils:3.0.22` example does not reproduce verbatim in this run — the resolved version is `3.5.1` with a single CVE that scores `UNREACHABLE` — but the underlying mechanism, and its effect wherever an artifact carries ≥2 CVEs, is directly visible in the two findings above.)

**`ReachabilityStatus` values** ([ReachabilityStatus.java](../risk-based-framework-core/src/main/java/org/crbf/domain/model/reachability/ReachabilityStatus.java)) and what produces each:

| Status | Produced when | Where |
|---|---|---|
| `UNREACHABLE` | Call graph built successfully, but no method of any class in the vulnerable JAR is called from application code (`reachableFromJar` is empty) | [SootUpReachabilityAdapter.java:120-122](../risk-based-framework-core/src/main/java/org/crbf/adapter/out/soot/SootUpReachabilityAdapter.java#L120-L122) |
| `UNKNOWN` | Call graph is empty (SootUp failed / no compiled classes), no physical JAR path available, or an exception during matching | [SootUpReachabilityAdapter.java:92-99,128-131](../risk-based-framework-core/src/main/java/org/crbf/adapter/out/soot/SootUpReachabilityAdapter.java#L92-L99); the app layer treats `UNKNOWN` conservatively as reachable for risk purposes (`isReachable()` returns true), see [ReachabilityStatus.java:28-30](../risk-based-framework-core/src/main/java/org/crbf/domain/model/reachability/ReachabilityStatus.java#L28-L30) |
| `REACHABLE_PROBABLE` | The JAR is reachable (≥1 of its classes is called), but no CamelCase token extracted from the CVE's `summary`/`description` text matches the simple name of any class inside that JAR | [SootUpReachabilityAdapter.java:168-169](../risk-based-framework-core/src/main/java/org/crbf/adapter/out/soot/SootUpReachabilityAdapter.java#L168-L169) |
| `REACHABLE_CONFIRMED` | A CamelCase token from the CVE text matches a class's simple name, that class is among the JAR's classes, **and** at least one method of that class appears in the call graph | [SootUpReachabilityAdapter.java:150-165](../risk-based-framework-core/src/main/java/org/crbf/adapter/out/soot/SootUpReachabilityAdapter.java#L150-L165) |

So "probable" does not mean "probably confirmed" in any statistical sense — it
means **"we could not extract a class name from the CVE's prose, so we fell
back to reporting every reachable method of the whole JAR."** It is a
regex-match failure mode, not a graded confidence score.

---

## Q2 — Is there a CVE-to-vulnerable-method mapping at all?

**No.** There is no dataset, database, or external source anywhere in the
codebase that maps a vulnerability identifier to the method(s) or class(es)
it affects. Confirmed by:

- `grep`-level search of every adapter under `adapter/out/` for anything
  resembling a vulnerable-function database (e.g. Eclipse Steady/Vulas,
  Snyk's function-level data, GitHub's `patch_url`-derived diffs) — none exists.
- [`OsvVulnerabilityMapper.toDomain`](../risk-based-framework-core/src/main/java/org/crbf/adapter/out/osv/OsvVulnerabilityMapper.java#L35-L73) parses OSV's response into `Vulnerability` using only: CVSS vector/score, minimum fix version (from `affected[].ranges[].events[].fixed`), CWE ids, aliases, summary/description text, and reference URLs. Nothing from OSV's `affected[].ecosystem_specific` or `database_specific` blocks is consumed for method/class identification, and OSV does not publish that data for Maven advisories in the first place.

**What actually happens instead** is the heuristic in
[`SootUpReachabilityAdapter`](../risk-based-framework-core/src/main/java/org/crbf/adapter/out/soot/SootUpReachabilityAdapter.java):

1. `CLASS_TOKEN_PATTERN` (line 54–55, `\b([A-Z][A-Za-z0-9]{2,})\b`) scans `vulnerability.summary()` and `vulnerability.description()` for CamelCase-looking tokens (`extractClassNameCandidates`, lines 319–324).
2. If any token's simple name matches a class actually present in the vulnerable JAR, that class is treated as "the vulnerable class" (`classifyVulnerability`, lines 150–158) → `REACHABLE_CONFIRMED`.
3. `inferVulnerableMethods` (lines 340–356) then applies a second heuristic — `METHOD_TOKEN_PATTERN` (line 58–59) looks for method-call-shaped tokens (`foo(`, `#foo`) in the same free text and intersects them by name (case-insensitive) with the confirmed class's reachable methods. This produces the `vulnerableMethods` set on `VulnerabilityReachability` — **but this field is never read anywhere outside the domain/optimisation layer.** It is not part of `RemediationCandidate`'s public surface used by the assembler beyond `reachabilityStatus`/`reachabilityReports`, and `RiskReportAssembler` never calls `.vulnerableMethods()` or `.vulnerableMethodIds()` on any `VulnerabilityReachability` (verified: no reference to `vulnerableMethod` anywhere in `RiskReportAssembler.java`). It is computed, then genuinely discarded — this is the one part of the pipeline where "computed and thrown away" is literally true.
4. If step 2 fails to find a class name (the common case — most CVE summaries describe *behaviour*, e.g. "Directory Traversal vulnerability in its extractFile method", not always with a resolvable class token, and even when they do the token has to exactly equal a class's simple name) → `REACHABLE_PROBABLE`, and `reachableMethods` becomes **the entire set of the JAR's methods that the call graph reaches**, regardless of which CVE is asking (`classifyVulnerability` line 169, passing the whole `reachableFromJar` set computed once per artifact).

**So, directly answering the brief's own hypothesis:** for any
`REACHABLE_PROBABLE` result (which the two real findings inspected in Q1
both are), `reachableMethods` is exactly "methods of the dependency reached
from the application entry point, irrespective of any vulnerability." There
is no per-CVE narrowing at all in that branch — every CVE of that artifact
gets the identical list, because it's computed from the artifact's call graph
subset, not from anything about the CVE.

**Coverage when a vulnerability's text yields no usable class token:**
silently falls back to `REACHABLE_PROBABLE` with the artifact-wide reachable
set — no distinct "unmapped" status, no logged warning distinguishable from a
genuine JAR-level match at the `ReachabilityStatus` level (there is a
`LOG.debug` line, [SootUpReachabilityAdapter.java:168](../risk-based-framework-core/src/main/java/org/crbf/adapter/out/soot/SootUpReachabilityAdapter.java#L168), but nothing surfaces to the report).

---

## Q3 — Risk attribution

**Per-vulnerability risk quantities do not exist.** `RemediationCandidate.contextualRisk` ([RemediationCandidate.java:111-153](../risk-based-framework-core/src/main/java/org/crbf/domain/model/optimisation/RemediationCandidate.java#L111-L153)) computes one score per artifact using:

- `maxCvss` — the **maximum** CVSS across the artifact's vulnerabilities (line 116-119)
- `maxEpss` — the **maximum** EPSS across the artifact's vulnerabilities, defaulting to `0.5` if none has an EPSS score (line 121-125)
- `stalenessUrgency` — from Goblin ecosystem data, artifact-level by nature
- `reachabilityWeight` — from the single aggregated `reachabilityStatus` (Q1)
- `pfetMultiplier`, `pathQualityFactor` — both artifact/upgrade-path properties

There is no summation or per-CVE weighting: the highest-severity CVE and the
highest-probability-of-exploitation CVE (which need not be the same CVE)
each contribute their single worst value, and the other CVEs on that artifact
contribute nothing extra to the score.

**`riskReduction`, `effortCost`, `decision` — origin and units:**

- Both come from [`Z3RemediationAdapter`](../risk-based-framework-core/src/main/java/org/crbf/adapter/out/z3/Z3RemediationAdapter.java), one `RemediationDecision` per candidate (i.e. per artifact) — [RemediationDecision.java](../risk-based-framework-core/src/main/java/org/crbf/domain/model/optimisation/RemediationDecision.java). `riskReduction` = `RemediationCandidate.contextualRisk()` if the optimiser chooses to upgrade, else `0.0` ([Z3RemediationAdapter.java:184-191](../risk-based-framework-core/src/main/java/org/crbf/adapter/out/z3/Z3RemediationAdapter.java#L184-L191)).
- **Unit of `riskReduction`:** none — it is the dimensionless output of the weighted-sum formula in `contextualRisk()` (roughly CVSS(0-10)×0.5 + EPSS(0-1)×10×0.3 + staleness(0-1)×10×0.2, then scaled by reachability/path/PFET multipliers). Not a probability, not a monetary figure, not time. Comparable only to other `riskReduction` values from the same run with the same weights.
- **Unit of `effortCost`:** an ordinal 1–4 scale keyed to the fix version's API-compatibility category — `COMPATIBLE=1.0, UNKNOWN=2.0, SOURCE_INCOMPATIBLE=3.0, BINARY_INCOMPATIBLE=4.0` ([RemediationCandidate.java:160-170](../risk-based-framework-core/src/main/java/org/crbf/domain/model/optimisation/RemediationCandidate.java#L160-L170)). Not hours, not story points, not a measured migration cost — a fixed lookup table, compared against a budget in the same made-up units (`effortBudget`, default `10.0`, [AnalyseMojo.java:82-83](../risk-based-framework-maven-plugin/src/main/java/org/crbf/plugin/AnalyseMojo.java#L82-L83)).
- `decision` (`MANDATORY`/`RECOMMENDED`/`DEFER`) is computed in [`RiskReportAssembler.resolveDecisionLabel`](../risk-based-framework-core/src/main/java/org/crbf/application/service/RiskReportAssembler.java#L159-L167): `MANDATORY` if Z3 says upgrade **and** the artifact's aggregated reachability is reachable; `RECOMMENDED` if Z3 says upgrade but the artifact is not reachable; `DEFER` otherwise. Per-artifact, same aggregation dependency as Q1.

**EPSS: reported per vulnerability, consumed per artifact.** [`EpssAdapter.enrich`](../risk-based-framework-core/src/main/java/org/crbf/adapter/out/epss/EpssAdapter.java#L42-L60) correctly attaches a distinct EPSS score to each `Vulnerability` (confirmed in the real report — each CVE under `jackson-databind` carries its own `epss.score`/`percentile`, lines 15-18, 33-36, etc. of the sample report). That per-CVE value is faithfully serialised into `CveSummary.epss` ([RiskReportAssembler.java:82](../risk-based-framework-core/src/main/java/org/crbf/application/service/RiskReportAssembler.java#L82)) and is genuinely per-vulnerability in the JSON. But it feeds `contextualRisk()` — and therefore `riskReduction` and the optimiser's decisions — only via `maxEpss` (artifact-level maximum, see above). So EPSS is **displayed** per vulnerability but **used** at artifact granularity; the two are decoupled today with no per-CVE risk output at all.

---

## Q4 — Export format coupling

- **Producer:** [`ReportGeneratorAdapter.exportReport`](../risk-based-framework-core/src/main/java/org/crbf/adapter/out/export/ReportGeneratorAdapter.java#L36-L56), the sole implementation of `ExportRiskReportPort`. It Jackson-serialises the `RiskReport` object to `risk-report.json` (line 45-46) and separately renders `risk-report.html` by string-replacing a `REPORT_DATA_PLACEHOLDER` token in a bundled template (`/report-template.html` on the classpath) with the same JSON string (lines 49-51, 58-67). **The HTML dashboard is not a second format** — it is the identical JSON embedded in a static page.
- **Not a direct domain dump.** There is a dedicated report/DTO layer: everything under `org.crbf.application.model.report` (`RiskReport`, `ArtifactFinding`, `CveSummary`, `ReachabilitySummary`, `RemediationSummary`, `CompatibilitySummary`, etc.) is distinct from the domain model (`org.crbf.domain.model.*`). [`RiskReportAssembler`](../risk-based-framework-core/src/main/java/org/crbf/application/service/RiskReportAssembler.java) is the single mapping point between the two. This is good news for restructuring: the domain layer (in particular `RemediationCandidate.reachabilityReports()`, which already holds the full per-vulnerability list) does not need to change at all to alter what the JSON looks like — only `RiskReportAssembler` and the report DTOs do.
- **Cost of restructuring to (dependency, vulnerability) granularity:** the reachability data needed is already sitting in `RemediationCandidate.reachabilityReports()` in the right shape (`List<VulnerabilityReachability>`, one per CVE, order-aligned with `RemediationCandidate.vulnerabilities()` — both built from the same `vulnerabilities` list in [`SootUpReachabilityAdapter.analyseReachability`](../risk-based-framework-core/src/main/java/org/crbf/adapter/out/soot/SootUpReachabilityAdapter.java#L124-L126)). Reachability is therefore cheap to move down to per-CVE (see Option A, §5). Remediation is not: `riskReduction`/`effortCost`/`decision` are fundamentally artifact-scoped in the domain (Z3 optimises one boolean "upgrade this GAV or not" per artifact, not per CVE — Q3), so a genuinely per-CVE remediation figure requires either duplicating the artifact-level number onto every CVE row (cheap, slightly misleading) or computing a new, separate per-CVE contribution to the risk formula that doesn't exist today (more work, see Option B).
- **Output path:** **not configurable.** `ReportGeneratorAdapter` hardcodes the filenames `risk-report.json`/`risk-report.html` (lines 45, 49), and the output directory is hardcoded by the caller as `projectPath.resolve("target")` ([AnalyseDependencyRiskService.java:135](../risk-based-framework-core/src/main/java/org/crbf/application/service/AnalyseDependencyRiskService.java#L135)). `AnalyseMojo` exposes no `@Parameter` for an output path or filename (only `effortBudget`, `osvApiUrl`, `goblinUrl`, and the five risk-weight parameters — [AnalyseMojo.java:78-142](../risk-based-framework-maven-plugin/src/main/java/org/crbf/plugin/AnalyseMojo.java#L78-L142)). **No other export formats exist** — no CSV, no SARIF, no CycloneDX/SPDX SBOM.

**This directly matters for the evaluation harness already in this repo.**
`evaluation/scripts/run.py` guesses at a configurable output path for
configuration 3 (this framework) and has a fallback comment for exactly this
situation:

> `# The two -D flags below are a guess at the plugin's output parameters. / # If the plugin writes to a fixed path instead, clear plugin_out_args in / # projects.csv and set plugin_report_path to that path; run.py will copy / # the report into raw/ after the goal finishes.` — [run.py:110-113](../evaluation/scripts/run.py#L110-L113)

Per this investigation, the plugin **does** write to a fixed path
(`target/risk-report.json`, always). Unless `projects.csv` already sets
`plugin_report_path` and clears `plugin_out_args` accordingly, the `-D`
flags guessed at in `run.py` do nothing and configuration 3's raw output
capture should be checked before relying on any results already collected
with it.

---

## Q5 — VEX feasibility

No mention of VEX, CycloneDX, PURL, or SBOM exists anywhere in this
repository (`grep -rniE "vex|cyclonedx|purl|sbom"` across all `.java`/`.xml`/`.md`, excluding `target/`, returns nothing) — this would be built from nothing, not extended.

### Recommendation: OpenVEX, not CycloneDX VEX

OpenVEX is the right fit for a one-week addition:

- It is a minimal, self-contained JSON-LD document — `@context`, `@id`,
  `author`, `timestamp`, `version`, and a `statements[]` array. Each statement
  needs a `vulnerability.name`, `products[].@id` (a package URL), a `status`,
  and — only for `not_affected` — a `justification`.
- A package URL for every finding is a one-line derivation from data the
  report already has: `Artifact.gav()` ([Artifact.java:18-20](../risk-based-framework-core/src/main/java/org/crbf/domain/model/artifact/Artifact.java#L18-L20)) is already `groupId:artifactId:version`, so `pkg:maven/{groupId}/{artifactId}@{version}` is a direct string format, no dependency needed.
- CycloneDX VEX, by contrast, is normally emitted as (or alongside) a full
  CycloneDX BOM, with `bom-ref` targets resolving into a complete SBOM
  component tree. This project produces no SBOM today; standing one up
  correctly (component tree, licenses, hashes, `bom-ref` wiring) is a
  separate, larger piece of work than the VEX statements themselves and is
  out of scope for a one-week timebox. CycloneDX does support an "embedded
  VEX-only" flavor without a full component list, but at that point it is
  materially more ceremony than OpenVEX for the same information content,
  with no compensating benefit for this project's needs.

### Mapping the framework's reachability statuses onto VEX

| Framework status | VEX status | Justification (if `not_affected`) | Evidence the framework actually has |
|---|---|---|---|
| `UNREACHABLE` | `not_affected` | `vulnerable_code_not_in_execute_path` | **Yes.** The call graph was built and no method of the artifact's classes appears in it. This is exactly what the justification means, and the framework has direct static-analysis evidence for it. |
| `REACHABLE_CONFIRMED` with non-empty `vulnerableMethods` | `affected` | n/a (justification only applies to `not_affected`) | **Yes, qualified.** The specific method the heuristic flagged is genuinely in the call graph — but "the CVE text happened to contain a token matching this method's name" is weak provenance for an `action_statement`; would need to be worded as "believed affected" rather than a confident VEX assertion, and OpenVEX has no confidence field to carry that caveat honestly. |
| `REACHABLE_CONFIRMED` with empty `vulnerableMethods` (class matched, no method) | `affected` | n/a | **Partial.** Class-level match only; same caveat as above, one level less specific. |
| `REACHABLE_PROBABLE` | *(no honest mapping — see below)* | — | **No.** This is the crux of the whole brief: the framework only knows "some class in this JAR is used"; it has no evidence at all about whether the *specific vulnerable code* is reached, because (Q2) it never identified what the vulnerable code is. |
| `UNKNOWN` | `under_investigation` | n/a | **Yes**, honestly — this is what `under_investigation` is for. |

**`REACHABLE_PROBABLE` cannot be honestly mapped to either `affected` or
`not_affected`.** Marking it `affected` overstates the evidence (identical to
what OSV-Scanner already asserts at package level, which the dissertation is
explicitly trying to improve on). Marking it `not_affected` would be worse —
actively wrong, since the JAR genuinely is reachable and the vulnerable code
might be too. The only honest mapping is `under_investigation`, with an
`impact_statement` noting the JAR-level (not method-level) evidence. That
is a real, if unglamorous, deliverable: it is more honest than what the
current JSON report already claims (`reachable: true` with no distinction
from a confirmed case), but it does not deliver the class of finding
("framework proves component X is *not affected* despite the JAR containing
a known-vulnerable class") that would make for a compelling VEX-vs-OSV
comparison chapter.

### What VEX requires that the framework does not currently produce

1. **A per-(product, vulnerability) affected status** — blocked directly
   behind Q1: today the JSON has one reachability status per artifact, not
   one per CVE. The underlying domain data (`RemediationCandidate.reachabilityReports()`) already has it; only the report layer needs to change (Option A, below) to unblock this specifically for VEX purposes — Z3/remediation figures do not need to be per-CVE for VEX, only reachability does.
2. **A package identifier scheme (PURL)** — trivial to derive (above), but
   currently absent; nothing in the codebase builds one today.
3. **A documented `author` identity and timestamp policy** for the VEX
   document (OpenVEX requires both) — a process decision, not a code change.
4. **A defensible justification per `not_affected` statement** — the
   framework already has this for `UNREACHABLE` today; it has nothing usable
   for the `REACHABLE_PROBABLE` majority case, and inventing one would
   misrepresent the analysis.

---

## Is per-vulnerability reachability achievable, and at what cost?

**Surfacing what is already computed: yes, cheaply.** The
`VulnerabilityReachability` records already exist per CVE, in the right
order, inside `RemediationCandidate.reachabilityReports()`. Making the JSON
report reflect that is a change confined to `RiskReportAssembler` and the
`application.model.report` DTOs — no domain or adapter code needs to change.

**Getting genuine method-level resolution for the `REACHABLE_PROBABLE`
majority: no, not in a week.** That would require either (a) a real
CVE→function mapping data source, which does not exist for OSV/Maven at the
coverage this project would need, or (b) diffing the vulnerable JAR against
its fix version to derive changed methods automatically (a JApiCmp-adjacent
technique — the project already depends on JApiCmp for compatibility
analysis, which is a promising angle for a *future* iteration, but reversing
its breaking-change detection into "which method changed between vulnerable
and fixed version" and then validating that change actually addresses the
CVE is materially new engineering, not a report change). This is out of
scope for the stated timebox and should not be attempted before the
dissertation deadline.

---

## Implementation options

### Option A — Expose the per-vulnerability reachability that already exists

**What changes:** Add a reachability field to `CveSummary` (or a sibling
DTO), populated in `RiskReportAssembler.toCveSummary`/`toCveSummaries` by
zipping `candidate.vulnerabilities()` with `candidate.reachabilityReports()`
(same list, same order, produced together in `SootUpReachabilityAdapter`) —
carrying `status`, `reachableMethodIds()`, and `vulnerableMethodIds()` per
CVE. Keep the existing artifact-level `ArtifactFinding.reachability` as-is
(additive change) or repurpose it as an "artifact-level rollup" with a note
that it is a maximum, not a shared fact.

**What it buys:** The report stops implying that three unrelated CVEs share
one reachability fact. Cases like the `jackson-databind`/`logback-core`
findings above become visibly heterogeneous where the underlying analysis
already found heterogeneity (e.g. a `logback-core` CVE that happened to match
a class name would show `REACHABLE_CONFIRMED` next to five siblings still at
`REACHABLE_PROBABLE`, rather than all six inheriting one value). This is also
the prerequisite for Q5 (VEX needs per-CVE status). It does **not** change
what `REACHABLE_PROBABLE` means or improve its resolution — it just stops
hiding the CONFIRMED/PROBABLE split that already exists between sibling CVEs.

**Estimated effort:** 4–6 hours (new/extended DTO, assembler change, a few
unit tests around the zip logic — note there are currently no unit tests for
`SootUpReachabilityAdapter` at all, see §6 — and a manual re-run against a
project with mixed-status CVEs on one artifact to confirm the shape).

**What breaks:** Nothing, if done additively. `evaluation/scripts/parse.py`'s
`parse_framework` (lines 122-170) reads `entry["reachability"]` at the
artifact level and does not need to change; it could optionally be updated to
also read the new per-CVE field once it exists, but its current per-artifact
reading keeps working unmodified. The HTML dashboard template
(`report-template.html`) would need a small update to display the new field
if it currently renders reachability once per artifact card — not verified
in this investigation (template not read; out of scope for a read-only pass
focused on the Java pipeline, worth a 10-minute check before starting).

### Option B — Restructure the report so the record unit is (dependency, vulnerability)

**What changes:** Replace or supplement `ArtifactFinding` with a flattened
list where each entry is one CVE, carrying its own artifact reference,
reachability (from Option A), and remediation figures. Because remediation is
genuinely artifact-scoped in the domain (Q3), this requires a decision:
either duplicate the artifact's single `riskReduction`/`effortCost`/`decision`
onto every CVE row (cheap, but readers may sum them and get a number that
double-counts), or compute a new per-CVE contribution — e.g. that CVE's own
CVSS/EPSS run through the same weighting formula, reported as "this CVE's
share of the artifact's risk" — which is new logic, not just new plumbing.

**What it buys:** A report shape that matches how the dissertation's own
evaluation script already wants to consume it (`parse.py`'s `key_of`, line
180-197, joins on `(project, group, artifact, version, cve_id)` — i.e. it
already treats (dependency, vulnerability) as the natural unit and currently
reconstructs it by exploding the artifact-level JSON itself, lines 148-169).
Restructuring the source report to match removes that reconstruction step
from the evaluation pipeline.

**Estimated effort:** 10–16 hours (new DTO shape, assembler rewrite, decide
and implement the remediation semantics above, update `report-template.html`
if it groups by artifact card — likely a non-trivial rework of that template,
not scoped here — regenerate and diff against a real run, update this
project's own tests).

**What breaks:** The JSON shape changes for every consumer.
`evaluation/scripts/parse.py`'s `parse_framework` would need rewriting (it
currently assumes `findings[].artifact` + nested `vulnerabilities[]` with
one shared `reachability`/`remediation` per finding — a genuinely flattened
report changes that contract). The HTML dashboard almost certainly needs
rework since it likely groups the display by artifact. Higher risk of running
past the stated one-week budget once the remediation-semantics decision above
is factored in — recommend deciding that specific question before starting,
not while mid-implementation.

### Option C — Do Option A, and additionally emit an OpenVEX document

**What changes:** Everything in Option A, plus a new adapter
(`OpenVexExportAdapter` or similar) invoked alongside `ReportGeneratorAdapter`
from the same `analyse()` call, building one OpenVEX `statements[]` entry per
(artifact, CVE) pair using the per-CVE reachability from Option A and the
status/justification mapping in Q5. `REACHABLE_PROBABLE` and `UNKNOWN` both
map to `under_investigation`; `UNREACHABLE` maps to `not_affected` with
`vulnerable_code_not_in_execute_path`; `REACHABLE_CONFIRMED` maps to
`affected`.

**What it buys:** A second, standard-format artifact the dissertation can
point to directly when the supervisor asks "why not VEX" — and, more
substantively, forces the honest `REACHABLE_PROBABLE → under_investigation`
distinction to be made explicit rather than staying folded into a generic
`reachable: true`, which is itself a useful clarifying side-effect independent
of whether VEX ships.

**Estimated effort:** Option A's 4–6 hours, plus 6–10 hours for the VEX
adapter itself (PURL construction, statement building, JSON-LD context
boilerplate, a couple of golden-file tests, wiring into the Mojo/service).
Total 10–16 hours — realistically the bulk of one weekend, tight but plausible
within the stated "one working week of evenings plus one weekend" if Option A
is done first and reused.

**What breaks:** Nothing existing — this is additive (a new output file,
e.g. `target/risk-report.openvex.json`, alongside the current two). The only
risk is scope creep if the justification-per-status question (Q5) is
relitigated mid-implementation instead of settled up front.

---

## Findings that contradict or complicate the brief

1. **The brief's specific example does not currently reproduce.** In this
   run's own `risk-based-framework-core/target/risk-report.json`,
   `plexus-utils` resolves to `3.5.1` (not `3.0.22`) with a single CVE
   (`CVE-2025-67030`) at `UNREACHABLE` (not `REACHABLE_PROBABLE`). The
   mechanism the brief describes is real and directly observable elsewhere in
   the same file (`jackson-databind`, `logback-core`), just not at the exact
   coordinates quoted — worth re-running against `simple-consumer` directly
   (not found in this repository checkout, see below) before citing a
   specific example in the dissertation text.
2. **No `simple-consumer` test project exists in this checkout.**
   `find . -iname "*simple-consumer*"` returns nothing. If it's the source of
   the brief's example, it lives outside this repository or was removed.
3. **No unit tests exist for `SootUpReachabilityAdapter`.** `find` across
   both modules' `src/test` trees for anything matching `soot`/`reachab*`
   returns nothing. The class implementing the entire reachability heuristic
   — the mechanism this whole investigation is about — has no test coverage
   in the repository as checked out.
4. **`evaluation/scripts/parse.py` already independently documents this
   exact limitation**, in its own words, before this investigation started:
   `parse_framework`'s docstring states *"Reachability, remediation and risk
   are recorded per artifact, not per vulnerability, so every vulnerability
   of an artifact inherits the same values. See the note in the README before
   drawing conclusions from this."* ([parse.py:132-134](../evaluation/scripts/parse.py#L132-L134)). Its `categorise` function further labels the OSV-vs-framework agreement pattern
   `C1,C2` as *"package-level reachable, method-level not: the core claim"*
   ([parse.py:234](../evaluation/scripts/parse.py#L234)) — implying the evaluation's headline result depends on the framework
   (`c3`) resolving at genuinely finer granularity than OSV-Scanner (`c2`).
   Given Q1/Q2's findings, that premise holds only for the `REACHABLE_CONFIRMED`
   subset of results, not the `REACHABLE_PROBABLE` majority — the evaluation's
   framing may need to be revisited regardless of which report-format option
   is chosen.
5. **The README note that `parse.py` refers to does not exist.**
   `evaluation/README.md` contains no text matching "per artifact", "per
   vulnerability", "inherit", or "note" (checked directly). Either the note
   was never written or was written somewhere else — worth locating or
   writing before the docstring's reader goes looking for it.
6. **The evaluation harness's own output-path handling for this plugin is
   speculative and, per this investigation, wrong as written.**
   `evaluation/scripts/run.py` (lines 110-113) guesses at `-D` flags for a
   configurable plugin output path, with an explicit comment acknowledging
   the guess and describing a fallback (`plugin_report_path` +
   copy-after-run) for the case where the plugin writes to a fixed path. Q4
   establishes that the plugin **always** writes to a fixed path
   (`target/risk-report.json`); there is no `-D` flag for it. Any
   configuration-3 raw output already collected via the guessed flags should
   be checked for whether the fallback copy path was actually engaged.
