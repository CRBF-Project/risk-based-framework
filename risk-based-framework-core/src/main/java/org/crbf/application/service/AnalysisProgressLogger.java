package org.crbf.application.service;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.compatibility.CompatibilityStatus;
import org.crbf.domain.model.optimisation.RemediationDecision;
import org.crbf.domain.model.optimisation.RemediationPlan;
import org.crbf.domain.model.reachability.VulnerabilityReachability;
import org.crbf.domain.model.stability.EcosystemStability;
import org.crbf.domain.model.stability.StabilityScore;
import org.crbf.domain.model.vulnerability.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.stream.Collectors;
import java.util.Optional;
import org.crbf.domain.model.optimisation.UpgradePathStatus;

public class AnalysisProgressLogger {

    private static final Logger LOG = LoggerFactory.getLogger(AnalysisProgressLogger.class);

    public void logAnalysisStart(String projectPath) {
        LOG.info("\n[Application] Starting the Contextualised Risk-Based Framework...");
        LOG.info("[Application] Target Project: {}", projectPath);
    }

    public void logGraphExtracted(int pathCount) {
        LOG.info("\n[Step 1] Extracting dependency graph...");
        LOG.info("[Step 1] Extracted {} dependency paths.", pathCount);
    }

    public void logGraphResolved(int uniqueCount) {
        LOG.info("[Step 1] Graph resolved successfully. Unique dependencies to analyse: {}", uniqueCount);
    }

    public void logUnresolvedJars(List<String> gavs) {
        LOG.warn(
                "[Step 1] {} artifact(s) could not be physically resolved — reachability analysis will be degraded for these:",
                gavs.size());
        gavs.forEach(gav -> LOG.warn("  - {}", gav));
    }

    public void logVulnerabilityScanStart() {
        LOG.info("[Step 2] Querying OSV for known vulnerabilities...");
    }

    public void logVulnerableArtifact(String gav, int cveCount) {
        LOG.info("\t[VULNERABLE] {} — {} CVE(s) found", gav, cveCount);
    }

    public void logJarUnresolvable(String gav) {
        LOG.warn("  [WARN] Could not resolve physical JAR for {}. Skipping reachability/breaking-change analysis.",
                gav);
    }

    public void logVulnerabilityLookupFailed(String gav, String reason) {
        LOG.error("  [ERROR] Vulnerability lookup failed for {}: {}", gav, reason);
        LOG.error("          Risk status for this artifact is UNKNOWN — it will appear in the report as unverified.");
    }

    public void logFixVersionLookupFailed(String fixVersion, String reason) {
        LOG.warn("  [WARN] Could not verify CVEs for fix version {}: {} — treating as unverified.",
                fixVersion, reason);
    }

    public void logScanComplete(int totalVulns) {
        LOG.info("[Step 2-3] Scan complete. Total CVEs found: {}", totalVulns);
    }

    public void logOptimisationStart() {
        LOG.info("\n[Step 4] Running Z3 optimisation...");
    }

    public void logAnalysisComplete() {
        LOG.info("=================================================================");
        LOG.info("  Analysis completed. HTML Dashboard in target/risk-report.html");
        LOG.info("==================================================================");
    }

    public void logFixJarUnresolvable(String gav, String fixVersion) {
        LOG.warn("  [WARN] Could not resolve fix JAR for {} → {}", gav, fixVersion);
    }

    public void logCompatibilityResult(
            String currentVersion, String fixVersion,
            CompatibilityStatus status, int count) {
        LOG.info("  [Breaking Changes] {} → {}: {} ({} changes)",
                currentVersion, fixVersion, status, count);
    }

    public void logBreakingChangeSample(List<String> changes, int limit) {
        changes.stream().limit(limit).forEach(bc -> LOG.info("    - {}", bc));
        if (changes.size() > limit) {
            LOG.info("    ... and {} more.", changes.size() - limit);
        }
    }

    // -------------------------------------------------------------------------
    // Vulnerability block
    // -------------------------------------------------------------------------

    public void logVulnerabilityBlock(Vulnerability v, VulnerabilityReachability result) {
        String fix = v.minimumFixVersion().isEmpty()
                ? "No fix version available"
                : "Upgrade to " + v.minimumFixVersion();

        String cwes = v.cwes().isEmpty()
                ? "None"
                : v.cwes().stream().map(c -> c.value()).collect(Collectors.joining(", "));

        LOG.info("  ┌─────────────────────────────────────────");
        LOG.info("  │ CVE:         {}", v.id().value());
        LOG.info("  │ Severity:    {}  (CVSS: {})", v.severity(), v.cvss().value());
        LOG.info("  │ Reachable:   {}{}",
                result.status(),
                result.status().isReachable()
                        ? " (" + result.reachableMethods().size() + " methods invoked)"
                        : "");
        LOG.info("  │ Fix:         {}", fix);
        LOG.info("  │ CWEs:        {}", cwes);
        LOG.info("  └─────────────────────────────────────────");
    }

    // -------------------------------------------------------------------------
    // Stability
    // -------------------------------------------------------------------------

    public void logStability(Artifact artifact, EcosystemStability s, String label) {
        LOG.info("  ┌─ Stability [{}] ─ {}", label, artifact.gav());
        LOG.info("  │  Latest:     {}", s.latestVersion());
        LOG.info("  │  TOOD:       {} days", s.tood().value());
        LOG.info("  │  VersionLag: {} releases", s.versionLag().value());
        LOG.info("  │  Adoption:   {}%", String.format("%.0f", s.adoptionRate().value() * 100));
        LOG.info("  │  Maint Rate: {} rel/day", String.format("%.4f", s.maintenanceRate().value()));
        LOG.info("  │  Urgency:    {}", String.format("%.2f", StabilityScore.stalenessUrgencyOf(s)));
        LOG.info("  └────────────────────────────────────────");
    }

    public void logStabilityLoaded(String label, Artifact artifact, EcosystemStability s) {
        LOG.info("  [Goblin/{}] {} — TOOD: {} days, Lag: {}, Adoption: {}%",
                label, artifact.gav(),
                s.tood().value(), s.versionLag().value(),
                String.format("%.0f", s.adoptionRate().value() * 100));
    }

    public void logStabilityFailed(String label, String gav, String reason) {
        LOG.warn("  [Goblin/{}] Failed to load stability for {}: {}", label, gav, reason);
    }

    // -------------------------------------------------------------------------
    // Upgrade path validation
    // -------------------------------------------------------------------------

    public void logUpgradeValidationStart(String gav, String fixVersion) {
        LOG.info("  [UpgradeValidation] Validating upgrade path for {} → {}", gav, fixVersion);
    }

    public void logGoblinUnavailableForValidation(String gav) {
        LOG.info("  [UpgradeValidation] Goblin unavailable — transitive diff skipped for {}", gav);
    }

    public void logTransitiveDiff(int added, int removed) {
        LOG.info("  [UpgradeValidation] Transitive diff — added: {}, removed: {}", added, removed);
    }

    public void logNewVulnerableTransitiveDeps(List<Artifact> deps) {
        LOG.info("  [UpgradeValidation] New vulnerable transitive deps: {}", deps.size());
        deps.forEach(dep -> LOG.info("    - {}", dep.gav()));
    }

    public void logUpgradeValidationResult(
            UpgradePathStatus status,
            Optional<Double> securitySignal) {

        String signal = securitySignal.map(value -> String.format("%.2f", value)).orElse("unavailable");
        LOG.info("  [UpgradeValidation] Path status: {} | Security signal: {}", status, signal);
    }

    public void logGoblinUnavailableUsingOsvFix(String osvFix) {
        LOG.info("  [UpgradeValidation] Goblin unavailable — using OSV fix: {}", osvFix);
    }

    public void logNoCleanCandidateFallback(String osvFix) {
        LOG.info("  [UpgradeValidation] No clean candidate found — falling back to OSV fix: {}", osvFix);
    }

    public void logFixVersionHasCves(String fixVersion, int count) {
        LOG.warn("  [UpgradeValidation] Fix version {} has {} CVE(s)", fixVersion, count);
    }

    // -------------------------------------------------------------------------
    // Remediation plan
    // -------------------------------------------------------------------------

    public void logRemediationPlan(RemediationPlan plan) {
        LOG.info("\n╔══════════════════════════════════════════════════════════════════╗");
        LOG.info("║  Z3 Optimal Remediation Plan  ({})",
                plan.solvedByZ3() ? "SMT-Optimal" : "Greedy Fallback");
        LOG.info("╚══════════════════════════════════════════════════════════════════╝");

        List<RemediationDecision> upgrades = plan.upgradeRecommendations();
        List<RemediationDecision> deferred = plan.deferredDecisions();

        if (upgrades.isEmpty()) {
            LOG.info("  No upgrades recommended (no fixable vulnerabilities found).");
        } else {
            LOG.info("\n  ── RECOMMENDED UPGRADES ──");
            upgrades.forEach(d -> {
                LOG.info("\n  ✔ UPGRADE  {} → {}", d.artifact().gav(), d.targetVersion());
                LOG.info("    Risk Reduction : {}", String.format("%.2f", d.riskReduction()));
                LOG.info("    Effort Cost    : {} units", String.format("%.1f", d.effortCost()));
                LOG.info("    Rationale      : {}", d.rationale());
            });
        }

        if (!deferred.isEmpty()) {
            LOG.info("\n  ── DEFERRED / NO FIX ──");
            deferred.forEach(d -> {
                LOG.info("\n  ✘ DEFER    {}", d.artifact().gav());
                LOG.info("    Rationale : {}", d.rationale());
            });
        }

        LOG.info("\n  ── SUMMARY ──");
        LOG.info("  Total Risk Reduction : {}", String.format("%.2f", plan.totalRiskReduction()));
        LOG.info("  Residual Risk        : {}", String.format("%.2f", plan.totalResidualRisk()));
        LOG.info("  Total Effort Used    : {} units", String.format("%.1f", plan.totalEffortCost()));
        LOG.info("═══════════════════════════════════════════════════════════════════");
    }

    // -------------------------------------------------------------------------
    // Global graph validation
    // -------------------------------------------------------------------------

    public void logGlobalValidationNoUpgrades() {
        LOG.info("\n[Step 4.5] No upgrades to validate globally.");
    }

    public void logGlobalValidationStart(List<Artifact> fixArtifacts) {
        LOG.info("\n[Step 4.5] Global graph validation — {} fix version(s)", fixArtifacts.size());
        fixArtifacts.forEach(a -> LOG.info("  - {}", a.gav()));
    }

    public void logGlobalValidationUnavailable() {
        LOG.info("  [Step 4.5] Goblin unavailable — global validation skipped.");
    }

    public void logGlobalValidationClean() {
        LOG.info("  [Step 4.5] Global graph is CLEAN — no new vulnerable deps.");
    }

    public void logGlobalValidationHasRisks(List<Artifact> vulnerableDeps) {
        LOG.warn("  [Step 4.5] Global graph HAS RISKS — {} vulnerable dep(s) detected:",
                vulnerableDeps.size());
        vulnerableDeps.forEach(dep -> LOG.warn("    - {}", dep.gav()));
    }

}
