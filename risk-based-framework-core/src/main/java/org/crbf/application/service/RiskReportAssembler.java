package org.crbf.application.service;

import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.crbf.application.model.report.ArtifactFinding;
import org.crbf.application.model.report.CompatibilitySummary;
import org.crbf.application.model.report.CveSummary;
import org.crbf.application.model.report.CvssSummary;
import org.crbf.application.model.report.EpssSummary;
import org.crbf.application.model.report.GlobalGraphValidationSummary;
import org.crbf.application.model.report.GraphValidationStatus;
import org.crbf.application.model.report.ReachabilitySummary;
import org.crbf.application.model.report.RemediationSummary;
import org.crbf.application.model.report.ResidualRiskSummary;
import org.crbf.application.model.report.RiskReport;
import org.crbf.application.model.report.UpgradeDecision;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.DependencyPath;
import org.crbf.domain.model.compatibility.CompatibilityReport;
import org.crbf.domain.model.compatibility.CompatibilityStatus;
import org.crbf.domain.model.optimisation.GlobalGraphValidation;
import org.crbf.domain.model.optimisation.RemediationCandidate;
import org.crbf.domain.model.optimisation.RemediationDecision;
import org.crbf.domain.model.optimisation.RemediationPlan;
import org.crbf.domain.model.optimisation.RiskWeights;
import org.crbf.domain.model.risk.ContextualRisk;
import org.crbf.domain.model.vulnerability.AlternativeFix;
import org.crbf.domain.model.vulnerability.Vulnerability;
import org.crbf.application.model.report.AlternativeFixSummary;

public class RiskReportAssembler {

        private final RiskWeights riskWeights;

        public RiskReportAssembler() {
                this(RiskWeights.defaults());
        }

        public RiskReportAssembler(RiskWeights riskWeights) {
                this.riskWeights = riskWeights == null ? RiskWeights.defaults() : riskWeights;
        }

        public RiskReport assemble(
                        Path projectPath,
                        List<DependencyPath> dependencyGraph,
                        Set<Artifact> uniqueArtifacts,
                        List<RemediationCandidate> candidates,
                        RemediationPlan plan,
                        List<String> vulnerabilityLookupFailures) {

                List<ArtifactFinding> findings = candidates.stream()
                                .map(candidate -> toFinding(candidate, findDecision(plan, candidate)))
                                .toList();

                List<String> scannedArtifacts = uniqueArtifacts.stream()
                                .map(Artifact::gav)
                                .toList();

                return new RiskReport(
                                projectPath.getFileName().toString(),
                                uniqueArtifacts.size(),
                                dependencyGraph.size(),
                                scannedArtifacts,
                                findings,
                                toResidualRiskSummary(candidates, plan),
                                toGlobalValidationSummary(plan.globalGraphValidation()),
                                vulnerabilityLookupFailures);
        }

        /**
         * Splits residual risk (deferred candidates' contextual risk) into
         * "actionable" — a fix or a known migration path exists, it just wasn't
         * selected or isn't automatable — versus "blocked" — no remediation
         * path is known at all. The Z3 optimiser's own totalResidualRisk sums
         * both together; this only adds a partition on top, computed with the
         * same {@link RiskWeights} the optimiser used, without touching it.
         */
        private ResidualRiskSummary toResidualRiskSummary(
                        List<RemediationCandidate> candidates, RemediationPlan plan) {
                double actionable = 0.0;
                double blocked = 0.0;

                for (RemediationCandidate candidate : candidates) {
                        boolean deferred = findDecision(plan, candidate)
                                        .map(d -> !d.shouldUpgrade())
                                        .orElse(true);
                        if (!deferred) {
                                continue;
                        }
                        if (candidate.hasFixAvailable() || candidate.hasAlternativeFix()) {
                                actionable += candidate.contextualRisk(riskWeights);
                        } else {
                                blocked += candidate.contextualRisk(riskWeights);
                        }
                }

                return new ResidualRiskSummary(actionable, blocked);
        }

        private ArtifactFinding toFinding(
                        RemediationCandidate candidate, Optional<RemediationDecision> decision) {
                return new ArtifactFinding(
                                candidate.artifact().gav(),
                                candidate.contextualRisk(riskWeights),
                                toCveSummaries(candidate),
                                toReachabilitySummary(candidate),
                                toCompatibilitySummary(candidate.compatibilityReport()),
                                toRemediationSummary(candidate, decision),
                                candidate.stabilityReportSummary());
        }

        /**
         * The risk factors are taken from the candidate rather than recomputed
         * here, so the report cannot drift from the score the optimiser used.
         */
        private List<CveSummary> toCveSummaries(RemediationCandidate candidate) {
                return candidate.vulnerabilities().stream()
                                .map(v -> toCveSummary(v, candidate.contextualRiskFor(v, riskWeights)))
                                .toList();
        }

        private CveSummary toCveSummary(Vulnerability v, ContextualRisk contextualRisk) {
                return new CveSummary(
                                v.id().value(),
                                v.severity().name(),
                                new CvssSummary(v.cvss().value(), v.cvss().vector()),
                                v.epss().map(e -> new EpssSummary(e.value(), e.percentile())),
                                v.cwes().stream().map(c -> c.value()).toList(),
                                v.aliases().stream().map(a -> a.value()).toList(),
                                v.summary(),
                                v.advisoryUrl(),
                                v.fixCommitUrl(),
                                v.published().map(Instant::toString).orElse(null),
                                v.modified().map(Instant::toString).orElse(null),
                                contextualRisk);
        }

        private ReachabilitySummary toReachabilitySummary(RemediationCandidate candidate) {
                List<String> reachableMethods = candidate.reachabilityReports().stream()
                                .flatMap(r -> r.reachableMethodIds().stream())
                                .filter(s -> s != null && !s.isBlank())
                                .distinct()
                                .toList();

                return new ReachabilitySummary(
                        candidate.aggregateReachabilityStatus(),
                        reachableMethods);
        }

        private CompatibilitySummary toCompatibilitySummary(Optional<CompatibilityReport> cr) {
                return cr.map(report -> {
                        boolean contextuallyAdjusted = report.status() == CompatibilityStatus.COMPATIBLE
                                        && report.breakingChangeCount() > 0;
                        return new CompatibilitySummary(
                                        report.status(),
                                        report.breakingChangeCount(),
                                        summarizeByType(report.breakingChanges()),
                                        topChanges(report.breakingChanges(), 25),
                                        contextuallyAdjusted);
                }).orElse(new CompatibilitySummary(
                                CompatibilityStatus.UNKNOWN, 0, Map.of(), List.of(), false));
        }

        private Map<String, Integer> summarizeByType(List<String> changes) {
                Map<String, Integer> summary = new LinkedHashMap<>();
                summary.put("BINARY", 0);
                summary.put("SOURCE", 0);
                summary.put("OTHER", 0);
                if (changes == null)
                        return summary;
                for (String bc : changes) {
                        if (bc == null)
                                continue;
                        if (bc.startsWith("[BINARY]"))
                                summary.merge("BINARY", 1, Integer::sum);
                        else if (bc.startsWith("[SOURCE]"))
                                summary.merge("SOURCE", 1, Integer::sum);
                        else
                                summary.merge("OTHER", 1, Integer::sum);
                }
                return summary;
        }

        private List<String> topChanges(List<String> changes, int limit) {
                if (changes == null)
                        return List.of();
                return changes.stream()
                                .filter(s -> s != null && !s.isBlank())
                                .distinct()
                                .limit(limit)
                                .toList();
        }

        private RemediationSummary toRemediationSummary(
                        RemediationCandidate candidate, Optional<RemediationDecision> decision) {
                UpgradeDecision label = resolveDecisionLabel(candidate, decision);
                return new RemediationSummary(
                                label,
                                resolveRationale(candidate, decision, label),
                                decision.map(RemediationDecision::riskReduction).orElse(0.0),
                                decision.map(RemediationDecision::effortCost).orElse(0.0),
                                candidate.fixVersion().orElse(null),
                                candidate.alternativeFix().map(this::toAlternativeFixSummary));
        }

        private AlternativeFixSummary toAlternativeFixSummary(AlternativeFix fix) {
                return new AlternativeFixSummary(fix.groupId(), fix.artifactId(), fix.version());
        }

        private UpgradeDecision resolveDecisionLabel(
                RemediationCandidate candidate,
                Optional<RemediationDecision> decision) {

        return decision
                .filter(RemediationDecision::shouldUpgrade)
                .map(d -> candidate.isMandatoryUpgrade()
                        ? UpgradeDecision.MANDATORY
                        : UpgradeDecision.RECOMMENDED)
                .orElseGet(() -> candidate.hasAlternativeFix()
                        ? UpgradeDecision.MIGRATION_AVAILABLE
                        : UpgradeDecision.DEFER);
        }

        /**
         * MIGRATION_AVAILABLE candidates never went through Z3 (they were
         * excluded alongside every other no-direct-fix candidate — see
         * {@code RemediationCandidate::hasFixAvailable} filters in
         * {@code Z3RemediationAdapter}), so the generic "No fix version
         * available." rationale attached there would otherwise read as "there
         * is nothing to do." There is: a manual migration, named explicitly
         * here so the report cannot be misread as "no action needed" for the
         * artifact with the most real exposure.
         */
        private String resolveRationale(
                        RemediationCandidate candidate, Optional<RemediationDecision> decision, UpgradeDecision label) {
                if (label == UpgradeDecision.MIGRATION_AVAILABLE) {
                        AlternativeFix fix = candidate.alternativeFix().orElseThrow();
                        return "No direct fix for " + candidate.artifact().ga() + ". A fix exists under a "
                                        + "different Maven coordinate: " + fix.gav() + " — requires manual "
                                        + "migration (dependency and package rename), not an automatic version bump.";
                }
                return decision.map(RemediationDecision::rationale)
                                .orElse("No optimisation decision available.");
        }

        private GlobalGraphValidationSummary toGlobalValidationSummary(GlobalGraphValidation gv) {
                GraphValidationStatus status = gv.graphDataUnavailable() ? GraphValidationStatus.UNAVAILABLE
                                : gv.isClean() ? GraphValidationStatus.CLEAN
                                                : !gv.newVulnerableDeps().isEmpty() ? GraphValidationStatus.HAS_RISKS
                                                                : GraphValidationStatus.NOT_RUN;

                return new GlobalGraphValidationSummary(
                                status,
                                gv.analyzedArtifacts().stream().map(Artifact::gav).toList(),
                                gv.newVulnerableDeps().stream().map(Artifact::gav).toList());
        }

        private Optional<RemediationDecision> findDecision(
                        RemediationPlan plan, RemediationCandidate candidate) {
                return plan.decisions().stream()
                                .filter(d -> d.artifact().gav().equals(candidate.artifact().gav()))
                                .findFirst();

        }
}
