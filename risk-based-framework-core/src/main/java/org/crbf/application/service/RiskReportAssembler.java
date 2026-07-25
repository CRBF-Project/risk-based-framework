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
import org.crbf.domain.model.vulnerability.Vulnerability;

public class RiskReportAssembler {

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
                                toGlobalValidationSummary(plan.globalGraphValidation()),
                                vulnerabilityLookupFailures);
        }

        private ArtifactFinding toFinding(
                        RemediationCandidate candidate, Optional<RemediationDecision> decision) {
                return new ArtifactFinding(
                                candidate.artifact().gav(),
                                toCveSummaries(candidate.vulnerabilities()),
                                toReachabilitySummary(candidate),
                                toCompatibilitySummary(candidate.compatibilityReport()),
                                toRemediationSummary(candidate, decision),
                                candidate.stabilityReportSummary());
        }

        private List<CveSummary> toCveSummaries(List<Vulnerability> vulnerabilities) {
                return vulnerabilities.stream()
                                .map(this::toCveSummary)
                                .toList();
        }

        private CveSummary toCveSummary(Vulnerability v) {
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
                                v.modified().map(Instant::toString).orElse(null));
        }

        private ReachabilitySummary toReachabilitySummary(RemediationCandidate candidate) {
                List<String> reachableMethods = candidate.reachabilityReports().stream()
                                .flatMap(r -> r.reachableMethodIds().stream())
                                .filter(s -> s != null && !s.isBlank())
                                .distinct()
                                .toList();

                return new ReachabilitySummary(
                                candidate.reachabilityStatus(),
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
                return new RemediationSummary(
                                resolveDecisionLabel(candidate, decision),
                                decision.map(RemediationDecision::rationale)
                                                .orElse("No optimisation decision available."),
                                decision.map(RemediationDecision::riskReduction).orElse(0.0),
                                decision.map(RemediationDecision::effortCost).orElse(0.0),
                                candidate.fixVersion().orElseThrow());
        }

        private UpgradeDecision resolveDecisionLabel(
                        RemediationCandidate candidate, Optional<RemediationDecision> decision) {
                return decision
                                .filter(RemediationDecision::shouldUpgrade)
                                .map(d -> candidate.reachabilityStatus().isReachable()
                                                ? UpgradeDecision.MANDATORY
                                                : UpgradeDecision.RECOMMENDED)
                                .orElse(UpgradeDecision.DEFER);
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
