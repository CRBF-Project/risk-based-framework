package org.crbf.application.service;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.crbf.application.model.report.RiskReport;
import org.crbf.application.port.in.AnalyseDependencyRiskUseCase;
import org.crbf.application.port.out.AnalyseReachabilityPort;
import org.crbf.application.port.out.DetectBreakingChangesPort;
import org.crbf.application.port.out.ExportRiskReportPort;
import org.crbf.application.port.out.LoadEpssScoresPort;
import org.crbf.application.port.out.LoadStabilityMetricsPort;
import org.crbf.application.port.out.LoadVulnerabilitiesPort;
import org.crbf.application.port.out.OptimiseRemediationPort;
import org.crbf.application.port.out.ResolveArtifactPort;
import org.crbf.application.port.out.ResolveTransitiveDependenciesPort;
import org.crbf.application.port.out.VulnerabilityLookupException;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.DependencyPath;
import org.crbf.domain.model.artifact.LocatedArtifact;
import org.crbf.domain.model.artifact.TransitiveDepsResult;
import org.crbf.domain.model.artifact.Version;
import org.crbf.domain.model.compatibility.CompatibilityReport;
import org.crbf.domain.model.optimisation.GlobalGraphValidation;
import org.crbf.domain.model.optimisation.RemediationCandidate;
import org.crbf.domain.model.optimisation.RemediationDecision;
import org.crbf.domain.model.optimisation.RemediationPlan;
import org.crbf.domain.model.optimisation.UpgradePathValidation;
import org.crbf.domain.model.reachability.ProjectCallGraph;
import org.crbf.domain.model.reachability.ReachabilityStatus;
import org.crbf.domain.model.reachability.VulnerabilityReachability;
import org.crbf.domain.model.risk.VulnerableArtifact;
import org.crbf.domain.model.stability.EcosystemStability;
import org.crbf.domain.model.vulnerability.Vulnerability;

public class AnalyseDependencyRiskService implements AnalyseDependencyRiskUseCase {

        private final ResolveArtifactPort resolveArtifactPort;
        private final LoadVulnerabilitiesPort loadVulnerabilitiesPort;
        private final LoadEpssScoresPort loadEpssScoresPort;
        private final LoadStabilityMetricsPort loadStabilityMetricsPort;
        private final AnalyseReachabilityPort analyseReachabilityPort;
        private final ResolveTransitiveDependenciesPort resolveTransitiveDepsPort;
        private final OptimiseRemediationPort optimizeRemediationPort;
        private final RiskReportAssembler reportAssembler;
        private final ExportRiskReportPort exportRiskReportPort;
        private final UpgradePathAnalyser upgradePathAnalyser;

        private final AnalysisProgressLogger logger = new AnalysisProgressLogger();

        public AnalyseDependencyRiskService(
                        ResolveArtifactPort resolveArtifactPort,
                        LoadVulnerabilitiesPort loadVulnerabilitiesPort,
                        LoadEpssScoresPort loadEpssScoresPort,
                        LoadStabilityMetricsPort loadStabilityMetricsPort,
                        AnalyseReachabilityPort analyseReachabilityPort,
                        DetectBreakingChangesPort detectBreakingChangesPort,
                        ResolveTransitiveDependenciesPort resolveTransitiveDepsPort,
                        OptimiseRemediationPort optimizeRemediationPort,
                        RiskReportAssembler reportAssembler,
                        ExportRiskReportPort exportRiskReportPort) {

                this.resolveArtifactPort = Objects.requireNonNull(resolveArtifactPort);
                this.loadVulnerabilitiesPort = Objects.requireNonNull(loadVulnerabilitiesPort);
                this.loadEpssScoresPort = Objects.requireNonNull(loadEpssScoresPort);
                this.loadStabilityMetricsPort = Objects.requireNonNull(loadStabilityMetricsPort);
                this.analyseReachabilityPort = Objects.requireNonNull(analyseReachabilityPort);
                this.resolveTransitiveDepsPort = Objects.requireNonNull(resolveTransitiveDepsPort);
                this.optimizeRemediationPort = Objects.requireNonNull(optimizeRemediationPort);
                this.reportAssembler = Objects.requireNonNull(reportAssembler);
                this.exportRiskReportPort = Objects.requireNonNull(exportRiskReportPort);
                this.upgradePathAnalyser = new UpgradePathAnalyser(
                                Objects.requireNonNull(loadVulnerabilitiesPort),
                                Objects.requireNonNull(resolveTransitiveDepsPort),
                                Objects.requireNonNull(resolveArtifactPort),
                                Objects.requireNonNull(detectBreakingChangesPort),
                                logger);
        }

        @Override
        public void analyse(Path projectPath, Path classesPath, List<DependencyPath> prebuiltGraph) {
                Set<Artifact> uniqueArtifacts = extractUniqueArtifacts(prebuiltGraph);
                logger.logGraphResolved(uniqueArtifacts.size());

                Map<Artifact, LocatedArtifact> resolvedArtifacts = resolveAllArtifacts(uniqueArtifacts);

                List<Path> allJarPaths = resolvedArtifacts.values().stream()
                                .map(LocatedArtifact::physicalJarPath)
                                .toList();
                ProjectCallGraph callGraph = analyseReachabilityPort.buildCallGraph(classesPath, allJarPaths);

                List<RemediationCandidate> candidates = new ArrayList<>();
                List<String> lookupFailures = new ArrayList<>();

                logger.logVulnerabilityScanStart();

                for (Artifact artifact : uniqueArtifacts) {
                        try {
                                LocatedArtifact located = resolvedArtifacts.get(artifact);

                                Optional<RemediationCandidate> candidate = located != null
                                                ? analyseArtifact(located, callGraph)
                                                : analyseUnresolvableArtifact(artifact);

                                candidate.ifPresent(candidates::add);

                        } catch (VulnerabilityLookupException e) {
                                logger.logVulnerabilityLookupFailed(e.gav(), e.getMessage());
                                lookupFailures.add(e.gav());
                        }
                }

                int totalVulns = candidates.stream().mapToInt(c -> c.vulnerabilities().size()).sum();
                logger.logScanComplete(totalVulns);

                logger.logOptimisationStart();
                RemediationPlan plan = optimizeRemediationPort.optimize(candidates);
                logger.logRemediationPlan(plan);

                plan = plan.withGlobalValidation(validateGlobalGraph(plan));
                logger.logRemediationPlan(plan);

                RiskReport report = reportAssembler.assemble(projectPath, prebuiltGraph,
                                uniqueArtifacts, candidates, plan, lookupFailures);
                exportRiskReportPort.exportReport(report, projectPath.resolve("target"));

                logger.logAnalysisComplete();
        }

        private Optional<RemediationCandidate> analyseArtifact(
                        LocatedArtifact locatedArtifact, ProjectCallGraph callGraph) {

                List<Vulnerability> vulnerabilities = loadEnrichedVulnerabilities(locatedArtifact.artifact());
                if (vulnerabilities.isEmpty())
                        return Optional.empty();

                VulnerableArtifact vulnerableArtifact = new VulnerableArtifact(locatedArtifact.artifact(),
                                vulnerabilities);
                logger.logVulnerableArtifact(vulnerableArtifact.gav(), vulnerabilities.size());

                List<VulnerabilityReachability> reachabilityResults = analyseReachabilityPort
                                .analyseReachability(callGraph, locatedArtifact, vulnerableArtifact.vulnerabilities());
                reachabilityResults.forEach(r -> logger.logVulnerabilityBlock(r.vulnerability(), r));

                ReachabilityStatus reachability = aggregateReachability(reachabilityResults);

                Optional<EcosystemStability> currentStability = loadStabilityMetrics(locatedArtifact.artifact(), false);
                currentStability.ifPresent(s -> logger.logStability(locatedArtifact.artifact(), s, "Current"));

                if (vulnerableArtifact.hasFixAvailable() && reachability != ReachabilityStatus.UNREACHABLE) {
                        String fixVersion = vulnerableArtifact.requiredFixVersion().map(Version::value).orElseThrow();
                        UpgradePathValidation validation = upgradePathAnalyser.validateUpgradePath(locatedArtifact,
                                        fixVersion);
                        Artifact fixArtifact = Artifact.create(
                                        locatedArtifact.groupId().value(),
                                        locatedArtifact.artifactId().value(),
                                        validation.proposedVersion(),
                                        locatedArtifact.scope());
                        Optional<EcosystemStability> fixStability = loadStabilityMetrics(fixArtifact, true);
                        fixStability.ifPresent(s -> logger.logStability(fixArtifact, s, "Fix version"));

                        Optional<CompatibilityReport> contextualReport = validation.compatibilityReport()
                                        .map(r -> r.contextualise(callGraph));

                        return Optional.of(new RemediationCandidate(locatedArtifact.artifact(),
                                        vulnerabilities, reachability, reachabilityResults,
                                        contextualReport, Optional.of(validation.proposedVersion()),
                                        Optional.empty(),
                                        currentStability, fixStability, Optional.of(validation)));
                }

                return Optional.of(new RemediationCandidate(
                                locatedArtifact.artifact(), vulnerabilities, reachability,
                                reachabilityResults,
                                Optional.empty(), vulnerableArtifact.requiredFixVersion().map(Version::value),
                                vulnerableArtifact.requiredAlternativeFix(),
                                currentStability, Optional.empty(), Optional.empty()));
        }

        /**
         * Degraded analysis - physical JAR not available
         */
        private Optional<RemediationCandidate> analyseUnresolvableArtifact(Artifact artifact) {
                List<Vulnerability> enrichedVulns = loadEnrichedVulnerabilities(artifact);
                if (enrichedVulns.isEmpty())
                        return Optional.empty();

                VulnerableArtifact vulnerableArtifact = new VulnerableArtifact(artifact, enrichedVulns);
                logger.logVulnerableArtifact(vulnerableArtifact.gav(), enrichedVulns.size());

                Optional<EcosystemStability> currentStability = loadStabilityMetrics(artifact, false);
                currentStability.ifPresent(s -> logger.logStability(artifact, s, "Current"));

                if (vulnerableArtifact.hasFixAvailable()) {
                        String fixVersion = vulnerableArtifact.requiredFixVersion().map(Version::value).orElseThrow();
                        UpgradePathValidation validation = upgradePathAnalyser.validateUpgradePathWithoutJar(artifact,
                                        fixVersion);
                        Artifact fixArtifact = Artifact.create(
                                        artifact.groupId().value(), artifact.artifactId().value(),
                                        validation.proposedVersion(), artifact.scope());
                        Optional<EcosystemStability> fixStability = loadStabilityMetrics(fixArtifact, true);
                        fixStability.ifPresent(s -> logger.logStability(fixArtifact, s, "Fix version"));

                        return Optional.of(new RemediationCandidate(
                                        artifact, enrichedVulns, ReachabilityStatus.UNKNOWN, List.of(),
                                        validation.compatibilityReport(),
                                        Optional.of(validation.proposedVersion()),
                                        Optional.empty(),
                                        currentStability, fixStability, Optional.of(validation)));
                }

                return Optional.of(new RemediationCandidate(
                                artifact, enrichedVulns, ReachabilityStatus.UNKNOWN, List.of(),
                                Optional.empty(), Optional.empty(),
                                vulnerableArtifact.requiredAlternativeFix(),
                                currentStability, Optional.empty(), Optional.empty()));
        }

        private List<Vulnerability> loadEnrichedVulnerabilities(Artifact artifact) {
                List<Vulnerability> vulnerabilities = loadVulnerabilitiesPort.loadVulnerabilities(artifact);
                return vulnerabilities.isEmpty() ? List.of() : loadEpssScoresPort.enrich(vulnerabilities);
        }

        /**
         * Returns the worst-case reachability across all vulnerabilities of the same
         * artifact. With two-tier analysis, different CVEs of the same artifact can
         * have different status (e.g. one CONFIRMED if its CVE text named the
         * vulnerable class, another PROBABLE if it did not). Taking the maximum
         * ensures the artifact-level decision for Z3 reflects the highest-confidence
         * reachability signal available.
         */
        private ReachabilityStatus aggregateReachability(List<VulnerabilityReachability> results) {
                return results.stream()
                                .map(VulnerabilityReachability::status)
                                .max(Comparator.comparingInt(ReachabilityStatus::severity))
                                .orElse(ReachabilityStatus.UNKNOWN);
        }

        /**
         * Loads ecosystem stability metrics from Goblin Weaver for the given artifact.
         * Returns {@code Optional.empty()} on any failure so that the framework
         * degrades gracefully when Goblin is unavailable.
         */
        private Optional<EcosystemStability> loadStabilityMetrics(Artifact artifact, Boolean isFixVersion) {
                try {
                        EcosystemStability stability = loadStabilityMetricsPort.loadMetrics(artifact);
                        logger.logStabilityLoaded(isFixVersion ? "Fix version" : "Current", artifact, stability);
                        return Optional.of(stability);
                } catch (Exception e) {
                        logger.logStabilityFailed(isFixVersion ? "fix" : "current", artifact.gav(), e.getMessage());
                        return Optional.empty();
                }
        }

        private Map<Artifact, LocatedArtifact> resolveAllArtifacts(Set<Artifact> uniqueArtifacts) {
                Map<Artifact, LocatedArtifact> resolved = new LinkedHashMap<>();
                List<String> unresolved = new ArrayList<>();

                for (Artifact artifact : uniqueArtifacts) {
                        resolveArtifactPort.resolve(
                                        artifact.groupId().value(), artifact.artifactId().value(),
                                        artifact.version().value(), artifact.scope().name())
                                        .ifPresentOrElse(
                                                        located -> resolved.put(artifact, located),
                                                        () -> unresolved.add(artifact.gav()));
                }

                if (!unresolved.isEmpty()) {
                        logger.logUnresolvedJars(unresolved);
                }

                return Collections.unmodifiableMap(resolved);
        }

        private Set<Artifact> extractUniqueArtifacts(List<DependencyPath> dependencyGraph) {
                return dependencyGraph.stream()
                                .flatMap(p -> p.path().stream().skip(1))
                                .filter(a -> a.scope().isAnalysable())
                                .collect(Collectors.toCollection(LinkedHashSet::new));
        }

        /**
         * Validates that applying ALL recommended upgrades simultaneously does not
         * introduce new vulnerable transitive dependencies invisible when validating
         * each artifact in isolation (e.g. cascading version changes via Maven
         * nearest-wins). Uses a single Goblin traversal with CVE_AGGREGATED across
         * all fix versions.
         */
        private GlobalGraphValidation validateGlobalGraph(RemediationPlan plan) {
                List<RemediationDecision> upgrades = plan.upgradeRecommendations();

                if (upgrades.isEmpty()) {
                        logger.logGlobalValidationNoUpgrades();
                        return GlobalGraphValidation.clean(List.of());
                }

                List<Artifact> fixArtifacts = upgrades.stream()
                                .map(d -> Artifact.create(
                                                d.artifact().groupId().value(), d.artifact().artifactId().value(),
                                                d.targetVersion(), d.artifact().scope()))
                                .toList();

                logger.logGlobalValidationStart(fixArtifacts);

                TransitiveDepsResult globalResult = resolveTransitiveDepsPort.resolveGlobalGraph(fixArtifacts);

                if (globalResult.isUnavailable()) {
                        logger.logGlobalValidationUnavailable();
                        return GlobalGraphValidation.unavailable();
                }

                if (globalResult.vulnerableDeps().isEmpty()) {
                        logger.logGlobalValidationClean();
                        return GlobalGraphValidation.clean(fixArtifacts);
                }

                logger.logGlobalValidationHasRisks(globalResult.vulnerableDeps());
                return GlobalGraphValidation.withRisks(fixArtifacts, globalResult.vulnerableDeps());
        }
}
