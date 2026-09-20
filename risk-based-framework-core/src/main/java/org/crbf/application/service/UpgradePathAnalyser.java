package org.crbf.application.service;

import org.crbf.application.port.out.DetectBreakingChangesPort;
import org.crbf.application.port.out.LoadVulnerabilitiesPort;
import org.crbf.application.port.out.ResolveArtifactPort;
import org.crbf.application.port.out.ResolveTransitiveDependenciesPort;
import org.crbf.application.port.out.VulnerabilityLookupException;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.LocatedArtifact;
import org.crbf.domain.model.artifact.TransitiveDepsResult;
import org.crbf.domain.model.artifact.Version;
import org.crbf.domain.model.compatibility.CompatibilityReport;
import org.crbf.domain.model.optimisation.UpgradeCandidate;
import org.crbf.domain.model.optimisation.UpgradePathStatus;
import org.crbf.domain.model.optimisation.UpgradePathValidation;
import org.crbf.domain.model.vulnerability.Vulnerability;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

class UpgradePathAnalyser {

    private final LoadVulnerabilitiesPort loadVulnerabilitiesPort;
    private final ResolveTransitiveDependenciesPort resolveTransitiveDepsPort;
    private final ResolveArtifactPort resolveArtifactPort;
    private final DetectBreakingChangesPort detectBreakingChangesPort;
    private final AnalysisProgressLogger logger;

    UpgradePathAnalyser(
            LoadVulnerabilitiesPort loadVulnerabilitiesPort,
            ResolveTransitiveDependenciesPort resolveTransitiveDepsPort,
            ResolveArtifactPort resolveArtifactPort,
            DetectBreakingChangesPort detectBreakingChangesPort,
            AnalysisProgressLogger logger) {
        this.loadVulnerabilitiesPort = Objects.requireNonNull(loadVulnerabilitiesPort);
        this.resolveTransitiveDepsPort = Objects.requireNonNull(resolveTransitiveDepsPort);
        this.resolveArtifactPort = Objects.requireNonNull(resolveArtifactPort);
        this.detectBreakingChangesPort = Objects.requireNonNull(detectBreakingChangesPort);
        this.logger = Objects.requireNonNull(logger);
    }

    /**
     * Full upgrade path analysis — requires the physical JAR to be available
     * so that binary compatibility (JApiCmp) can be performed.
     */
    UpgradePathValidation validateUpgradePath(LocatedArtifact locatedArtifact, String osvFixVersion) {
        logger.logUpgradeValidationStart(locatedArtifact.gav(), osvFixVersion);
        UpgradeAnalysisData data = computeUpgradeAnalysis(locatedArtifact.artifact(), osvFixVersion);
        CompatibilityReport compatibility = detectCompatibility(locatedArtifact, data.confirmedFixVersion());
        return buildUpgradePathValidation(locatedArtifact.artifact(), osvFixVersion, data, Optional.of(compatibility));
    }

    /**
     * Degraded upgrade path analysis — used when the physical JAR is unavailable.
     * Skips JApiCmp; compatibility is absent.
     */
    UpgradePathValidation validateUpgradePathWithoutJar(Artifact artifact, String osvFixVersion) {
        logger.logUpgradeValidationStart(artifact.gav(), osvFixVersion);
        UpgradeAnalysisData data = computeUpgradeAnalysis(artifact, osvFixVersion);
        return buildUpgradePathValidation(artifact, osvFixVersion, data, Optional.empty());
    }

    private record UpgradeAnalysisData(
            String confirmedFixVersion,
            List<Vulnerability> fixVersionVulns,
            List<Artifact> addedDeps,
            List<Artifact> removedDeps,
            List<Artifact> newVulnerableDeps,
            boolean fixVersionVulnerabilityDataAvailable,
            boolean transitiveGraphDataAvailable) {

        UpgradePathStatus upgradePathStatus() {
            if (!fixVersionVulnerabilityDataAvailable
                    || !transitiveGraphDataAvailable) {
                return UpgradePathStatus.UNKNOWN;
            }

            return fixVersionVulns.isEmpty()
                    && newVulnerableDeps.isEmpty()
                    ? UpgradePathStatus.CLEAN
                    : UpgradePathStatus.HAS_RISKS;
        }

        Optional<Double> upgradePathSecuritySignal() {
            if (upgradePathStatus() == UpgradePathStatus.UNKNOWN) {
                return Optional.empty();
            }

            double fixSafety =
                    fixVersionVulns.isEmpty() ? 1.0 : 0.0;

            double introducedVulnerabilityRatio =
                    newVulnerableDeps.isEmpty()
                            ? 0.0
                            : (double) newVulnerableDeps.size()
                                    / Math.max(addedDeps.size(), 1);

            return Optional.of(
                    fixSafety - introducedVulnerabilityRatio);
        }
    }

    /**
     * JAR-independent phases: best fix version selection, OSV check on that
     * version, and transitive dependency diff via Goblin.
     */
    private UpgradeAnalysisData computeUpgradeAnalysis(Artifact artifact, String osvFixVersion) {
        String confirmedFixVersion = findBestFixVersion(artifact, osvFixVersion);
        Artifact fixArtifact = Artifact.create(
                artifact.groupId().value(), artifact.artifactId().value(),
                confirmedFixVersion, artifact.scope());

        List<Vulnerability> fixVersionVulns;
        boolean fixVersionVulnerabilityDataAvailable;

        try {
            fixVersionVulns = loadVulnerabilitiesPort.loadVulnerabilities(fixArtifact);
            fixVersionVulnerabilityDataAvailable = true;
        } catch (VulnerabilityLookupException e) {
            logger.logFixVersionLookupFailed(
                    confirmedFixVersion,
                    e.getMessage());

            fixVersionVulns = List.of();
            fixVersionVulnerabilityDataAvailable = false;
        }

        if (!fixVersionVulns.isEmpty()) {
            logger.logFixVersionHasCves(confirmedFixVersion, fixVersionVulns.size());
        }

        TransitiveDepsResult currentResult = resolveTransitiveDepsPort.resolveTransitiveDepsWithCves(artifact);
        TransitiveDepsResult fixResult = resolveTransitiveDepsPort.resolveTransitiveDepsWithCves(fixArtifact);

        boolean transitiveGraphDataAvailable = !currentResult.isUnavailable() && !fixResult.isUnavailable();

        Set<Artifact> addedDeps;
        Set<Artifact> removedDeps;
        List<Artifact> newVulnerableDeps;

        if (transitiveGraphDataAvailable) {
            addedDeps = setDifference(fixResult.allDeps(), currentResult.allDeps());
            removedDeps = setDifference(currentResult.allDeps(), fixResult.allDeps());
            logger.logTransitiveDiff(addedDeps.size(), removedDeps.size());

            newVulnerableDeps =
                    fixResult.vulnerableDeps().stream()
                            .filter(dep -> addedDeps.stream()
                                    .anyMatch(added ->
                                            added.groupId().value()
                                                    .equals(dep.groupId().value())
                                            && added.artifactId().value()
                                                    .equals(dep.artifactId().value())))
                            .toList();
        } else {
            logger.logGoblinUnavailableForValidation(
                    artifact.gav());

            addedDeps = Set.of();
            removedDeps = Set.of();
            newVulnerableDeps = List.of();
        }

        return new UpgradeAnalysisData(
                confirmedFixVersion,
                fixVersionVulns,
                List.copyOf(addedDeps),
                List.copyOf(removedDeps),
                newVulnerableDeps,
                fixVersionVulnerabilityDataAvailable,
                transitiveGraphDataAvailable);
    }

    private UpgradePathValidation buildUpgradePathValidation(
            Artifact artifact, String osvFixVersion, UpgradeAnalysisData data,
            Optional<CompatibilityReport> compatibility) {
        
        UpgradePathStatus pathStatus = data.upgradePathStatus();
        Optional<Double> securitySignal = data.upgradePathSecuritySignal();
        logger.logUpgradeValidationResult(pathStatus, securitySignal);

        Optional<String> alternativeSafeVersion = data.confirmedFixVersion().equals(osvFixVersion)
                ? Optional.empty()
                : Optional.of(osvFixVersion);

        return new UpgradePathValidation(
                artifact,
                data.confirmedFixVersion(),
                data.fixVersionVulns(),
                data.addedDeps(),
                data.removedDeps(),
                data.newVulnerableDeps(),
                compatibility,
                securitySignal,
                pathStatus,
                alternativeSafeVersion);
    }

    private CompatibilityReport detectCompatibility(LocatedArtifact current, String fixVersion) {
        Optional<LocatedArtifact> fixCandidateOpt = resolveArtifactPort.resolve(
                current.groupId().value(), current.artifactId().value(),
                fixVersion, current.scope().name());

        if (fixCandidateOpt.isEmpty()) {
            logger.logFixJarUnresolvable(current.gav(), fixVersion);
            return CompatibilityReport.unknown(
                    current.artifact(),
                    Artifact.create(current.groupId().value(), current.artifactId().value(),
                            fixVersion, current.scope()));
        }
        LocatedArtifact fixCandidate = fixCandidateOpt.get();

        CompatibilityReport report = detectBreakingChangesPort.detect(current, fixCandidate);
        logger.logCompatibilityResult(
                current.version().value(), fixVersion,
                report.status(), report.breakingChangeCount());
        logger.logBreakingChangeSample(report.breakingChanges(), 3);
        return report;
    }

    /**
     * Selects the minimum clean version that is ≥ the OSV minimum fix version.
     * Candidates come from Goblin sorted ascending; the first one that is also
     * clean according to OSV is chosen. Falls back to osvFixVersion when Goblin
     * is unavailable or no clean candidate exists.
     */
    private String findBestFixVersion(Artifact artifact, String osvFixVersion) {
        List<UpgradeCandidate> candidates = resolveTransitiveDepsPort.getNewerVersionsWithCves(artifact);

        if (candidates.isEmpty()) {
            logger.logGoblinUnavailableUsingOsvFix(osvFixVersion);
            return osvFixVersion;
        }

        return candidates.stream()
                .filter(UpgradeCandidate::isClean)
                .filter(c -> c.version().isNewerThanOrEqual(new Version(osvFixVersion)))
                .map(c -> c.version().value())
                .filter(v -> {
                    try {
                        return loadVulnerabilitiesPort.loadVulnerabilities(
                                Artifact.create(artifact.groupId().value(),
                                        artifact.artifactId().value(), v, artifact.scope()))
                                .isEmpty();
                    } catch (VulnerabilityLookupException e) {
                        return false;
                    }
                })
                .findFirst()
                .orElseGet(() -> {
                    logger.logNoCleanCandidateFallback(osvFixVersion);
                    return osvFixVersion;
                });
    }

    private static <T> Set<T> setDifference(Set<T> a, Set<T> b) {
        Set<T> result = new LinkedHashSet<>(a);
        result.removeAll(b);
        return result;
    }
}
