package org.crbf.domain.model.optimisation;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.compatibility.CompatibilityReport;
import org.crbf.domain.model.compatibility.CompatibilityStatus;
import org.crbf.domain.model.reachability.ReachabilityStatus;
import org.crbf.domain.model.reachability.VulnerabilityReachability;
import org.crbf.domain.model.stability.EcosystemStability;
import org.crbf.domain.model.stability.StabilityScore;
import org.crbf.domain.model.vulnerability.AlternativeFix;
import org.crbf.domain.model.vulnerability.Severity;
import org.crbf.domain.model.vulnerability.Vulnerability;
import org.crbf.domain.model.vulnerability.VulnerabilityId;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Value Object that aggregates all contextual signals for a single vulnerable
 * artifact, forming the input unit for the remediation optimisation step.
 *
 * <p>
 * One candidate is created per unique vulnerable artifact. Each vulnerability
 * is scored independently using its own CVSS, EPSS and reachability status.
 * The artifact-level contextual risk is the maximum contextual risk among its
 * vulnerabilities.
 *
 * @param artifact
 *                                  The artifact under analysis.
 * @param vulnerabilities
 *                                  All known vulnerabilities affecting this
 *                                  artifact version.
 * @param reachabilityReports
 *                                  Exactly one reachability result per
 *                                  vulnerability.
 * @param compatibilityReport
 *                                  API compatibility of the candidate fix
 *                                  version,
 *                                  or {@code Optional.empty()} when
 *                                  unavailable.
 * @param fixVersion
 *                                  The selected safe version, if one exists.
 * @param alternativeFix
 *                                  A fix available under a different Maven
 *                                  coordinate,
 *                                  requiring manual migration.
 * @param currentStability
 *                                  Ecosystem metrics for the currently used
 *                                  version.
 * @param fixVersionStability
 *                                  Ecosystem metrics for the proposed fix
 *                                  version.
 * @param upgradePathValidation
 *                                  Validation of the proposed upgrade path.
 */
public record RemediationCandidate(
        Artifact artifact,
        List<Vulnerability> vulnerabilities,
        List<VulnerabilityReachability> reachabilityReports,
        Optional<CompatibilityReport> compatibilityReport,
        Optional<String> fixVersion,
        Optional<AlternativeFix> alternativeFix,
        Optional<EcosystemStability> currentStability,
        Optional<EcosystemStability> fixVersionStability,
        Optional<UpgradePathValidation> upgradePathValidation) {

    private static final double CVSS_MAX_SCORE = 10.0;

    private static final double PATH_QUALITY_FLOOR = 0.3;
    private static final double PATH_QUALITY_MIDPOINT = 0.5;

    public RemediationCandidate {
        if (artifact == null) {
            throw new IllegalArgumentException("Artifact cannot be null.");
        }

        vulnerabilities = vulnerabilities == null
                ? List.of()
                : List.copyOf(vulnerabilities);

        reachabilityReports = reachabilityReports == null
                ? List.of()
                : List.copyOf(reachabilityReports);

        compatibilityReport = compatibilityReport == null
                ? Optional.empty()
                : compatibilityReport;

        fixVersion = fixVersion == null
                ? Optional.empty()
                : fixVersion;

        alternativeFix = alternativeFix == null
                ? Optional.empty()
                : alternativeFix;

        currentStability = currentStability == null
                ? Optional.empty()
                : currentStability;

        fixVersionStability = fixVersionStability == null
                ? Optional.empty()
                : fixVersionStability;

        upgradePathValidation = upgradePathValidation == null
                ? Optional.empty()
                : upgradePathValidation;

        validateReachabilityReports(vulnerabilities, reachabilityReports);
    }

    /**
     * Convenience factory that omits ecosystem stability and upgrade-path data.
     */
    public static RemediationCandidate withoutStability(
            Artifact artifact,
            List<Vulnerability> vulnerabilities,
            List<VulnerabilityReachability> reachabilityReports,
            Optional<CompatibilityReport> compatibilityReport,
            Optional<String> fixVersion,
            Optional<AlternativeFix> alternativeFix) {

        return new RemediationCandidate(
                artifact,
                vulnerabilities,
                reachabilityReports,
                compatibilityReport,
                fixVersion,
                alternativeFix,
                Optional.empty(),
                Optional.empty(),
                Optional.empty());
    }

    public boolean hasFixAvailable() {
        return fixVersion.isPresent();
    }

    /**
     * A fix exists under a different Maven coordinate and therefore requires
     * manual migration rather than a direct version upgrade.
     */
    public boolean hasAlternativeFix() {
        return alternativeFix.isPresent();
    }

    /**
     * Returns the highest reachability classification observed across the
     * vulnerabilities affecting this artifact.
     */
    public ReachabilityStatus aggregateReachabilityStatus() {
        return reachabilityReports.stream()
                .map(VulnerabilityReachability::status)
                .max(Comparator.comparingInt(ReachabilityStatus::severity))
                .orElse(ReachabilityStatus.UNKNOWN);
    }

    /**
     * An upgrade is mandatory when at least one CRITICAL vulnerability is
     * reachable and a direct fix version is available.
     */
    public boolean isMandatoryUpgrade() {
        if (!hasFixAvailable()) {
            return false;
        }

        return vulnerabilities.stream()
                .filter(vulnerability -> vulnerability.severity() == Severity.CRITICAL)
                .anyMatch(vulnerability -> reachabilityStatusFor(vulnerability).isReachable());
    }

    public double contextualRisk() {
        return contextualRisk(RiskWeights.defaults());
    }

    /**
     * Computes the artifact-level contextual risk as the maximum contextual
     * risk among the vulnerabilities affecting the artifact.
     */
    public double contextualRisk(RiskWeights weights) {
        double stalenessUrgency = currentStability
                .map(StabilityScore::stalenessUrgencyOf)
                .orElse(0.5);

        double pathQualityFactor = upgradePathValidation
                .flatMap(UpgradePathValidation::upgradePathSecuritySignal)
                .map(signal -> Math.max(
                        PATH_QUALITY_FLOOR,
                        PATH_QUALITY_MIDPOINT + signal * PATH_QUALITY_MIDPOINT))
                .orElse(1.0);

        return vulnerabilities.stream()
                .mapToDouble(vulnerability -> contextualRiskOf(
                        vulnerability,
                        weights,
                        stalenessUrgency,
                        pathQualityFactor))
                .max()
                .orElse(0.0);
    }

    /**
     * Computes contextual risk for one vulnerability, preserving the
     * association between its CVSS, EPSS and reachability signals.
     */
    private double contextualRiskOf(
            Vulnerability vulnerability,
            RiskWeights weights,
            double stalenessUrgency,
            double pathQualityFactor) {

        double baseRisk = baseRiskOf(
                vulnerability,
                weights,
                stalenessUrgency);

        double reachabilityWeight = reachabilityWeightFor(vulnerability, weights);

        return baseRisk
                * reachabilityWeight
                * pathQualityFactor;
    }

    private double baseRiskOf(
            Vulnerability vulnerability,
            RiskWeights weights,
            double stalenessUrgency) {

        double cvssNorm = vulnerability.cvss().value() / CVSS_MAX_SCORE;

        if (vulnerability.epss().isPresent()) {
            double epssScore = vulnerability.epss().orElseThrow().value();

            return (cvssNorm * weights.cvssWeight())
                    + (epssScore * weights.epssWeight())
                    + (stalenessUrgency * weights.stalenessWeight());
        }

        double availableWeight = weights.cvssWeight()
                + weights.stalenessWeight();

        if (availableWeight == 0.0) {
            throw new IllegalStateException(
                    "Cannot calculate base risk without EPSS when "
                            + "CVSS and staleness weights are both zero.");
        }

        return ((cvssNorm * weights.cvssWeight())
                + (stalenessUrgency * weights.stalenessWeight()))
                / availableWeight;
    }

    private double reachabilityWeightFor(
            Vulnerability vulnerability,
            RiskWeights weights) {

        return switch (reachabilityStatusFor(vulnerability)) {
            case REACHABLE_CONFIRMED,
                    REACHABLE_PROBABLE ->
                weights.reachableWeight();

            case UNKNOWN -> weights.unknownWeight();

            case UNREACHABLE -> weights.unreachableWeight();
        };
    }

    private ReachabilityStatus reachabilityStatusFor(
            Vulnerability vulnerability) {

        return reachabilityReports.stream()
                .filter(report -> report.vulnerability().id().equals(vulnerability.id()))
                .map(VulnerabilityReachability::status)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "Missing reachability report for vulnerability "
                                + vulnerability.id().value()));
    }

    public double upgradeCost() {
        if (!hasFixAvailable()) {
            return Double.MAX_VALUE;
        }

        CompatibilityStatus compatibility = compatibilityReport
                .map(CompatibilityReport::status)
                .orElse(CompatibilityStatus.UNKNOWN);

        return switch (compatibility) {
            case COMPATIBLE -> 1.0;
            case UNKNOWN -> 2.0;
            case SOURCE_INCOMPATIBLE -> 3.0;
            case BINARY_INCOMPATIBLE -> 4.0;
        };
    }

    public String stabilityReportSummary() {
        StringBuilder summary = new StringBuilder();

        currentStability.ifPresentOrElse(
                stability -> summary.append(
                        String.format(
                                "Current: TOOD=%d days, VersionLag=%d, LatestVersion=%s",
                                stability.tood().value(),
                                stability.versionLag().value(),
                                stability.latestVersion())),
                () -> summary.append("Current: no Goblin data"));

        summary.append(" | ");

        fixVersionStability.ifPresentOrElse(
                stability -> {
                    StabilityScore score = StabilityScore.ofFixVersion(stability);

                    summary.append(
                            String.format(
                                    "Fix: StabilityScore=%.2f "
                                            + "(AdoptionRate=%.0f%%, "
                                            + "Lifespan=%.0f days, "
                                            + "MaintenanceRate=%.4f rel/day)",
                                    score.value(),
                                    stability.adoptionRate().value() * 100,
                                    stability.adoptionLifespan().days(),
                                    stability.maintenanceRate().value()));
                },
                () -> summary.append("Fix: no Goblin data"));

        upgradePathValidation.ifPresent(validation -> {
            // An unvalidated path is not a risky path; reporting UNKNOWN as
            // "HAS RISKS" would read an unreachable ecosystem service as evidence.
            UpgradePathStatus pathStatus = validation.upgradePathStatus();

            summary.append(" | Upgrade path: ").append(pathStatus.name());

            if (pathStatus == UpgradePathStatus.HAS_RISKS) {
                summary.append(
                        String.format(
                                " (%d new CVE(s))",
                                validation.totalNewVulns()));
            }

            validation.upgradePathSecuritySignal().ifPresent(signal -> summary.append(
                    String.format(
                            " | upgradePathSecuritySignal: %.2f",
                            signal)));
        });

        return summary.toString();
    }

    /**
     * Ensures that every vulnerability has exactly one corresponding
     * reachability result and that no unrelated results are present.
     */
    private static void validateReachabilityReports(
            List<Vulnerability> vulnerabilities,
            List<VulnerabilityReachability> reachabilityReports) {

        Set<VulnerabilityId> vulnerabilityIds = vulnerabilities.stream()
                .map(Vulnerability::id)
                .collect(Collectors.toSet());

        if (vulnerabilityIds.size() != vulnerabilities.size()) {
            throw new IllegalArgumentException(
                    "Vulnerabilities must have unique identifiers.");
        }

        Set<VulnerabilityId> reportedIds = reachabilityReports.stream()
                .map(VulnerabilityReachability::vulnerability)
                .map(Vulnerability::id)
                .collect(Collectors.toSet());

        if (reportedIds.size() != reachabilityReports.size()) {
            throw new IllegalArgumentException(
                    "Each vulnerability must have exactly one reachability report.");
        }

        if (!vulnerabilityIds.equals(reportedIds)) {
            throw new IllegalArgumentException(
                    "Each vulnerability must have exactly one reachability report.");
        }
    }
}