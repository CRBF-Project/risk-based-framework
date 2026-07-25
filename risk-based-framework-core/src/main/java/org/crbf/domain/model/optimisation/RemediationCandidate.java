package org.crbf.domain.model.optimisation;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.compatibility.CompatibilityReport;
import org.crbf.domain.model.compatibility.CompatibilityStatus;
import org.crbf.domain.model.reachability.ReachabilityStatus;
import org.crbf.domain.model.reachability.VulnerabilityReachability;
import org.crbf.domain.model.stability.EcosystemStability;
import org.crbf.domain.model.stability.PfetDays;
import org.crbf.domain.model.stability.StabilityScore;
import org.crbf.domain.model.vulnerability.Severity;
import org.crbf.domain.model.vulnerability.Vulnerability;

import java.util.List;
import java.util.Optional;

/**
 * Value Object that aggregates all contextual signals for a single vulnerable
 * artifact, forming the input unit for the Z3 optimisation step.
 *
 * One candidate is created per unique vulnerable artifact — not per CVE.
 * Multiple CVEs on the same artifact are represented in the
 * {@code vulnerabilities}
 * list, and the worst-case signals (highest CVSS, worst compatibility) are used
 * by the optimiser.
 *
 * @param artifact            The artifact under analysis.
 * @param vulnerabilities     All known CVEs affecting this artifact version.
 * @param reachabilityStatus  Whether the artifact's classes are reachable
 *                            from the project's call graph (SootUp/CHA result).
 * @param compatibilityReport API compatibility of the candidate fix version,
 *                            or {@code Optional.empty()} if no fix exists,
 *                            the JAR was unavailable, or analysis failed.
 * @param fixVersion          The earliest known safe version, or {@code null}.
 * @param currentStability    Goblin metrics for the current artifact version.
 * @param fixVersionStability Goblin metrics for the proposed fix version.
 */
public record RemediationCandidate(
        Artifact artifact,
        List<Vulnerability> vulnerabilities,
        ReachabilityStatus reachabilityStatus,
        List<VulnerabilityReachability> reachabilityReports,
        Optional<CompatibilityReport> compatibilityReport,
        Optional<String> fixVersion,
        Optional<EcosystemStability> currentStability,
        Optional<EcosystemStability> fixVersionStability,
        Optional<UpgradePathValidation> upgradePathValidation) {

    private static final double SIGNAL_SCALE = 10.0;

    private static final double PFET_SATURATION_DAYS = 365.0;

    private static final double PFET_MAX_PENALTY = 0.2;

    private static final double PATH_QUALITY_FLOOR = 0.3;

    private static final double PATH_QUALITY_MIDPOINT = 0.5;

    public RemediationCandidate {
        if (artifact == null) {
            throw new IllegalArgumentException("Artifact cannot be null.");
        }
        vulnerabilities = vulnerabilities == null ? List.of() : List.copyOf(vulnerabilities);
        reachabilityReports = reachabilityReports == null ? List.of() : List.copyOf(reachabilityReports);
        compatibilityReport = compatibilityReport == null ? Optional.empty() : compatibilityReport;
        currentStability = currentStability == null ? Optional.empty() : currentStability;
        fixVersionStability = fixVersionStability == null ? Optional.empty() : fixVersionStability;
        upgradePathValidation = upgradePathValidation == null ? Optional.empty() : upgradePathValidation;
    }

    /**
     * Convenience factory that omits stability data.
     * Falls back gracefully to neutral stability assumptions.
     */
    public static RemediationCandidate withoutStability(
            Artifact artifact,
            List<Vulnerability> vulnerabilities,
            ReachabilityStatus reachabilityStatus,
            List<VulnerabilityReachability> reachabilityReports,
            Optional<CompatibilityReport> compatibilityReport,
            Optional<String> fixVersion) {
        return new RemediationCandidate(
                artifact, vulnerabilities, reachabilityStatus, reachabilityReports,
                compatibilityReport, fixVersion,
                Optional.empty(), Optional.empty(), Optional.empty());
    }

    public boolean hasFixAvailable() {
        return fixVersion != null && fixVersion.isPresent();
    }

    /**
     * A CRITICAL+REACHABLE artifact is mandatory to address, regardless of budget.
     * The combination of confirmed call-graph reachability with a CVSS ≥ 9.0
     * represents the highest exploitability confidence.
     */
    public boolean isMandatoryUpgrade() {
        boolean hasCritical = vulnerabilities.stream()
                .anyMatch(v -> v.severity() == Severity.CRITICAL);
        return hasCritical
                && reachabilityStatus.isReachable()
                && hasFixAvailable();
    }

    public PfetDays pfetDays() {
        return fixVersionStability()
                .map(s -> PfetDays.of(s.releasedAt()))
                .orElse(PfetDays.unknown());
    }

    public double contextualRisk() {
        return contextualRisk(RiskWeights.defaults());
    }

    public double contextualRisk(RiskWeights weights) {
        double maxCvss = vulnerabilities.stream()
                .mapToDouble(v -> v.cvss().value())
                .max()
                .orElse(0.0);

        double maxEpss = vulnerabilities.stream()
                .flatMap(v -> v.epss().stream())
                .mapToDouble(epss -> epss.value())
                .max()
                .orElse(0.5);

        // 0.5 is the neutral assumption when Goblin data is unavailable
        double stalenessUrgency = currentStability
                .map(StabilityScore::stalenessUrgencyOf)
                .orElse(0.5);

        double reachabilityWeight = switch (reachabilityStatus) {
            case REACHABLE_CONFIRMED -> weights.reachableWeight();
            case REACHABLE_PROBABLE -> weights.reachableWeight();
            case UNKNOWN -> weights.unknownWeight();
            case UNREACHABLE -> weights.unreachableWeight();
        };

        double pfetMultiplier = 1.0 + Math.min(pfetDays().value() / PFET_SATURATION_DAYS, 1.0) * PFET_MAX_PENALTY;

        double riskScore = (maxCvss * weights.cvssWeight())
                + (maxEpss * SIGNAL_SCALE * weights.epssWeight())
                + (stalenessUrgency * SIGNAL_SCALE * weights.stalenessWeight());

        // netRiskDelta ∈ [-1, 1] → pathQualityFactor ∈ [PATH_QUALITY_FLOOR, 1.0]
        // Upgrades that introduce new transitive CVEs yield less net benefit.
        double pathQualityFactor = upgradePathValidation
                .map(upv -> Math.max(PATH_QUALITY_FLOOR,
                        PATH_QUALITY_MIDPOINT + upv.netRiskDelta() * PATH_QUALITY_MIDPOINT))
                .orElse(1.0);

        return riskScore * reachabilityWeight * pathQualityFactor * pfetMultiplier;
    }

    public double upgradeCost() {
        if (!hasFixAvailable()) {
            return Double.MAX_VALUE;
        }

        CompatibilityStatus compat = compatibilityReport
                .map(CompatibilityReport::status)
                .orElse(CompatibilityStatus.UNKNOWN);

        return switch (compat) {
            case COMPATIBLE -> 1.0;
            case UNKNOWN -> 2.0;
            case SOURCE_INCOMPATIBLE -> 3.0;
            case BINARY_INCOMPATIBLE -> 4.0;
        };
    }

    public String stabilityReportSummary() {
        StringBuilder sb = new StringBuilder();

        currentStability.ifPresentOrElse(cs -> sb.append(
                String.format("Current: TOOD=%d days, VersionLag=%d, LatestVersion=%s",
                        cs.tood().value(), cs.versionLag().value(), cs.latestVersion())),
                () -> sb.append("Current: no Goblin data"));

        sb.append(" | ");

        fixVersionStability.ifPresentOrElse(fs -> {
            StabilityScore score = StabilityScore.ofFixVersion(fs);
            sb.append(String.format(
                    "Fix: StabilityScore=%.2f (AdoptionRate=%.0f%%, Lifespan=%.0f days, MaintenanceRate=%.4f rel/day)",
                    score.value(),
                    fs.adoptionRate().value() * 100,
                    fs.adoptionLifespan().days(),
                    fs.maintenanceRate().value()));
        }, () -> sb.append("Fix: no Goblin data"));

        int pfet = pfetDays().value();
        if (pfet > 0) {
            sb.append(String.format(" | PFET=%d days", pfet));
        }

        upgradePathValidation.ifPresent(upv -> {
            sb.append(" | Upgrade path: ");
            sb.append(upv.isCleanPath() ? "CLEAN" : "HAS RISKS");
            if (!upv.isCleanPath()) {
                sb.append(String.format(" (%d new CVE(s))", upv.totalNewVulns()));
            }
            sb.append(String.format(" | netRiskDelta: %.2f", upv.netRiskDelta()));
        });

        return sb.toString();
    }
}