package org.crbf.domain.model.optimisation;

import static org.crbf.fixture.VulnerabilityFixture.vulnerability;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.Scope;
import org.crbf.domain.model.reachability.ReachabilityStatus;
import org.crbf.domain.model.reachability.VulnerabilityReachability;
import org.crbf.domain.model.stability.EcosystemStability;
import org.crbf.domain.model.vulnerability.Vulnerability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class ContextualRiskFactorsTest {
    private static final double TOLERANCE = 1e-9;
    private static final Artifact ARTIFACT = Artifact.create("org.example", "library", "1.0.0", Scope.COMPILE);
    private static final Vulnerability VULNERABILITY = vulnerability("CVE-2026-1001", 10, 0);
    private static final RiskWeights CVSS_ONLY = new RiskWeights(1, 0, 0, 1, 0.5, 0.1);
    private static final RiskWeights STALENESS_ONLY = new RiskWeights(0, 0, 1, 1, 0.5, 0.1);

    @ParameterizedTest
    @CsvSource({"73, 2, 0.20", "365, 0, 0.60", "730, 0, 0.60", "0, 10, 0.40", "0, 20, 0.40"})
    void shouldApplyWeightedStalenessWithIndependentSaturationLimits(int days, int missedVersions, double expectedRisk) {
        EcosystemStability current = EcosystemStability.create("2.0.0", days, missedVersions, null, null, null, 0);
        RemediationCandidate candidate = candidate(ReachabilityStatus.REACHABLE_CONFIRMED,
                Optional.of(current), Optional.empty());

        double risk = candidate.contextualRisk(STALENESS_ONLY);

        assertEquals(expectedRisk, risk, TOLERANCE);
    }

    @ParameterizedTest
    @CsvSource({"REACHABLE_CONFIRMED, 1.0", "REACHABLE_PROBABLE, 1.0", "UNKNOWN, 0.5", "UNREACHABLE, 0.1"})
    void shouldApplyTheWeightForTheVulnerabilityReachability(ReachabilityStatus status, double expectedRisk) {
        RemediationCandidate candidate = candidate(status, Optional.empty(), Optional.empty());

        double risk = candidate.contextualRisk(CVSS_ONLY);

        assertEquals(expectedRisk, risk, TOLERANCE);
    }

    @ParameterizedTest
    @CsvSource({
            "CLEAN, 1.0, 1.0",
            "HAS_RISKS, 0.5, 0.75",
            "HAS_RISKS, 0.0, 0.50",
            "HAS_RISKS, -0.2, 0.40",
            "HAS_RISKS, -0.4, 0.30",
            "HAS_RISKS, -1.0, 0.30"
    })
    void shouldApplyPathQualityAndRetainItsMinimumFloor(
            UpgradePathStatus status, double signal, double expectedRisk) {
        UpgradePathValidation path = path(Optional.of(signal), status);
        RemediationCandidate candidate = candidate(ReachabilityStatus.REACHABLE_CONFIRMED,
                Optional.empty(), Optional.of(path));

        double risk = candidate.contextualRisk(CVSS_ONLY);

        assertEquals(expectedRisk, risk, TOLERANCE);
    }

    @Test
    void shouldRetainRiskWhenUpgradePathQualityIsUnknown() {
        UpgradePathValidation unknown = path(Optional.empty(), UpgradePathStatus.UNKNOWN);
        RemediationCandidate candidate = candidate(ReachabilityStatus.REACHABLE_CONFIRMED,
                Optional.empty(), Optional.of(unknown));

        assertEquals(1.0, candidate.contextualRisk(CVSS_ONLY), TOLERANCE);
    }

    private RemediationCandidate candidate(ReachabilityStatus status, Optional<EcosystemStability> current,
            Optional<UpgradePathValidation> path) {
        return new RemediationCandidate(ARTIFACT, List.of(VULNERABILITY),
                List.of(new VulnerabilityReachability(VULNERABILITY, status, Set.of(), Set.of())),
                Optional.empty(), Optional.of("2.0.0"), Optional.empty(), current, Optional.empty(), path);
    }

    private UpgradePathValidation path(Optional<Double> signal, UpgradePathStatus status) {
        return new UpgradePathValidation(ARTIFACT, "2.0.0", List.of(), List.of(), List.of(), List.of(),
                Optional.empty(), signal, status, Optional.empty());
    }
}
