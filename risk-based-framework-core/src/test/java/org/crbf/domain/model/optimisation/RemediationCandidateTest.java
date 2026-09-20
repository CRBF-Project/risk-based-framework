package org.crbf.domain.model.optimisation;

import static org.crbf.fixture.RemediationCandidateFixture.withFix;
import static org.crbf.fixture.VulnerabilityFixture.vulnerability;
import static org.crbf.fixture.VulnerabilityFixture.vulnerabilityWithoutEpss;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

class RemediationCandidateTest {

    private static final double DELTA = 0.000001;

    @Test
    void contextualRiskShouldNormalizeCvssToUnitInterval() {
        Vulnerability vulnerability = vulnerability("CVE-2026-0001", 10.0, 0.0);

        RemediationCandidate candidate = withFix(List.of(
                reachability(
                        vulnerability,
                        ReachabilityStatus.REACHABLE_CONFIRMED)));

        RiskWeights cvssOnlyWeights = new RiskWeights(
                1.0,
                0.0,
                0.0,
                1.0,
                1.0,
                1.0);

        double risk = candidate.contextualRisk(cvssOnlyWeights);
        double expectedRisk = 1.0;
        assertEquals(expectedRisk, risk, DELTA);
    }

    @Test
    void contextualRiskShouldUseSignalsFromTheSameVulnerability() {
        Vulnerability criticalUnreachable = vulnerability("CVE-2026-0001", 10.0, 0.10);

        Vulnerability highReachable = vulnerability("CVE-2026-0002", 5.0, 0.90);

        RemediationCandidate candidate = withFix(List.of(
                reachability(
                        criticalUnreachable,
                        ReachabilityStatus.UNREACHABLE),
                reachability(
                        highReachable,
                        ReachabilityStatus.REACHABLE_CONFIRMED)));

        RiskWeights weights = new RiskWeights(
                0.50,
                0.30,
                0.20,
                1.00,
                0.50,
                0.10);

        double risk = candidate.contextualRisk(weights);

        double expectedRisk = 0.62;
        assertEquals(expectedRisk, risk, DELTA);
    }

    @Test
    void mandatoryUpgradeShouldRequireCriticalAndReachableOnSameVulnerability() {
        Vulnerability criticalUnreachable = vulnerability("CVE-2026-0001", 9.5, 0.20);

        Vulnerability highReachable = vulnerability("CVE-2026-0002", 8.0, 0.80);

        RemediationCandidate candidate = withFix(List.of(
                reachability(
                        criticalUnreachable,
                        ReachabilityStatus.UNREACHABLE),
                reachability(
                        highReachable,
                        ReachabilityStatus.REACHABLE_CONFIRMED)));

        assertFalse(candidate.isMandatoryUpgrade());
    }

    @Test
    void mandatoryUpgradeShouldBeTrueWhenCriticalVulnerabilityIsReachable() {
        Vulnerability criticalReachable = vulnerability("CVE-2026-0001", 9.5, 0.20);

        RemediationCandidate candidate = withFix(List.of(
                reachability(
                        criticalReachable,
                        ReachabilityStatus.REACHABLE_CONFIRMED)));

        assertTrue(candidate.isMandatoryUpgrade());
    }

    @Test
    void aggregateReachabilityShouldReturnHighestReachabilityStatus() {
        Vulnerability unreachable = vulnerability("CVE-2026-0001", 5.0, 0.10);

        Vulnerability confirmed = vulnerability("CVE-2026-0002", 7.0, 0.20);

        RemediationCandidate candidate = withFix(List.of(
                reachability(
                        unreachable,
                        ReachabilityStatus.UNREACHABLE),
                reachability(
                        confirmed,
                        ReachabilityStatus.REACHABLE_CONFIRMED)));

        assertEquals(
                ReachabilityStatus.REACHABLE_CONFIRMED,
                candidate.aggregateReachabilityStatus());
    }

    @Test
    void candidateShouldRejectMissingReachabilityReport() {
        Vulnerability vulnerability = vulnerability("CVE-2026-0001", 7.0, 0.20);

        Artifact artifact = Artifact.create(
                "org.example",
                "test-library",
                "1.0.0",
                Scope.COMPILE);

        assertThrows(
                IllegalArgumentException.class,
                () -> new RemediationCandidate(
                        artifact,
                        List.of(vulnerability),
                        List.of(),
                        Optional.empty(),
                        Optional.of("2.0.0"),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty()));
    }

    @Test
    void contextualRiskShouldRenormalizeAvailableWeightsWhenEpssIsUnavailable() {
        double cvss = 8.0;
        double cvssMaxScore = 10.0;
        double normalizedCvss = cvss / cvssMaxScore;

        Vulnerability vulnerability = vulnerabilityWithoutEpss("CVE-2026-0001", cvss);

        RemediationCandidate candidate = withFix(List.of(
                reachability(
                        vulnerability,
                        ReachabilityStatus.REACHABLE_CONFIRMED)));

        double cvssWeight = 0.50;
        double epssWeight = 0.30;
        double stalenessWeight = 0.20;

        RiskWeights weights = new RiskWeights(
                cvssWeight,
                epssWeight,
                stalenessWeight,
                1.00,
                0.50,
                0.10);

        double risk = candidate.contextualRisk(weights);

        double defaultStalenessUrgency = 0.5;
        double availableWeight = cvssWeight + stalenessWeight;

        double expectedRisk = ((normalizedCvss * cvssWeight)
                + (defaultStalenessUrgency * stalenessWeight))
                / availableWeight;

        assertEquals(expectedRisk, risk, DELTA);
    }

    @Test
    void contextualRiskShouldNotRenormalizeWeightsWhenEpssIsZero() {
        double cvss = 8.0;
        double cvssMaxScore = 10.0;
        double normalizedCvss = cvss / cvssMaxScore;
        double epss = 0.0;

        Vulnerability vulnerability = vulnerability("CVE-2026-0001", cvss, epss);

        RemediationCandidate candidate = withFix(List.of(
                reachability(
                        vulnerability,
                        ReachabilityStatus.REACHABLE_CONFIRMED)));

        double cvssWeight = 0.50;
        double epssWeight = 0.30;
        double stalenessWeight = 0.20;

        RiskWeights weights = new RiskWeights(
                cvssWeight,
                epssWeight,
                stalenessWeight,
                1.00,
                0.50,
                0.10);

        double risk = candidate.contextualRisk(weights);

        double defaultStalenessUrgency = 0.5;

        double expectedRisk = (normalizedCvss * cvssWeight)
                + (epss * epssWeight)
                + (defaultStalenessUrgency * stalenessWeight);

        assertEquals(expectedRisk, risk, DELTA);
    }

    @Test
    void contextualRiskShouldReachTheoreticalMaximum() {
        Artifact artifact = Artifact.create(
                "org.example",
                "test-library",
                "1.0.0",
                Scope.COMPILE);

        double maximumCvss = 10.0;
        double maximumEpss = 1.0;

        Vulnerability vulnerability = vulnerability(
                "CVE-2026-0001",
                maximumCvss,
                maximumEpss);

        EcosystemStability maximumStaleness = EcosystemStability.create(
                "2.0.0",
                365,
                10,
                0.0,
                0.0,
                0.0,
                0L);

        RemediationCandidate candidate = new RemediationCandidate(
                artifact,
                List.of(vulnerability),
                List.of(reachability(
                        vulnerability,
                        ReachabilityStatus.REACHABLE_CONFIRMED)),
                Optional.empty(),
                Optional.of("2.0.0"),
                Optional.empty(),
                Optional.of(maximumStaleness),
                Optional.empty(),
                Optional.empty());

        // Every weighted signal saturated, with reachability and path quality
        // both neutral at 1.0, bounds the contextual risk at 1.0.
        double expectedMaximumRisk = 1.0;

        assertEquals(
                expectedMaximumRisk,
                candidate.contextualRisk(),
                DELTA);
    }

    private static VulnerabilityReachability reachability(
            Vulnerability vulnerability,
            ReachabilityStatus status) {

        return new VulnerabilityReachability(
                vulnerability,
                status,
                Set.of(),
                Set.of());
    }
}