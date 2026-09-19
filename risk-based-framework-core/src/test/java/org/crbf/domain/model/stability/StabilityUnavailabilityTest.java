package org.crbf.domain.model.stability;

import static org.crbf.fixture.VulnerabilityFixture.vulnerability;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.Scope;
import org.crbf.domain.model.optimisation.RemediationCandidate;
import org.crbf.domain.model.optimisation.RiskWeights;
import org.crbf.domain.model.reachability.VulnerabilityReachability;
import org.crbf.domain.model.vulnerability.Vulnerability;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unavailable ecosystem data must be distinguishable from a genuine reading of
 * zero. Absent metrics fall back to a neutral value; a real "fully up to date"
 * reading contributes no staleness urgency. Collapsing the two would make an
 * unreachable ecosystem service silently lower the risk score.
 */
class StabilityUnavailabilityTest {

    private static final double NEUTRAL_STALENESS = 0.5;
    private static final double NO_STALENESS = 0.0;
    private static final double TOLERANCE = 1e-9;

    private static final double CVSS_SCORE = 8.0;
    private static final double CVSS_MAX_SCORE = 10.0;
    private static final double EPSS_SCORE = 0.02;

    private static final String CURRENT_VERSION = "1.0.0";
    private static final String FIX_VERSION = "2.0.0";

    private static final int NO_TIME_LAG_DAYS = 0;
    private static final int NO_VERSION_LAG = 0;
    private static final double NO_ADOPTION = 0.0;
    private static final double NO_LIFESPAN = 0.0;
    private static final double NO_MAINTENANCE = 0.0;
    private static final long UNSET_RELEASE_TIMESTAMP = 0L;

    private static final RiskWeights WEIGHTS = RiskWeights.defaults();

    @Test
    @DisplayName("Absent current stability falls back to neutral staleness urgency")
    void absentCurrentStabilityUsesNeutralStaleness() {
        RemediationCandidate candidate = candidateWithCurrentStability(Optional.empty());

        assertEquals(
                expectedContextualRisk(NEUTRAL_STALENESS),
                candidate.contextualRisk(WEIGHTS),
                TOLERANCE);
    }

    @Test
    @DisplayName("An up-to-date current version contributes no staleness urgency")
    void upToDateCurrentVersionContributesNoStaleness() {
        EcosystemStability upToDate = EcosystemStability.create(
                CURRENT_VERSION,
                NO_TIME_LAG_DAYS,
                NO_VERSION_LAG,
                NO_ADOPTION,
                NO_LIFESPAN,
                NO_MAINTENANCE,
                UNSET_RELEASE_TIMESTAMP);

        RemediationCandidate candidate = candidateWithCurrentStability(Optional.of(upToDate));

        assertEquals(
                expectedContextualRisk(NO_STALENESS),
                candidate.contextualRisk(WEIGHTS),
                TOLERANCE);
    }

    @Test
    @DisplayName("Unknown fix stability is neutral, not zero confidence")
    void unknownFixStabilityIsNeutral() {
        EcosystemStability unadopted = EcosystemStability.create(
                FIX_VERSION,
                NO_TIME_LAG_DAYS,
                NO_VERSION_LAG,
                NO_ADOPTION,
                NO_LIFESPAN,
                NO_MAINTENANCE,
                UNSET_RELEASE_TIMESTAMP);

        assertEquals(
                NEUTRAL_STALENESS,
                StabilityScore.unknown().value(),
                TOLERANCE);

        assertEquals(
                NO_STALENESS,
                StabilityScore.ofFixVersion(unadopted).value(),
                TOLERANCE);
    }

    private static double expectedContextualRisk(double stalenessUrgency) {
        return (CVSS_SCORE / CVSS_MAX_SCORE) * WEIGHTS.cvssWeight()
                + EPSS_SCORE * WEIGHTS.epssWeight()
                + stalenessUrgency * WEIGHTS.stalenessWeight();
    }

    private static RemediationCandidate candidateWithCurrentStability(
            Optional<EcosystemStability> currentStability) {

        Vulnerability vulnerability = vulnerability("CVE-0000-0001", CVSS_SCORE, EPSS_SCORE);

        return new RemediationCandidate(
                Artifact.create("org.example", "test-library", CURRENT_VERSION, Scope.COMPILE),
                List.of(vulnerability),
                List.of(VulnerabilityReachability.reachableConfirmed(vulnerability, Set.of(), Set.of())),
                Optional.empty(),
                Optional.of(FIX_VERSION),
                Optional.empty(),
                currentStability,
                Optional.empty(),
                Optional.empty());
    }
}
