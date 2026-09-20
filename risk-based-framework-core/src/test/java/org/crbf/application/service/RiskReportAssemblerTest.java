package org.crbf.application.service;

import static org.crbf.fixture.RemediationCandidateFixture.withFix;
import static org.crbf.fixture.VulnerabilityFixture.vulnerability;
import static org.crbf.fixture.VulnerabilityFixture.vulnerabilityWithoutEpss;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import org.crbf.application.model.report.ArtifactFinding;
import org.crbf.application.model.report.RiskReport;
import org.crbf.application.model.report.UpgradeDecision;
import org.crbf.domain.model.optimisation.GlobalGraphValidation;
import org.crbf.domain.model.optimisation.RemediationCandidate;
import org.crbf.domain.model.optimisation.RemediationDecision;
import org.crbf.domain.model.optimisation.RemediationPlan;
import org.crbf.domain.model.reachability.ReachabilityStatus;
import org.crbf.domain.model.reachability.VulnerabilityReachability;
import org.crbf.domain.model.risk.ContextualRisk;
import org.crbf.domain.model.vulnerability.Vulnerability;
import org.junit.jupiter.api.Test;

class RiskReportAssemblerTest {

    @Test
    void selectedReachableCandidateShouldBeRecommendedWhenNotMandatory() {
        Vulnerability vulnerability = vulnerability("CVE-2026-0001", 8.0, 0.80);

        RemediationCandidate candidate = withFix(List.of(
                new VulnerabilityReachability(
                        vulnerability,
                        ReachabilityStatus.REACHABLE_CONFIRMED,
                        Set.of(),
                        Set.of())));

        double riskReduction = 0.5;
        double effortCost = 1.0;

        RemediationDecision decision = RemediationDecision.upgrade(
                candidate.artifact(),
                candidate.fixVersion().orElseThrow(),
                riskReduction,
                effortCost,
                "Selected by optimiser.");

        RemediationPlan plan = new RemediationPlan(
                List.of(decision),
                decision.riskReduction(),
                0.0,
                decision.effortCost(),
                true,
                GlobalGraphValidation.notRun());

        RiskReport report = new RiskReportAssembler().assemble(
                Path.of("test-project"),
                List.of(),
                Set.of(candidate.artifact()),
                List.of(candidate),
                plan,
                List.of());

        UpgradeDecision actualDecision = report.findings()
                .get(0)
                .remediation()
                .decision();

        assertEquals(
                UpgradeDecision.RECOMMENDED,
                actualDecision);
    }

    @Test
    void selectedCriticalReachableCandidateShouldBeMandatory() {
        Vulnerability vulnerability = vulnerability("CVE-2026-0001", 9.5, 0.80);

        RemediationCandidate candidate = withFix(List.of(
                new VulnerabilityReachability(
                        vulnerability,
                        ReachabilityStatus.REACHABLE_CONFIRMED,
                        Set.of(),
                        Set.of())));

        double riskReduction = 0.5;
        double effortCost = 1.0;

        RemediationDecision decision = RemediationDecision.upgrade(
                candidate.artifact(),
                candidate.fixVersion().orElseThrow(),
                riskReduction,
                effortCost,
                "Mandatory upgrade.");

        RemediationPlan plan = new RemediationPlan(
                List.of(decision),
                decision.riskReduction(),
                0.0,
                decision.effortCost(),
                true,
                GlobalGraphValidation.notRun());

        RiskReport report = new RiskReportAssembler().assemble(
                Path.of("test-project"),
                List.of(),
                Set.of(candidate.artifact()),
                List.of(candidate),
                plan,
                List.of());

        UpgradeDecision actualDecision = report.findings()
                .get(0)
                .remediation()
                .decision();

        assertEquals(UpgradeDecision.MANDATORY, actualDecision);
    }

    @Test
    void findingShouldExposeContextualRiskIndependentlyOfRiskReduction() {
        Vulnerability vulnerability = vulnerability("CVE-2026-0001", 8.0, 0.80);

        RemediationCandidate candidate = withFix(List.of(
                new VulnerabilityReachability(
                        vulnerability,
                        ReachabilityStatus.REACHABLE_CONFIRMED,
                        Set.of(),
                        Set.of())));

        // No decision reaches the plan, so the remediation summary reports zero
        // risk reduction. The finding must still carry the artifact's own risk.
        RemediationPlan emptyPlan = new RemediationPlan(
                List.of(),
                0.0,
                candidate.contextualRisk(),
                0.0,
                true,
                GlobalGraphValidation.notRun());

        RiskReport report = new RiskReportAssembler().assemble(
                Path.of("test-project"),
                List.of(),
                Set.of(candidate.artifact()),
                List.of(candidate),
                emptyPlan,
                List.of());

        ArtifactFinding finding = report.findings().get(0);

        assertEquals(0.0, finding.remediation().riskReduction(), TOLERANCE);
        assertEquals(
                candidate.contextualRisk(),
                finding.contextualRisk(),
                TOLERANCE);
    }

    @Test
    void reportedContextualRiskShouldBeReconstructibleFromTheFactorsPublishedWithIt() {
        Vulnerability vulnerability = vulnerability("CVE-2026-0001", 8.0, 0.80);

        RemediationCandidate candidate = withFix(List.of(
                new VulnerabilityReachability(
                        vulnerability,
                        ReachabilityStatus.REACHABLE_CONFIRMED,
                        Set.of(),
                        Set.of())));

        ContextualRisk risk = assembleSingleFindingRisk(candidate);

        double reconstructed = (risk.cvssNormalized() * risk.effectiveCvssWeight()
                + risk.epss().orElse(0.0) * risk.effectiveEpssWeight()
                + risk.stalenessUrgency() * risk.effectiveStalenessWeight())
                * risk.reachabilityFactor()
                * risk.pathQualityFactor();

        assertEquals(risk.value(), reconstructed, TOLERANCE);
    }

    @Test
    void reportedWeightsShouldBeRenormalisedWhenNoEpssScoreExists() {
        Vulnerability vulnerability = vulnerabilityWithoutEpss("CVE-2026-0002", 8.0);

        RemediationCandidate candidate = withFix(List.of(
                new VulnerabilityReachability(
                        vulnerability,
                        ReachabilityStatus.REACHABLE_CONFIRMED,
                        Set.of(),
                        Set.of())));

        ContextualRisk risk = assembleSingleFindingRisk(candidate);

        // The EPSS weight is redistributed over the signals that were observed,
        // so the weights the report publishes still describe a complete
        // calculation rather than the configured 0.50/0.30/0.20.
        assertEquals(
                1.0,
                risk.effectiveCvssWeight()
                        + risk.effectiveEpssWeight()
                        + risk.effectiveStalenessWeight(),
                TOLERANCE);
    }

    private ContextualRisk assembleSingleFindingRisk(RemediationCandidate candidate) {
        RiskReport report = new RiskReportAssembler().assemble(
                Path.of("test-project"),
                List.of(),
                Set.of(candidate.artifact()),
                List.of(candidate),
                RemediationPlan.empty(),
                List.of());

        return report.findings().get(0).vulnerabilities().get(0).contextualRisk();
    }

    private static final double TOLERANCE = 1e-9;
}