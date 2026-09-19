package org.crbf.application.service;

import static org.crbf.fixture.RemediationCandidateFixture.withFix;
import static org.crbf.fixture.VulnerabilityFixture.vulnerability;
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

    private static final double TOLERANCE = 1e-9;
}