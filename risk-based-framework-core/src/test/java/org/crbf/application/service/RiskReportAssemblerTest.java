package org.crbf.application.service;

import static org.crbf.fixture.RemediationCandidateFixture.withFix;
import static org.crbf.fixture.VulnerabilityFixture.vulnerability;
import static org.crbf.fixture.VulnerabilityFixture.vulnerabilityWithoutEpss;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.crbf.adapter.out.z3.Z3RemediationAdapter;
import org.crbf.application.model.report.ArtifactFinding;
import org.crbf.application.model.report.RiskReport;
import org.crbf.application.model.report.UpgradeDecision;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.Scope;
import org.crbf.domain.model.optimisation.GlobalGraphValidation;
import org.crbf.domain.model.optimisation.OptimisationStatus;
import org.crbf.domain.model.optimisation.RemediationCandidate;
import org.crbf.domain.model.optimisation.RemediationDecision;
import org.crbf.domain.model.optimisation.RemediationPlan;
import org.crbf.domain.model.reachability.ReachabilityStatus;
import org.crbf.domain.model.reachability.VulnerabilityReachability;
import org.crbf.domain.model.risk.ContextualRisk;
import org.crbf.domain.model.vulnerability.Vulnerability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.CsvSource;

class RiskReportAssemblerTest {

        @Test
        void shouldIncludeThePlanBudgetInTheReport() {
                RemediationPlan plan = RemediationPlan.empty().withEffortBudget(10);

                RiskReport report = new RiskReportAssembler().assemble(Path.of("test-project"), List.of(),
                                Set.of(), List.of(), plan, List.of());

                assertEquals(Optional.of(10.0), report.availableEffortBudget());
        }

        @ParameterizedTest
        @CsvSource({ "9.5, true, MANDATORY_PENDING", "8.0, true, OPTIONAL_NOT_SELECTED",
                        "8.0, false, NO_FIX_AVAILABLE" })
        void shouldDistinguishUnselectedActionsWhenNoFeasiblePlanExists(
                        double cvss, boolean hasFix, UpgradeDecision expected) {
                Vulnerability critical = vulnerability("CVE-2026-0001", 10, 0.5);
                RemediationCandidate mandatory = withFix(List.of(new VulnerabilityReachability(
                                critical, ReachabilityStatus.REACHABLE_CONFIRMED, Set.of(), Set.of())));
                Vulnerability vulnerability = vulnerability("CVE-2026-0002", cvss, 0.5);
                RemediationCandidate candidate = RemediationCandidate.withoutStability(
                                Artifact.create("org.example", "other", "1.0.0", Scope.COMPILE), List.of(vulnerability),
                                List.of(new VulnerabilityReachability(vulnerability,
                                                ReachabilityStatus.REACHABLE_CONFIRMED, Set.of(), Set.of())),
                                Optional.empty(), hasFix ? Optional.of("2.0.0") : Optional.empty(), Optional.empty());
                List<RemediationCandidate> candidates = List.of(mandatory, candidate);
                RemediationPlan plan = new Z3RemediationAdapter(1).optimize(candidates);

                RiskReport report = new RiskReportAssembler().assemble(Path.of("test-project"), List.of(),
                                Set.of(mandatory.artifact(), candidate.artifact()), candidates, plan, List.of());

                assertEquals(expected, report.findings().get(1).remediation().decision());
                assertEquals(0, report.findings().get(1).remediation().effortCost());
                assertEquals(0, report.findings().get(1).remediation().riskReduction());
                assertEquals(plan.infeasibility(), report.infeasibility());
        }

        @ParameterizedTest
        @EnumSource(OptimisationStatus.class)
        void shouldPreserveOptimisationOutcomeThroughGraphValidationAndReporting(OptimisationStatus status) {
                RemediationPlan plan = new RemediationPlan(List.of(), 0, 0, 0,
                                status, GlobalGraphValidation.notRun());

                RiskReport report = new RiskReportAssembler().assemble(
                                Path.of("test-project"), List.of(), Set.of(), List.of(),
                                plan.withGlobalValidation(GlobalGraphValidation.notRun()), List.of());

                assertEquals(status, report.optimisationStatus());
        }

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

                assertEquals(5.0 / 7.0, risk.effectiveCvssWeight(), TOLERANCE);
                assertEquals(0.0, risk.effectiveEpssWeight(), TOLERANCE);
                assertEquals(2.0 / 7.0, risk.effectiveStalenessWeight(), TOLERANCE);
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