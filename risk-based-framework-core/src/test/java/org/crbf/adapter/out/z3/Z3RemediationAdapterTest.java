package org.crbf.adapter.out.z3;

import static org.crbf.fixture.VulnerabilityFixture.vulnerability;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.Scope;
import org.crbf.domain.model.compatibility.CompatibilityReport;
import org.crbf.domain.model.compatibility.CompatibilityStatus;
import org.crbf.domain.model.optimisation.RemediationCandidate;
import org.crbf.domain.model.optimisation.OptimisationStatus;
import org.crbf.domain.model.optimisation.InfeasibilityDetails;
import org.crbf.domain.model.optimisation.GlobalGraphValidation;
import org.crbf.domain.model.optimisation.RemediationDecision;
import org.crbf.domain.model.optimisation.RemediationPlan;
import org.crbf.domain.model.optimisation.RiskWeights;
import org.crbf.domain.model.reachability.ReachabilityStatus;
import org.crbf.domain.model.reachability.VulnerabilityReachability;
import org.crbf.domain.model.vulnerability.Vulnerability;
import org.junit.jupiter.api.Test;

class Z3RemediationAdapterTest {

    private static final double DELTA = 0.000001;
    // Isolate selection from other risk signals: contextual risk = CVSS / 10.
    private static final RiskWeights CVSS_ONLY = new RiskWeights(1, 0, 0, 1, 1, 1);

    @Test
    void shouldReportConfiguredBudgetForOptimalPlans() {
        RemediationPlan plan = new Z3RemediationAdapter(4, CVSS_ONLY)
                .optimize(List.of(candidate("budget", 8, CompatibilityStatus.COMPATIBLE)));

        assertEquals(Optional.of(4.0), plan.availableEffortBudget());
    }

    @Test
    void shouldReportConfiguredBudgetForFallbackPlans() {
        RemediationPlan plan = failingSolver(4)
                .optimize(List.of(candidate("budget", 8, CompatibilityStatus.COMPATIBLE)));

        assertEquals(Optional.of(4.0), plan.availableEffortBudget());
    }

    @Test
    void shouldPreserveBudgetAfterValidatingAnInfeasiblePlan() {
        RemediationPlan plan = new Z3RemediationAdapter(1, CVSS_ONLY)
                .optimize(List.of(candidate("budget", 10, CompatibilityStatus.UNKNOWN)))
                .withGlobalValidation(GlobalGraphValidation.notRun());

        assertEquals(Optional.of(1.0), plan.availableEffortBudget());
    }

    @Test
    void shouldReportBudgetWhenOptimisationHasNoCandidates() {
        assertEquals(Optional.of(4.0), failingSolver(4).optimize(List.of()).availableEffortBudget());
    }

    @Test
    void shouldSkipTheSolverWhenNoVulnerableDependenciesExist() {
        RemediationPlan plan = failingSolver(1).optimize(List.of());

        assertEquals(OptimisationStatus.NOT_RUN, plan.optimisationStatus());
        assertEquals(List.of(), plan.decisions());
    }

    @Test
    void shouldRetainMandatoryPendingDetailsAfterGraphValidation() {
        RemediationCandidate first = candidate("first", 9.5, CompatibilityStatus.UNKNOWN);
        RemediationCandidate second = candidate("second", 10, CompatibilityStatus.UNKNOWN);

        RemediationPlan plan = new Z3RemediationAdapter(3, CVSS_ONLY).optimize(List.of(first, second))
                .withGlobalValidation(GlobalGraphValidation.notRun());

        InfeasibilityDetails details = plan.infeasibility().orElseThrow();
        assertEquals(InfeasibilityDetails.Reason.MANDATORY_EFFORT_EXCEEDS_BUDGET, details.reason());
        assertEquals(3, details.availableEffortBudget(), DELTA);
        assertEquals(4, details.requiredMandatoryEffort(), DELTA);
        assertEquals(1, details.budgetShortfall().orElseThrow(), DELTA);
        assertEquals(List.of(
                new InfeasibilityDetails.MandatoryUpgrade(first.artifact().gav(), "2.0.0", 2),
                new InfeasibilityDetails.MandatoryUpgrade(second.artifact().gav(), "2.0.0", 2)), details.mandatoryUpgrades());
    }

    @Test
    void shouldMaximiseTotalRiskReductionRatherThanGreedyRiskPerEffort() {
        RemediationCandidate cheap = candidate("cheap", 5, CompatibilityStatus.COMPATIBLE);
        RemediationCandidate first = candidate("first", 8, CompatibilityStatus.UNKNOWN);
        RemediationCandidate second = candidate("second", 7, CompatibilityStatus.UNKNOWN);

        RemediationPlan plan = new Z3RemediationAdapter(4, CVSS_ONLY)
                .optimize(List.of(cheap, first, second));

        assertTrue(plan.solvedByZ3());
        assertEquals(Set.of(first.artifact(), second.artifact()), upgradedArtifacts(plan));
        assertEquals(1.5, plan.totalRiskReduction(), DELTA);
        assertEquals(0.5, plan.totalResidualRisk(), DELTA);
    }

    @Test
    void shouldAllowAnUpgradeThatExactlyUsesTheEffortBudget() {
        RemediationCandidate candidate = candidate("exact", 8, CompatibilityStatus.SOURCE_INCOMPATIBLE);

        RemediationPlan plan = new Z3RemediationAdapter(3, CVSS_ONLY).optimize(List.of(candidate));

        assertTrue(plan.solvedByZ3());
        assertEquals(Set.of(candidate.artifact()), upgradedArtifacts(plan));
        assertEquals(3, plan.totalEffortCost(), DELTA);
        assertEquals("2.0.0", plan.upgradeRecommendations().get(0).targetVersion());
    }

    @Test
    void shouldDeferAnOptionalUpgradeThatExceedsTheEffortBudget() {
        RemediationCandidate candidate = candidate("expensive", 8, CompatibilityStatus.BINARY_INCOMPATIBLE);

        RemediationPlan plan = new Z3RemediationAdapter(3, CVSS_ONLY).optimize(List.of(candidate));

        assertTrue(plan.solvedByZ3());
        assertEquals(List.of(), plan.upgradeRecommendations());
        assertEquals(1, plan.deferredDecisions().size());
        assertEquals(0, plan.totalEffortCost(), DELTA);
        assertEquals(0.8, plan.totalResidualRisk(), DELTA);
    }

    @Test
    void shouldDeferCriticalReachableDependenciesWithoutAvailableFixes() {
        RemediationCandidate noFix = candidate("no-fix", 10, ReachabilityStatus.REACHABLE_CONFIRMED,
                CompatibilityStatus.COMPATIBLE, Optional.empty());
        RemediationCandidate fixable = candidate("fixable", 6, CompatibilityStatus.COMPATIBLE);

        RemediationPlan plan = new Z3RemediationAdapter(2, CVSS_ONLY).optimize(List.of(noFix, fixable));

        assertTrue(plan.solvedByZ3());
        assertEquals(Set.of(fixable.artifact()), upgradedArtifacts(plan));
        assertEquals(List.of(noFix.artifact()), plan.deferredDecisions().stream()
                .map(decision -> decision.artifact()).toList());
        assertEquals(1, plan.totalResidualRisk(), DELTA);
    }

    @Test
    void shouldSelectMandatoryUpgradeEvenWhenOptionalUpgradesOfferMoreRiskReduction() {
        RemediationCandidate mandatory = candidate("mandatory", 9.5, CompatibilityStatus.BINARY_INCOMPATIBLE);
        RemediationCandidate first = candidate("first", 8, CompatibilityStatus.UNKNOWN);
        RemediationCandidate second = candidate("second", 7, CompatibilityStatus.UNKNOWN);

        RemediationPlan plan = new Z3RemediationAdapter(4, CVSS_ONLY)
                .optimize(List.of(mandatory, first, second));

        assertTrue(plan.solvedByZ3());
        assertEquals(Set.of(mandatory.artifact()), upgradedArtifacts(plan));
        assertEquals(4, plan.totalEffortCost(), DELTA);
    }

    @Test
    void shouldNotForceCriticalUpgradesWhenTheVulnerabilityIsUnreachable() {
        RemediationCandidate critical = candidate("critical", 10, ReachabilityStatus.UNREACHABLE,
                CompatibilityStatus.BINARY_INCOMPATIBLE, Optional.of("2.0.0"));
        RemediationCandidate first = candidate("first", 8, CompatibilityStatus.UNKNOWN);
        RemediationCandidate second = candidate("second", 7, CompatibilityStatus.UNKNOWN);

        RemediationPlan plan = new Z3RemediationAdapter(4, CVSS_ONLY)
                .optimize(List.of(critical, first, second));

        assertTrue(plan.solvedByZ3());
        assertEquals(Set.of(first.artifact(), second.artifact()), upgradedArtifacts(plan));
    }

    @Test
    void shouldReportInfeasibilityWhenMandatoryUpgradesExceedBudget() {
        RemediationCandidate first = candidate("first", 9.5, CompatibilityStatus.UNKNOWN);
        RemediationCandidate second = candidate("second", 10, CompatibilityStatus.UNKNOWN);

        RemediationPlan plan = new Z3RemediationAdapter(3, CVSS_ONLY).optimize(List.of(first, second));

        assertEquals(OptimisationStatus.INFEASIBLE, plan.optimisationStatus());
        assertFalse(plan.solvedByZ3());
        assertEquals(Set.of(), upgradedArtifacts(plan));
        assertEquals(0, plan.totalEffortCost(), DELTA);
        assertEquals(0, plan.totalRiskReduction(), DELTA);
        assertEquals(1.95, plan.totalResidualRisk(), DELTA);
    }

    @Test
    void shouldReserveMandatoryEffortBeforeOptionalUpgradesInFallback() {
        RemediationCandidate mandatory = candidate("mandatory", 10, CompatibilityStatus.BINARY_INCOMPATIBLE);
        RemediationCandidate optional = candidate("optional", 8, CompatibilityStatus.COMPATIBLE);

        RemediationPlan plan = failingSolver(4).optimize(List.of(mandatory, optional));

        // Optional work has the higher risk/effort ratio, but cannot displace mandatory work.
        assertEquals(OptimisationStatus.GREEDY_FALLBACK, plan.optimisationStatus());
        assertFalse(plan.solvedByZ3());
        assertEquals(Set.of(mandatory.artifact()), upgradedArtifacts(plan));
        assertEquals(4, plan.totalEffortCost(), DELTA);
        assertEquals(0.8, plan.totalResidualRisk(), DELTA);
    }

    @Test
    void shouldIncludeUnfixedDependenciesInFallbackResidualRisk() {
        RemediationCandidate mandatory = candidate("mandatory", 10, CompatibilityStatus.UNKNOWN);
        RemediationCandidate noFix = candidate("no-fix", 8, ReachabilityStatus.REACHABLE_CONFIRMED,
                CompatibilityStatus.UNKNOWN, Optional.empty());

        RemediationPlan plan = failingSolver(2).optimize(List.of(mandatory, noFix));

        assertEquals(OptimisationStatus.GREEDY_FALLBACK, plan.optimisationStatus());
        assertFalse(plan.solvedByZ3());
        assertEquals(List.of(noFix.artifact()), plan.deferredDecisions().stream()
                .map(decision -> decision.artifact()).toList());
        assertEquals(0.8, plan.totalResidualRisk(), DELTA);
    }

    @Test
    void shouldSpendOnlyRemainingEffortOnOptionalUpgradesInFallback() {
        RemediationCandidate mandatory = candidate("mandatory", 10, CompatibilityStatus.UNKNOWN);
        RemediationCandidate cheap = candidate("cheap", 8, CompatibilityStatus.COMPATIBLE);
        RemediationCandidate expensive = candidate("expensive", 7, CompatibilityStatus.UNKNOWN);

        RemediationPlan plan = failingSolver(3).optimize(List.of(expensive, mandatory, cheap));

        assertEquals(OptimisationStatus.GREEDY_FALLBACK, plan.optimisationStatus());
        assertEquals(Set.of(mandatory.artifact(), cheap.artifact()), upgradedArtifacts(plan));
        assertEquals(3, plan.totalEffortCost(), DELTA);
        assertEquals(0.7, plan.totalResidualRisk(), DELTA);
    }

    @Test
    void shouldReportInfeasibilityEvenWhenTheSolverCannotStart() {
        RemediationCandidate mandatory = candidate("mandatory", 10, CompatibilityStatus.UNKNOWN);
        RemediationCandidate noFix = candidate("no-fix", 8, ReachabilityStatus.REACHABLE_CONFIRMED,
                CompatibilityStatus.UNKNOWN, Optional.empty());

        RemediationPlan plan = failingSolver(1).optimize(List.of(mandatory, noFix));

        assertEquals(OptimisationStatus.INFEASIBLE, plan.optimisationStatus());
        assertEquals(Set.of(), upgradedArtifacts(plan));
        assertEquals(1.8, plan.totalResidualRisk(), DELTA);
    }

    @Test
    void shouldNotSelectOptionalUpgradesWhenMandatoryConstraintsAreInfeasible() {
        RemediationCandidate mandatory = candidate("mandatory", 10, CompatibilityStatus.UNKNOWN);
        RemediationCandidate optional = candidate("optional", 8, CompatibilityStatus.COMPATIBLE);

        RemediationPlan plan = new Z3RemediationAdapter(1, CVSS_ONLY).optimize(List.of(mandatory, optional));

        assertEquals(OptimisationStatus.INFEASIBLE, plan.optimisationStatus());
        assertEquals(Set.of(), upgradedArtifacts(plan));
        assertEquals(1.8, plan.totalResidualRisk(), DELTA);
    }

    @Test
    void shouldUseFallbackForNativeSolverLinkageFailure() {
        RemediationCandidate optional = candidate("optional", 8, CompatibilityStatus.COMPATIBLE);
        Z3RemediationAdapter adapter = new Z3RemediationAdapter(1, CVSS_ONLY, () -> {
            throw new UnsatisfiedLinkError("Native Z3 library unavailable");
        });

        RemediationPlan plan = adapter.optimize(List.of(optional));

        assertEquals(OptimisationStatus.GREEDY_FALLBACK, plan.optimisationStatus());
        assertEquals(Set.of(optional.artifact()), upgradedArtifacts(plan));
        assertEquals(1, plan.totalEffortCost(), DELTA);
    }

    private static Z3RemediationAdapter failingSolver(double budget) {
        return new Z3RemediationAdapter(budget, CVSS_ONLY, () -> {
            throw new IllegalStateException("Z3 context unavailable");
        });
    }

    private static Set<Artifact> upgradedArtifacts(RemediationPlan plan) {
        return plan.upgradeRecommendations().stream()
                .map(decision -> decision.artifact()).collect(Collectors.toSet());
    }

    private static RemediationCandidate candidate(String name, double cvss, CompatibilityStatus compatibility) {
        return candidate(name, cvss, ReachabilityStatus.REACHABLE_CONFIRMED, compatibility, Optional.of("2.0.0"));
    }

    private static RemediationCandidate candidate(String name, double cvss, ReachabilityStatus reachability,
            CompatibilityStatus compatibility, Optional<String> fixVersion) {
        Artifact artifact = Artifact.create("org.example", name, "1.0.0", Scope.COMPILE);
        Artifact target = Artifact.create("org.example", name, "2.0.0", Scope.COMPILE);
        Vulnerability vulnerability = vulnerability("CVE-2026-0001", cvss, 0);
        return RemediationCandidate.withoutStability(
                artifact,
                List.of(vulnerability),
                List.of(new VulnerabilityReachability(vulnerability, reachability, Set.of(), Set.of())),
                Optional.of(new CompatibilityReport(artifact, target, compatibility, List.of())),
                fixVersion,
                Optional.empty());
    }
}
