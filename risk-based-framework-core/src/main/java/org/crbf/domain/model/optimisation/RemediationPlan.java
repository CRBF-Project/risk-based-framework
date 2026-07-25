package org.crbf.domain.model.optimisation;

import java.util.Comparator;
import java.util.List;

/**
 * Represents the complete output of the Z3 optimisation step.
 *
 * Contains the full list of per-artifact decisions, aggregate metrics, and a
 * flag indicating whether the plan was produced by the Z3 solver ({@code true})
 * or by the greedy fallback ({@code false}).
 *
 * @param decisions  One {@link RemediationDecision} per vulnerable artifact.
 * @param totalRiskReduction Sum of risk scores eliminated by all recommended upgrades.
 * @param totalResidualRisk Sum of risk scores that remain after applying the plan.
 * @param totalEffortCost Total effort units consumed by all recommended upgrades.
 * @param solvedByZ3 {@code true} if produced by Z3; {@code false} for the greedy fallback.
 */
public record RemediationPlan(
        List<RemediationDecision> decisions,
        double totalRiskReduction,
        double totalResidualRisk,
        double totalEffortCost,
        boolean solvedByZ3,
        GlobalGraphValidation globalGraphValidation
) {
    public RemediationPlan {
        decisions = decisions == null ? List.of() : List.copyOf(decisions);
    }

    public static RemediationPlan empty() {
        return new RemediationPlan(List.of(), 0.0, 0.0, 0.0, false, GlobalGraphValidation.notRun());
    }

    public RemediationPlan withGlobalValidation(GlobalGraphValidation validation) {
        return new RemediationPlan(
                decisions,
                totalRiskReduction,
                totalResidualRisk,
                totalEffortCost,
                solvedByZ3,
                validation);
    }

    public List<RemediationDecision> upgradeRecommendations() {
        return decisions.stream()
                .filter(RemediationDecision::shouldUpgrade)
                .sorted(Comparator.comparingDouble(RemediationDecision::riskReduction).reversed())
                .toList();
    }

    public List<RemediationDecision> deferredDecisions() {
        return decisions.stream()
                .filter(d -> !d.shouldUpgrade())
                .toList();
    }
}