package org.crbf.domain.model.optimisation;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * Represents the complete output of the Z3 optimisation step.
 *
 * Contains the full list of per-artifact decisions, aggregate metrics, and an
 * optimisation outcome. An infeasible result contains no upgrade recommendations;
 * its decisions retain all candidates as unmitigated risk, not a feasible plan.
 *
 * @param decisions  One {@link RemediationDecision} per vulnerable artifact.
 * @param totalPotentialRiskAddressed Sum of current risk scores potentially addressed by recommended upgrades; not verified reduction.
 * @param totalUnselectedRisk Sum of current risk scores of unselected dependencies; not post-update residual risk.
 * @param totalEffortCost Total effort units consumed by all recommended upgrades.
 * @param optimisationStatus Whether optimisation succeeded, was infeasible, or used a technical fallback.
 * @param availableEffortBudget Configured effort limit, absent for legacy plan producers.
 */
public record RemediationPlan(
        List<RemediationDecision> decisions,
        double totalPotentialRiskAddressed,
        double totalUnselectedRisk,
        double totalEffortCost,
        OptimisationStatus optimisationStatus,
        GlobalGraphValidation globalGraphValidation,
        Optional<InfeasibilityDetails> infeasibility,
        Optional<Double> availableEffortBudget
) {
    public RemediationPlan {
        decisions = decisions == null ? List.of() : List.copyOf(decisions);
    }

    /** Compatibility constructor for producers that do not report a budget. */
    public RemediationPlan(List<RemediationDecision> decisions, double totalPotentialRiskAddressed,
            double totalUnselectedRisk, double totalEffortCost, OptimisationStatus optimisationStatus,
            GlobalGraphValidation globalGraphValidation, Optional<InfeasibilityDetails> infeasibility) {
        this(decisions, totalPotentialRiskAddressed, totalUnselectedRisk, totalEffortCost,
                optimisationStatus, globalGraphValidation, infeasibility, Optional.empty());
    }

    public RemediationPlan withEffortBudget(double budget) {
        return new RemediationPlan(decisions, totalPotentialRiskAddressed, totalUnselectedRisk, totalEffortCost,
                optimisationStatus, globalGraphValidation, infeasibility, Optional.of(budget));
    }

    public RemediationPlan(List<RemediationDecision> decisions, double totalPotentialRiskAddressed,
            double totalUnselectedRisk, double totalEffortCost, OptimisationStatus optimisationStatus,
            GlobalGraphValidation globalGraphValidation) {
        this(decisions, totalPotentialRiskAddressed, totalUnselectedRisk, totalEffortCost,
                optimisationStatus, globalGraphValidation, Optional.empty());
    }

    public RemediationPlan(List<RemediationDecision> decisions, double totalPotentialRiskAddressed,
            double totalUnselectedRisk, double totalEffortCost, boolean solvedByZ3,
            GlobalGraphValidation globalGraphValidation) {
        this(decisions, totalPotentialRiskAddressed, totalUnselectedRisk, totalEffortCost,
                solvedByZ3 ? OptimisationStatus.OPTIMAL : OptimisationStatus.GREEDY_FALLBACK,
                globalGraphValidation);
    }

    public boolean solvedByZ3() {
        return optimisationStatus == OptimisationStatus.OPTIMAL;
    }

    public static RemediationPlan empty() {
        return new RemediationPlan(List.of(), 0.0, 0.0, 0.0, OptimisationStatus.NOT_RUN, GlobalGraphValidation.notRun());
    }

    public RemediationPlan withGlobalValidation(GlobalGraphValidation validation) {
        return new RemediationPlan(
                decisions,
                totalPotentialRiskAddressed,
                totalUnselectedRisk,
                totalEffortCost,
                optimisationStatus,
                validation,
                infeasibility,
                availableEffortBudget);
    }

    public List<RemediationDecision> upgradeRecommendations() {
        return decisions.stream()
                .filter(RemediationDecision::shouldUpgrade)
                .sorted(Comparator.comparingDouble(RemediationDecision::potentialRiskAddressed).reversed())
                .toList();
    }

    public List<RemediationDecision> deferredDecisions() {
        return decisions.stream()
                .filter(d -> !d.shouldUpgrade())
                .toList();
    }
}