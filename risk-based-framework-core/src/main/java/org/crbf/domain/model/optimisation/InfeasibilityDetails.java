package org.crbf.domain.model.optimisation;

import java.util.List;
import java.util.Optional;

public record InfeasibilityDetails(
        Reason reason,
        double availableEffortBudget,
        double requiredMandatoryEffort,
        Optional<Double> budgetShortfall,
        List<MandatoryUpgrade> mandatoryUpgrades) {

    public InfeasibilityDetails {
        mandatoryUpgrades = List.copyOf(mandatoryUpgrades);
    }

    public enum Reason {
        MANDATORY_EFFORT_EXCEEDS_BUDGET,
        UNSATISFIABLE_CONSTRAINTS
    }

    public record MandatoryUpgrade(String artifact, String targetVersion, double effortCost) {}

    public static InfeasibilityDetails of(Reason reason, double budget, List<MandatoryUpgrade> pending) {
        double required = pending.stream().mapToDouble(MandatoryUpgrade::effortCost).sum();
        Optional<Double> shortfall = reason == Reason.MANDATORY_EFFORT_EXCEEDS_BUDGET && required > budget
                ? Optional.of(required - budget) : Optional.empty();
        return new InfeasibilityDetails(reason, budget, required, shortfall, pending);
    }
}
