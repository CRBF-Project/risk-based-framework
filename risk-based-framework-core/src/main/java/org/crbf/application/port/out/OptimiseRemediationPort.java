package org.crbf.application.port.out;

import org.crbf.domain.model.optimisation.RemediationCandidate;
import org.crbf.domain.model.optimisation.RemediationPlan;

import java.util.List;

/**
 * Output port for the remediation optimisation step.
 *
 * Given the set of vulnerable artifacts with their contextual risk scores
 * and upgrade effort costs, this port computes the optimal subset of
 * artifacts to upgrade within the configured effort budget — maximising
 * total risk reduction while respecting the budget capacity constraint.
 *
 * The primary implementation uses the Z3 SMT solver (Bounded Knapsack).
 */
public interface OptimiseRemediationPort {
    RemediationPlan optimize(List<RemediationCandidate> candidates);
}