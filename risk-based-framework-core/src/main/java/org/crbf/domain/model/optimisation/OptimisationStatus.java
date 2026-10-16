package org.crbf.domain.model.optimisation;

/** Distinguishes a proven optimum, infeasibility, and a technical solver fallback. */
public enum OptimisationStatus {
    NOT_RUN,
    OPTIMAL,
    INFEASIBLE,
    GREEDY_FALLBACK
}
