package org.crbf.domain.model.reachability;

/**
 * Represents the outcome of a Static Reachability Analysis (SRA) for a
 * given vulnerability within a specific project.
 *
 * REACHABLE_CONFIRMED;
 * REACHABLE_PROBABLE;
 * UNREACHABLE;
 * UNKNOWN;
 */
public enum ReachabilityStatus {
    UNREACHABLE(0),
    UNKNOWN(1),
    REACHABLE_PROBABLE(2),
    REACHABLE_CONFIRMED(3);

    private final int severity;

    ReachabilityStatus(int severity) {
        this.severity = severity;
    }

    public int severity() {
        return severity;
    }

    public boolean isReachable() {
        return this == REACHABLE_CONFIRMED || this == REACHABLE_PROBABLE;
    }
}
 