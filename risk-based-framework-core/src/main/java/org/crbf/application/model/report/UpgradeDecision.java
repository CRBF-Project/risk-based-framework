package org.crbf.application.model.report;

public enum UpgradeDecision {
    MANDATORY, RECOMMENDED,
    MANDATORY_PENDING, OPTIONAL_NOT_SELECTED, NO_FIX_AVAILABLE,

    /**
     * No fix exists under this artifact's own Maven coordinate, but one does
     * exist under a different, renamed/forked coordinate (see
     * {@link org.crbf.domain.model.vulnerability.AlternativeFix}). Requires
     * manual migration — never resolved automatically by the optimiser.
     */
    MIGRATION_AVAILABLE,

    DEFER
}
