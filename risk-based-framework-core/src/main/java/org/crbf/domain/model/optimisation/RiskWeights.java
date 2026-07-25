package org.crbf.domain.model.optimisation;

/**
 * Configurable weights for the contextual risk score.
 *
 * <p>cvssWeight + epssWeight + stalenessWeight must sum to 1.00 (max 2 decimal places).
 * Reachability weights are independent multipliers and have no sum constraint.
 */
public record RiskWeights(
        double cvssWeight,
        double epssWeight,
        double stalenessWeight,
        double reachableWeight,
        double unknownWeight,
        double unreachableWeight
) {
    // Default signal weights: CVSS dominates, EPSS refines, staleness adds urgency context.
    private static final double DEFAULT_CVSS_WEIGHT = 0.50;
    private static final double DEFAULT_EPSS_WEIGHT = 0.30;
    private static final double DEFAULT_STALENESS_WEIGHT = 0.20;

    // Default reachability multipliers.
    private static final double DEFAULT_REACHABLE_WEIGHT = 1.00;
    private static final double DEFAULT_UNKNOWN_WEIGHT = 0.50;
    private static final double DEFAULT_UNREACHABLE_WEIGHT = 0.10;

    public RiskWeights {
        if (cvssWeight < 0 || epssWeight < 0 || stalenessWeight < 0) {
            throw new IllegalArgumentException("Risk weights (cvss, epss, staleness) must be non-negative.");
        }
        long cvssH      = Math.round(cvssWeight * 100);
        long epssH      = Math.round(epssWeight * 100);
        long stalenessH = Math.round(stalenessWeight * 100);
        if (cvssH + epssH + stalenessH != 100) {
            throw new IllegalArgumentException(
                    "cvssWeight + epssWeight + stalenessWeight must sum to 1.00 (max 2 decimal places). Got: "
                            + String.format("%.2f + %.2f + %.2f = %.2f",
                                    cvssWeight, epssWeight, stalenessWeight,
                                    cvssWeight + epssWeight + stalenessWeight));
        }
        if (reachableWeight < 0 || unknownWeight < 0 || unreachableWeight < 0) {
            throw new IllegalArgumentException("Reachability weights must be non-negative.");
        }
    }

    public static RiskWeights defaults() {
        return new RiskWeights(
                DEFAULT_CVSS_WEIGHT,
                DEFAULT_EPSS_WEIGHT,
                DEFAULT_STALENESS_WEIGHT,
                DEFAULT_REACHABLE_WEIGHT,
                DEFAULT_UNKNOWN_WEIGHT,
                DEFAULT_UNREACHABLE_WEIGHT);
    }
}
