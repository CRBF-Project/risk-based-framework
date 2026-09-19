package org.crbf.domain.model.optimisation;

/**
 * Configurable weights for the contextual risk score.
 *
 * <p>CVSS, EPSS and staleness weights must be non-negative and sum to 1.0.
 * Reachability weights are independent attenuation factors in [0.0, 1.0] and
 * must satisfy reachable >= unknown >= unreachable.
 */
public record RiskWeights(
        double cvssWeight,
        double epssWeight,
        double stalenessWeight,
        double reachableWeight,
        double unknownWeight,
        double unreachableWeight) {
    
            // Default signal weights: CVSS dominates, EPSS refines, staleness adds urgency context.
    private static final double DEFAULT_CVSS_WEIGHT = 0.50;
    private static final double DEFAULT_EPSS_WEIGHT = 0.30;
    private static final double DEFAULT_STALENESS_WEIGHT = 0.20;

    // Default reachability multipliers.
    private static final double DEFAULT_REACHABLE_WEIGHT = 1.00;
    private static final double DEFAULT_UNKNOWN_WEIGHT = 0.50;
    private static final double DEFAULT_UNREACHABLE_WEIGHT = 0.10;

    private static final double WEIGHT_SUM_TOLERANCE = 1e-9;

    public RiskWeights {
        if (cvssWeight < 0.0 || epssWeight < 0.0 || stalenessWeight < 0.0)
            throw new IllegalArgumentException("Risk weights (CVSS, EPSS, staleness) must be non-negative.");

        double totalWeight = cvssWeight + epssWeight + stalenessWeight;

        if (Math.abs(totalWeight - 1.0) > WEIGHT_SUM_TOLERANCE) {
            throw new IllegalArgumentException("CVSS, EPSS and staleness weights must sum to 1.0. Got: "
                    + String.format("%.6f + %.6f + %.6f = %.6f",
                            cvssWeight,
                            epssWeight,
                            stalenessWeight,
                            totalWeight));
        }

        if (reachableWeight < 0.0 || reachableWeight > 1.0
                || unknownWeight < 0.0 || unknownWeight > 1.0
                || unreachableWeight < 0.0 || unreachableWeight > 1.0) {
            throw new IllegalArgumentException("Reachability weights must be in [0.0, 1.0].");
        }

        if (reachableWeight < unknownWeight || unknownWeight < unreachableWeight)
            throw new IllegalArgumentException("Reachability weights must satisfy reachable >= unknown >= unreachable.");
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
