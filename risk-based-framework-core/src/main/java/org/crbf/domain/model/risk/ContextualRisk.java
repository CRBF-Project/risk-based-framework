package org.crbf.domain.model.risk;

import java.util.Optional;

import org.crbf.domain.model.optimisation.RiskWeights;
import org.crbf.domain.model.reachability.ReachabilityStatus;

/**
 * The contextual risk of a single vulnerability, together with every factor
 * that produced it.
 *
 * <p>The score alone cannot be checked by the developer who receives it. This
 * record therefore carries the observed signals, the weights actually applied
 * and the attenuation factors, so that {@code value()} can be recomputed from
 * the data published alongside it.
 *
 * <p>The effective weights are not always the configured ones: when EPSS is
 * unavailable its weight is redistributed over the remaining signals, so
 * reporting the configured 0.50/0.30/0.20 would describe a calculation that
 * did not happen. {@link #of} is the only construction path, which keeps the
 * stored results and the factors that explain them in agreement.
 */
public record ContextualRisk(
        double cvssNormalized,
        Optional<Double> epss,
        double stalenessUrgency,
        double effectiveCvssWeight,
        double effectiveEpssWeight,
        double effectiveStalenessWeight,
        double baseRisk,
        ReachabilityStatus reachabilityStatus,
        double reachabilityFactor,
        double pathQualityFactor,
        double value) {

    private static final double COHERENCE_TOLERANCE = 1e-9;

    public ContextualRisk {
        epss = epss == null ? Optional.empty() : epss;

        if (reachabilityStatus == null) {
            throw new IllegalArgumentException("ReachabilityStatus cannot be null.");
        }

        double expectedBaseRisk = weightedSum(
                cvssNormalized, epss, stalenessUrgency,
                effectiveCvssWeight, effectiveEpssWeight, effectiveStalenessWeight);

        if (Math.abs(baseRisk - expectedBaseRisk) > COHERENCE_TOLERANCE) {
            throw new IllegalArgumentException(
                    "baseRisk does not follow from the factors it is reported with: "
                            + baseRisk + " vs " + expectedBaseRisk);
        }

        double expectedValue = baseRisk * reachabilityFactor * pathQualityFactor;

        if (Math.abs(value - expectedValue) > COHERENCE_TOLERANCE) {
            throw new IllegalArgumentException(
                    "Contextual risk does not follow from the factors it is reported with: "
                            + value + " vs " + expectedValue);
        }
    }

    /**
     * Derives the effective weights and the resulting scores from the observed
     * signals.
     *
     * @param epss the measured exploit prediction score, or
     *             {@code Optional.empty()} when no EPSS entry exists for the
     *             vulnerability.
     */
    public static ContextualRisk of(
            double cvssNormalized,
            Optional<Double> epss,
            double stalenessUrgency,
            RiskWeights weights,
            ReachabilityStatus reachabilityStatus,
            double reachabilityFactor,
            double pathQualityFactor) {

        Optional<Double> measuredEpss = epss == null ? Optional.empty() : epss;

        double effectiveCvssWeight;
        double effectiveEpssWeight;
        double effectiveStalenessWeight;

        if (measuredEpss.isPresent()) {
            effectiveCvssWeight = weights.cvssWeight();
            effectiveEpssWeight = weights.epssWeight();
            effectiveStalenessWeight = weights.stalenessWeight();
        } else {
            double availableWeight = weights.cvssWeight() + weights.stalenessWeight();

            if (availableWeight == 0.0) {
                throw new IllegalStateException(
                        "Cannot calculate base risk without EPSS when "
                                + "CVSS and staleness weights are both zero.");
            }

            effectiveCvssWeight = weights.cvssWeight() / availableWeight;
            effectiveEpssWeight = 0.0;
            effectiveStalenessWeight = weights.stalenessWeight() / availableWeight;
        }

        double baseRisk = weightedSum(
                cvssNormalized, measuredEpss, stalenessUrgency,
                effectiveCvssWeight, effectiveEpssWeight, effectiveStalenessWeight);

        return new ContextualRisk(
                cvssNormalized,
                measuredEpss,
                stalenessUrgency,
                effectiveCvssWeight,
                effectiveEpssWeight,
                effectiveStalenessWeight,
                baseRisk,
                reachabilityStatus,
                reachabilityFactor,
                pathQualityFactor,
                baseRisk * reachabilityFactor * pathQualityFactor);
    }

    private static double weightedSum(
            double cvssNormalized,
            Optional<Double> epss,
            double stalenessUrgency,
            double cvssWeight,
            double epssWeight,
            double stalenessWeight) {

        return (cvssNormalized * cvssWeight)
                + (epss.orElse(0.0) * epssWeight)
                + (stalenessUrgency * stalenessWeight);
    }
}
