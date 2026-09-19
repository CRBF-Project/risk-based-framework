package org.crbf.domain.model.optimisation;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class RiskWeightsTest {

    @Test
    void shouldAcceptValidRiskWeights() {
        double cvssWeight = 0.50;
        double epssWeight = 0.30;
        double stalenessWeight = 0.20;

        double reachableWeight = 1.00;
        double unknownWeight = 0.50;
        double unreachableWeight = 0.10;

        assertDoesNotThrow(() -> new RiskWeights(
                cvssWeight,
                epssWeight,
                stalenessWeight,
                reachableWeight,
                unknownWeight,
                unreachableWeight));
    }

    @Test
    void shouldRejectBaseRiskWeightsThatDoNotSumToOne() {
        double cvssWeight = 0.50;
        double epssWeight = 0.30;
        double stalenessWeight = 0.30;

        assertThrows(
                IllegalArgumentException.class,
                () -> new RiskWeights(
                        cvssWeight,
                        epssWeight,
                        stalenessWeight,
                        1.00,
                        0.50,
                        0.10));
    }

    @Test
    void shouldRejectReachabilityWeightAboveOne() {
        double invalidReachableWeight = 1.10;

        assertThrows(
                IllegalArgumentException.class,
                () -> new RiskWeights(
                        0.50,
                        0.30,
                        0.20,
                        invalidReachableWeight,
                        0.50,
                        0.10));
    }

    @Test
    void shouldRejectNegativeReachabilityWeight() {
        double invalidUnreachableWeight = -0.10;

        assertThrows(
                IllegalArgumentException.class,
                () -> new RiskWeights(
                        0.50,
                        0.30,
                        0.20,
                        1.00,
                        0.50,
                        invalidUnreachableWeight));
    }

    @Test
    void shouldRejectUnknownWeightGreaterThanReachableWeight() {
        double reachableWeight = 0.50;
        double invalidUnknownWeight = 0.60;

        assertThrows(
                IllegalArgumentException.class,
                () -> new RiskWeights(
                        0.50,
                        0.30,
                        0.20,
                        reachableWeight,
                        invalidUnknownWeight,
                        0.10));
    }

    @Test
    void shouldRejectUnreachableWeightGreaterThanUnknownWeight() {
        double unknownWeight = 0.30;
        double invalidUnreachableWeight = 0.40;

        assertThrows(
                IllegalArgumentException.class,
                () -> new RiskWeights(
                        0.50,
                        0.30,
                        0.20,
                        1.00,
                        unknownWeight,
                        invalidUnreachableWeight));
    }
}