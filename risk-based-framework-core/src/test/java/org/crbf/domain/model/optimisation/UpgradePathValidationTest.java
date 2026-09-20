package org.crbf.domain.model.optimisation;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Optional;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.Scope;
import org.junit.jupiter.api.Test;

class UpgradePathValidationTest {

    private static final Artifact ARTIFACT = Artifact.create(
            "org.example",
            "library",
            "1.0.0",
            Scope.COMPILE);

    @Test
    void shouldRejectSecuritySignalWhenUpgradePathStatusIsUnknown() {
        double validSecuritySignal = 0.5;

        assertThrows(
                IllegalArgumentException.class,
                () -> validation(
                        Optional.of(validSecuritySignal),
                        UpgradePathStatus.UNKNOWN));
    }

    @Test
    void shouldRejectMissingSecuritySignalWhenUpgradePathStatusIsKnown() {
        Optional<Double> securitySignal = Optional.empty();

        assertThrows(
                IllegalArgumentException.class,
                () -> validation(
                        securitySignal,
                        UpgradePathStatus.CLEAN));
    }

    @Test
    void shouldRejectSecuritySignalAboveUpperBound() {
        double outOfRangeSecuritySignal = 1.1;

        assertThrows(
                IllegalArgumentException.class,
                () -> validation(
                        Optional.of(outOfRangeSecuritySignal),
                        UpgradePathStatus.CLEAN));
    }

    @Test
    void shouldRejectSecuritySignalBelowLowerBound() {
        double belowLowerBoundSignal = -1.1;

        assertThrows(
                IllegalArgumentException.class,
                () -> validation(
                        Optional.of(belowLowerBoundSignal),
                        UpgradePathStatus.CLEAN));
    }

    private UpgradePathValidation validation(
            Optional<Double> securitySignal,
            UpgradePathStatus status) {

        return new UpgradePathValidation(
                ARTIFACT,
                "2.0.0",
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                Optional.empty(),
                securitySignal,
                status,
                Optional.empty());
    }
}