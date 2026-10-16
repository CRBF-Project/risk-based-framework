package org.crbf.domain.model.optimisation;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class InfeasibilityDetailsTest {

    @Test
    void shouldNotAttributeGeneralConstraintInfeasibilityToBudget() {
        InfeasibilityDetails details = InfeasibilityDetails.of(
                InfeasibilityDetails.Reason.UNSATISFIABLE_CONSTRAINTS, 3,
                List.of(new InfeasibilityDetails.MandatoryUpgrade("org.example:library:1.0.0", "2.0.0", 2)));

        assertEquals(Optional.empty(), details.budgetShortfall());
    }
}
