package org.crbf.domain.model.stability;

public record AdoptionRate(double value) {
    public AdoptionRate {
        if (value < 0.0 || value > 1.0) {
            throw new IllegalArgumentException(
                "The Adoption Rate must be between 0.0 and 1.0. Received value: " + value
            );
        }
    }
}