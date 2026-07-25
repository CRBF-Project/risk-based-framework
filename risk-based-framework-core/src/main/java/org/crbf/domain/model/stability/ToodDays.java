package org.crbf.domain.model.stability;

public record ToodDays(int value) {
    public ToodDays {
        if (value < 0) {
            throw new IllegalArgumentException(
                "The TOOD (Time-Out-Of-Date) cannot be negative. Received value: " + value
            );
        }
    }
}
