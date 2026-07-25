package org.crbf.domain.model.stability;

public record MaintenanceRate(double value) {
    public MaintenanceRate {
        if (value < 0.0) {
            throw new IllegalArgumentException("The Maintenance Rate (release frequency) cannot be negative.");
        }
    }
}
