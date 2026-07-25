package org.crbf.domain.model.stability;

public record AdoptionLifespan(double days) {
    public double value() {
        return days;
    }
}