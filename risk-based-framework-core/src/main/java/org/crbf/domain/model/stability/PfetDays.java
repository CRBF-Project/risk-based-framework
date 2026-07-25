package org.crbf.domain.model.stability;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

public record PfetDays(int value) {

    public static PfetDays of(Instant releasedAt) {
        if (releasedAt == null || releasedAt.equals(Instant.EPOCH)) {
            return new PfetDays(0);
        }
        int days = (int) ChronoUnit.DAYS.between(releasedAt, Instant.now());
        return new PfetDays(Math.max(0, days));
    }

    public static PfetDays unknown() {
        return new PfetDays(0);
    }
}
