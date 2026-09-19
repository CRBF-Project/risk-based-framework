package org.crbf.domain.model.stability;

import java.time.Instant;

public record EcosystemStability(
                String latestVersion,
                ToodDays tood,
                VersionLag versionLag,
                AdoptionRate adoptionRate,
                AdoptionLifespan adoptionLifespan,
                MaintenanceRate maintenanceRate,
                Instant releasedAt) {
        public static EcosystemStability create(
                        String latestVersion,
                        int toodDays,
                        int versionLag,
                        double adoptionRate,
                        double adoptionLifespan,
                        double maintenanceRate,
                        long releaseTimestampMs) {

                return new EcosystemStability(
                                latestVersion,
                                new ToodDays(toodDays),
                                new VersionLag(versionLag),
                                new AdoptionRate(adoptionRate),
                                new AdoptionLifespan(adoptionLifespan),
                                new MaintenanceRate(maintenanceRate),
                                releaseTimestampMs > 0
                                                ? Instant.ofEpochMilli(releaseTimestampMs)
                                                : Instant.EPOCH);
        }

}
