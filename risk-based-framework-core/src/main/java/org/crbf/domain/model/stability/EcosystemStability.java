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

        /**
         * Returns an EcosystemStability representing an artifact for which
         * Goblin has no data (e.g. very recent or private artifact).
         */
        public static EcosystemStability unknown(String version) {
                return new EcosystemStability(
                                version,
                                new ToodDays(0),
                                new VersionLag(0),
                                new AdoptionRate(0.0),
                                new AdoptionLifespan(0.0),
                                new MaintenanceRate(0.0),
                                Instant.EPOCH);
        }
}
