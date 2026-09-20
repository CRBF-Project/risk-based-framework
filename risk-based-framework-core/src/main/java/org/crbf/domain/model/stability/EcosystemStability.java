package org.crbf.domain.model.stability;

import java.time.Instant;
import java.util.Optional;

/**
 * Ecosystem metrics for a single artifact version.
 *
 * <p>The adoption and maintenance signals are optional because the ecosystem
 * data source does not report them for every artifact. An absent signal is kept
 * distinct from a measured zero: "no dependent has adopted this version" is
 * evidence, whereas "the data source reported nothing" is not.
 */
public record EcosystemStability(
                String latestVersion,
                ToodDays tood,
                VersionLag versionLag,
                Optional<AdoptionRate> adoptionRate,
                Optional<AdoptionLifespan> adoptionLifespan,
                Optional<MaintenanceRate> maintenanceRate,
                Instant releasedAt) {

        /**
         * @param adoptionRate     the measured adoption rate, or {@code null} when
         *                         the data source reported none.
         * @param adoptionLifespan the measured adoption lifespan in days, or
         *                         {@code null} when the data source reported none.
         * @param maintenanceRate  the measured release frequency, or {@code null}
         *                         when the data source reported none.
         */
        public static EcosystemStability create(
                        String latestVersion,
                        int toodDays,
                        int versionLag,
                        Double adoptionRate,
                        Double adoptionLifespan,
                        Double maintenanceRate,
                        long releaseTimestampMs) {

                return new EcosystemStability(
                                latestVersion,
                                new ToodDays(toodDays),
                                new VersionLag(versionLag),
                                Optional.ofNullable(adoptionRate).map(AdoptionRate::new),
                                Optional.ofNullable(adoptionLifespan).map(AdoptionLifespan::new),
                                Optional.ofNullable(maintenanceRate).map(MaintenanceRate::new),
                                releaseTimestampMs > 0
                                                ? Instant.ofEpochMilli(releaseTimestampMs)
                                                : Instant.EPOCH);
        }

}
