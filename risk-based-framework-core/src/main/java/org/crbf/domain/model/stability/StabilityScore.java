package org.crbf.domain.model.stability;

import java.util.Optional;

/**
 * A normalised [0.0 – 1.0] score that represents the "upgrade stability
 * confidence" for a candidate fix version
 *
 * A score of {@code 1.0} represents maximum confidence (fully adopted,
 * actively maintained). A score of {@code 0.0} represents zero confidence
 * (no ecosystem adoption).
 */
public record StabilityScore(double value) {

    /** Average releases/day considered "actively maintained". */
    private static final double ACTIVE_MAINTENANCE_THRESHOLD = 0.10;

    /**
     * Adoption lifespan at which confidence saturates (2 years).
     */
    private static final double TARGET_ADOPTION_LIFESPAN_DAYS = 730.0;

    /** TOOD threshold (days) at which urgency reaches 1.0. */
    private static final double MAX_URGENCY_TOOD_DAYS = 365.0;

    /** VersionLag at which urgency saturates. */
    private static final double MAX_URGENCY_VERSION_LAG = 10.0;

    public StabilityScore {
        if (value < 0.0 || value > 1.0) {
            throw new IllegalArgumentException(
                    "StabilityScore must be in [0.0, 1.0]. Received: " + value);
        }
    }

    /**
     * Computes the stability confidence for a candidate fix version.
     *
     * <p>The score is only defined when every component was actually measured.
     * A missing component is not read as zero confidence, because the score
     * would then report an unreachable data source as an unadopted release.
     *
     * @param fixVersionStability Goblin metrics for the proposed fix version.
     * @return Normalised stability confidence in [0.0, 1.0], or
     *         {@link Optional#empty()} when any component is unavailable.
     */
    public static Optional<StabilityScore> ofFixVersion(EcosystemStability fixVersionStability) {
        Optional<AdoptionRate> adoption = fixVersionStability.adoptionRate();
        Optional<MaintenanceRate> maintenance = fixVersionStability.maintenanceRate();
        Optional<AdoptionLifespan> lifespan = fixVersionStability.adoptionLifespan();

        if (adoption.isEmpty() || maintenance.isEmpty() || lifespan.isEmpty()) {
            return Optional.empty();
        }

        double adoptionRate = adoption.get().value();

        double maintenanceNorm = Math.min(
                maintenance.get().value() / ACTIVE_MAINTENANCE_THRESHOLD,
                1.0);

        double lifespanNorm = Math.min(
                lifespan.get().days() / TARGET_ADOPTION_LIFESPAN_DAYS,
                1.0);

        double score = adoptionRate * 0.55
                + maintenanceNorm * 0.30
                + lifespanNorm * 0.15;

        return Optional.of(new StabilityScore(Math.max(0.0, Math.min(score, 1.0))));
    }

    /**
     * A midpoint fallback (0.5) used when ecosystem stability data is
     * unavailable. It is not an observed measurement and must not be reported
     * as one.
     */
    public static StabilityScore unknown() {
        return new StabilityScore(0.5);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Derived signals
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Computes the "staleness urgency" of the CURRENT artifact version.
     * 
     * @param currentVersionStability Goblin metrics for the artifact version
     *                                currently used by the project.
     * @return Urgency factor in [0.0, 1.0].
     */
    public static double stalenessUrgencyOf(EcosystemStability currentVersionStability) {
        double timeLagNorm = Math.min(
                currentVersionStability.tood().value()
                        / MAX_URGENCY_TOOD_DAYS,
                1.0);

        double versionLagNorm = Math.min(
                currentVersionStability.versionLag().value()
                        / MAX_URGENCY_VERSION_LAG,
                1.0);

        return timeLagNorm * 0.60
                + versionLagNorm * 0.40;
    }

}
