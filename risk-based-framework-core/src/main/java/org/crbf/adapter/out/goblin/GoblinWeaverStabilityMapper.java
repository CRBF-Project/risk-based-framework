package org.crbf.adapter.out.goblin;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.stability.EcosystemStability;

import java.util.Comparator;

/**
 * Maps Goblin Weaver API responses to the domain object
 * {@link EcosystemStability}.
 */
class GoblinWeaverStabilityMapper {

    private static final long MS_PER_DAY = 86_400_000L;

    EcosystemStability toDomain(
            GoblinWeaverReleaseResponse releaseResponse,
            GoblinWeaverArtifactResponse artifactResponse,
            GoblinWeaverReleaseResponse newVersionsResponse,
            Artifact artifact) {

        int versionLag = 0;
        int toodDays = 0;
        double adoptionRate = 0.0;
        double adoptionLifespan = 0.0;
        long releaseTimestamp = 0L;

        if (releaseResponse != null
                && releaseResponse.nodes() != null
                && !releaseResponse.nodes().isEmpty()) {

            GoblinWeaverReleaseResponse.GoblinNodeDto node = releaseResponse.nodes().get(0);

            if (node.freshness() != null) {
                versionLag = parseIntSafe(node.freshness().numberMissedRelease());
                long outdatedMs = parseLongSafe(node.freshness().outdatedTimeInMs());
                if (outdatedMs > 0) {
                    toodDays = (int) (outdatedMs / MS_PER_DAY);
                }
            }

            adoptionRate = resolveAdoptionRate(node);
            adoptionLifespan = node.adoptionLifespan() != null && node.adoptionLifespan() >= 0
                    ? node.adoptionLifespan()
                    : 0.0;
            releaseTimestamp = node.timestamp() != null ? node.timestamp() : 0L;
        }

        double maintenanceRate = 0.0;
        if (artifactResponse != null && artifactResponse.nodes() != null) {
            maintenanceRate = artifactResponse.nodes().stream()
                    .map(GoblinWeaverArtifactResponse.GoblinArtifactNodeDto::speed)
                    .filter(s -> s != null && s >= 0)
                    .findFirst()
                    .orElse(0.0);
        }

        String latestVersion = resolveLatestVersionFromNewVersions(newVersionsResponse, artifact.version().value());

        return EcosystemStability.create(latestVersion, toodDays, versionLag,
                adoptionRate, adoptionLifespan, maintenanceRate, releaseTimestamp);
    }

    private double resolveAdoptionRate(GoblinWeaverReleaseResponse.GoblinNodeDto node) {
        if (node.adoptionRate() != null && node.adoptionRate() >= 0.0) {
            return node.adoptionRate();
        }
        // Fallback: relative popularity within the same artifact's history is not
        // available here (single-node response), so return 0.0
        return 0.0;
    }

    private String resolveLatestVersionFromNewVersions(
            GoblinWeaverReleaseResponse newVersionsResponse,
            String fallback) {

        if (newVersionsResponse == null || newVersionsResponse.nodes() == null) {
            return fallback;
        }
        return newVersionsResponse.nodes().stream()
                .filter(n -> n.timestamp() != null && n.version() != null && !n.version().isBlank())
                .max(Comparator.comparingLong(GoblinWeaverReleaseResponse.GoblinNodeDto::timestamp))
                .map(GoblinWeaverReleaseResponse.GoblinNodeDto::version)
                .orElse(fallback);
    }

    private int parseIntSafe(String value) {
        if (value == null)
            return 0;
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private long parseLongSafe(String value) {
        if (value == null)
            return 0L;
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            return 0L;
        }
    }
}
