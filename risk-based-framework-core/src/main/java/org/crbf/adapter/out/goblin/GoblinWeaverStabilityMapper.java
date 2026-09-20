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
        Double adoptionRate = null;
        Double adoptionLifespan = null;
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
                    : null;
            releaseTimestamp = node.timestamp() != null ? node.timestamp() : 0L;
        }

        Double maintenanceRate = null;
        if (artifactResponse != null && artifactResponse.nodes() != null) {
            maintenanceRate = artifactResponse.nodes().stream()
                    .map(GoblinWeaverArtifactResponse.GoblinArtifactNodeDto::speed)
                    .filter(s -> s != null && s >= 0)
                    .findFirst()
                    .orElse(null);
        }

        String latestVersion = resolveLatestVersionFromNewVersions(newVersionsResponse, artifact.version().value());

        return EcosystemStability.create(latestVersion, toodDays, versionLag,
                adoptionRate, adoptionLifespan, maintenanceRate, releaseTimestamp);
    }

    private Double resolveAdoptionRate(GoblinWeaverReleaseResponse.GoblinNodeDto node) {
        if (node.adoptionRate() != null && node.adoptionRate() >= 0.0) {
            return node.adoptionRate();
        }
        // No adoption figure was reported. Returning 0.0 here would be read
        // downstream as "no dependent adopted this release", which is a claim
        // the response does not make.
        return null;
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
