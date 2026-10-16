package org.crbf.adapter.out.goblin;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.stability.EcosystemStability;

import java.util.Comparator;

/**
 * Maps Goblin Weaver API responses to the domain object
 * {@link EcosystemStability}. Freshness is required because its domain fields
 * cannot represent absence; missing values must not be mapped to measured zero.
 */
class GoblinWeaverStabilityMapper {

    private static final long MS_PER_DAY = 86_400_000L;

    EcosystemStability toDomain(
            GoblinWeaverReleaseResponse releaseResponse,
            GoblinWeaverArtifactResponse artifactResponse,
            GoblinWeaverReleaseResponse newVersionsResponse,
            Artifact artifact) {

        if (releaseResponse == null || releaseResponse.nodes() == null || releaseResponse.nodes().isEmpty()
                || releaseResponse.nodes().get(0) == null || releaseResponse.nodes().get(0).freshness() == null) {
            throw new IllegalArgumentException("Goblin freshness data is unavailable");
        }
        GoblinWeaverReleaseResponse.GoblinNodeDto node = releaseResponse.nodes().get(0);
        int versionLag = Integer.parseInt(node.freshness().numberMissedRelease());
        long outdatedMs = Long.parseLong(node.freshness().outdatedTimeInMs());
        if (versionLag < 0 || outdatedMs < 0) {
            throw new IllegalArgumentException("Goblin freshness values must be non-negative");
        }
        int toodDays = Math.toIntExact(outdatedMs / MS_PER_DAY);
        Double adoptionRate = resolveAdoptionRate(node);
        Double adoptionLifespan = node.adoptionLifespan() != null && node.adoptionLifespan() >= 0
                ? node.adoptionLifespan() : null;
        long releaseTimestamp = node.timestamp() != null ? node.timestamp() : 0L;

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

}
