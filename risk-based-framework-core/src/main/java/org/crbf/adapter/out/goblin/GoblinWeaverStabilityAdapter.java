package org.crbf.adapter.out.goblin;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.crbf.application.port.out.LoadStabilityMetricsPort;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.stability.EcosystemStability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Optional;

/**
 * Outbound adapter that retrieves ecosystem stability metrics from the
 * Goblin Weaver REST API (https://github.com/Goblin-Ecosystem/goblinWeaver).
 *
 * Orchestrates three API calls via GoblinWeaverClient:
 * POST /release — FRESHNESS (TOOD, VersionLag), ADOPTION_RATE,
 * ADOPTION_LIFESPAN
 * POST /artifact — SPEED (MaintenanceRate)
 * POST /release/newVersions — latest available version (max-timestamp node)
 *
 * All calls degrade gracefully: any failure defaults the missing metrics to
 * 0.0.
 */
public class GoblinWeaverStabilityAdapter implements LoadStabilityMetricsPort {

        private static final Logger LOG = LoggerFactory.getLogger(GoblinWeaverStabilityAdapter.class);

        private static final String DEFAULT_BASE_URL = "http://localhost:8080";

        private final GoblinWeaverClient client;
        private final GoblinWeaverStabilityMapper mapper;

        public GoblinWeaverStabilityAdapter() {
                this(DEFAULT_BASE_URL);
        }

        public GoblinWeaverStabilityAdapter(String baseUrl) {
                HttpClient httpClient = HttpClient.newBuilder()
                                .connectTimeout(Duration.ofSeconds(30))
                                .build();
                this.client = new GoblinWeaverClient(baseUrl, httpClient, new ObjectMapper());
                this.mapper = new GoblinWeaverStabilityMapper();
        }

        @Override
        public Optional<EcosystemStability> loadMetrics(Artifact artifact) {
                try {
                        GoblinWeaverReleaseResponse releaseResponse = client
                                        .fetchReleaseMetrics(
                                                        artifact.groupId().value(),
                                                        artifact.artifactId().value(),
                                                        artifact.version().value())
                                        .orElse(null);

                        if (releaseResponse == null) {
                                LOG.warn("No Goblin release data for {}; stability reported as unavailable",
                                                artifact.gav());
                                return Optional.empty();
                        }

                        GoblinWeaverArtifactResponse artifactResponse = client
                                        .fetchArtifactMetrics(artifact.groupId().value(), artifact.artifactId().value())
                                        .orElse(null);

                        GoblinWeaverReleaseResponse newVersionsResponse = client
                                        .fetchNewVersions(
                                                        artifact.groupId().value(),
                                                        artifact.artifactId().value(),
                                                        artifact.version().value())
                                        .orElse(null);

                        return Optional.of(
                                        mapper.toDomain(releaseResponse, artifactResponse, newVersionsResponse,
                                                        artifact));

                } catch (Exception e) {
                        LOG.error("Unexpected error loading stability for {}: {}", artifact.gav(), e.getMessage());
                        return Optional.empty();
                }
        }

}
