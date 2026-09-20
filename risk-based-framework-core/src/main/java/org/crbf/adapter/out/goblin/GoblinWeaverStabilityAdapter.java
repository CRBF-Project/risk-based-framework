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
 * Stability data is returned only when all required Goblin responses are
 * available. Partial or failed lookups are represented as
 * {@link Optional#empty()}, preventing unavailable metrics from being
 * interpreted as legitimate zero values.
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
                        Optional<GoblinWeaverReleaseResponse> releaseResponse = client.fetchReleaseMetrics(
                                        artifact.groupId().value(),
                                        artifact.artifactId().value(),
                                        artifact.version().value());

                        if (releaseResponse.isEmpty()) {
                                LOG.warn(
                                                "No Goblin release data for {}; stability reported as unavailable",
                                                artifact.gav());
                                return Optional.empty();
                        }

                        Optional<GoblinWeaverArtifactResponse> artifactResponse = client.fetchArtifactMetrics(
                                        artifact.groupId().value(),
                                        artifact.artifactId().value());

                        if (artifactResponse.isEmpty()) {
                                LOG.warn(
                                                "No Goblin artifact data for {}; stability reported as unavailable",
                                                artifact.gav());
                                return Optional.empty();
                        }

                        Optional<GoblinWeaverReleaseResponse> newVersionsResponse = client.fetchNewVersions(
                                        artifact.groupId().value(),
                                        artifact.artifactId().value(),
                                        artifact.version().value());

                        if (newVersionsResponse.isEmpty()) {
                                LOG.warn(
                                                "No Goblin version data for {}; stability reported as unavailable",
                                                artifact.gav());
                                return Optional.empty();
                        }

                        return Optional.of(
                                        mapper.toDomain(
                                                        releaseResponse.orElseThrow(),
                                                        artifactResponse.orElseThrow(),
                                                        newVersionsResponse.orElseThrow(),
                                                        artifact));

                } catch (Exception e) {
                        LOG.error(
                                        "Unexpected error loading stability for {}: {}",
                                        artifact.gav(),
                                        GoblinErrors.describe(e));

                        return Optional.empty();
                }
        }

}
