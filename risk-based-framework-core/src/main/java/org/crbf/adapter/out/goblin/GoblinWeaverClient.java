package org.crbf.adapter.out.goblin;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * Low-level HTTP client for the Goblin Weaver REST API.
 * Single point of contact with the external system — all endpoints go through
 * here.
 */
class GoblinWeaverClient {

        private static final Logger LOG = LoggerFactory.getLogger(GoblinWeaverClient.class);

        private static final String RELEASE_ENDPOINT = "/release";
        private static final String NEW_VERSIONS_ENDPOINT = "/release/newVersions";
        private static final String ARTIFACT_ENDPOINT = "/artifact";

        private final String baseUrl;
        private final HttpClient httpClient;
        private final ObjectMapper objectMapper;

        GoblinWeaverClient(String baseUrl, HttpClient httpClient, ObjectMapper objectMapper) {
                this.baseUrl = baseUrl;
                this.httpClient = httpClient;
                this.objectMapper = objectMapper;
        }

        Optional<GoblinWeaverReleaseResponse> fetchReleaseMetrics(
                        String groupId, String artifactId, String version) {

                GoblinWeaverReleaseRequest request = new GoblinWeaverReleaseRequest(
                                groupId, artifactId, version, GoblinWeaverReleaseRequest.STABILITY_ADDED_VALUES);

                return post(RELEASE_ENDPOINT, request, GoblinWeaverReleaseResponse.class,
                                groupId + ":" + artifactId + ":" + version);
        }

        Optional<GoblinWeaverReleaseResponse> fetchNewVersions(String groupId, String artifactId, String version) {
                GoblinWeaverReleaseRequest request = new GoblinWeaverReleaseRequest(
                                groupId, artifactId, version, List.of());

                return post(NEW_VERSIONS_ENDPOINT, request, GoblinWeaverReleaseResponse.class,
                                groupId + ":" + artifactId + ":" + version);
        }

        Optional<GoblinWeaverArtifactResponse> fetchArtifactMetrics(String groupId, String artifactId) {
                GoblinWeaverArtifactRequest request = new GoblinWeaverArtifactRequest(
                                groupId, artifactId, GoblinWeaverArtifactRequest.ARTIFACT_ADDED_VALUES);

                return post(ARTIFACT_ENDPOINT, request, GoblinWeaverArtifactResponse.class,
                                groupId + ":" + artifactId);
        }

        private <T> Optional<T> post(String endpoint, Object requestBody, Class<T> responseType, String label) {
                try {
                        String body = objectMapper.writeValueAsString(requestBody);

                        HttpRequest request = HttpRequest.newBuilder()
                                        .uri(URI.create(baseUrl + endpoint))
                                        .header("Content-Type", "application/json")
                                        .POST(HttpRequest.BodyPublishers.ofString(body))
                                        .timeout(Duration.ofSeconds(30))
                                        .build();

                        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                        if (response.statusCode() != 200) {
                                LOG.warn("{} returned status {} for {}", endpoint, response.statusCode(), label);
                                return Optional.empty();
                        }

                        return Optional.of(objectMapper.readValue(response.body(), responseType));

                } catch (Exception e) {
                        LOG.error("Request to {} failed for {} — {}", endpoint, label, GoblinErrors.describe(e));
                        return Optional.empty();
                }
        }
}
