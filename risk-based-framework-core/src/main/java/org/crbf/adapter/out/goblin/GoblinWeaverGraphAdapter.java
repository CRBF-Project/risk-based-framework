package org.crbf.adapter.out.goblin;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.crbf.application.port.out.ResolveTransitiveDependenciesPort;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.TransitiveDepsResult;
import org.crbf.domain.model.optimisation.UpgradeCandidate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class GoblinWeaverGraphAdapter implements ResolveTransitiveDependenciesPort {

        private static final Logger LOG = LoggerFactory.getLogger(GoblinWeaverGraphAdapter.class);

        private static final String TRAVERSING_ENDPOINT = "/graph/traversing";
        private static final String NEW_VERSIONS_ENDPOINT = "/release/newVersions";

        private final String baseUrl;
        private final HttpClient httpClient;
        private final ObjectMapper objectMapper;
        private final GoblinWeaverUpgradeCandidateMapper upgradeCandidateMapper;
        private final GoblinWeaverGraphMapper graphMapper;

        public GoblinWeaverGraphAdapter(String baseUrl) {
                this.baseUrl = baseUrl;
                this.httpClient = HttpClient.newBuilder()
                                .connectTimeout(Duration.ofSeconds(10))
                                .build();
                this.objectMapper = new ObjectMapper();
                this.upgradeCandidateMapper = new GoblinWeaverUpgradeCandidateMapper();
                this.graphMapper = new GoblinWeaverGraphMapper();
        }

        @Override
        public Set<Artifact> resolveTransitiveDeps(Artifact artifact) {
                try {
                        GoblinWeaverTraversingRequest request = GoblinWeaverTraversingRequest
                                        .forArtifactWithCves(artifact.gav());

                        GoblinWeaverTraversingResponse response = post(TRAVERSING_ENDPOINT, request,
                                        GoblinWeaverTraversingResponse.class);

                        Set<Artifact> deps = graphMapper.toDomain(response);

                        LOG.debug("Resolved {} transitive deps for {}", deps.size(), artifact.gav());

                        return deps;

                } catch (Exception e) {
                        LOG.error("resolveTransitiveDeps failed for {}: {}", artifact.gav(), GoblinErrors.describe(e));
                        return Set.of();
                }
        }

        @Override
        public List<UpgradeCandidate> getNewerVersionsWithCves(Artifact artifact) {
                try {
                        GoblinWeaverReleaseRequest request = new GoblinWeaverReleaseRequest(
                                        artifact.groupId().value(),
                                        artifact.artifactId().value(),
                                        artifact.version().value(),
                                        GoblinWeaverReleaseRequest.CVE_ADDED_VALUES);

                        GoblinWeaverReleaseResponse response = post(NEW_VERSIONS_ENDPOINT, request,
                                        GoblinWeaverReleaseResponse.class);

                        return upgradeCandidateMapper.toDomain(response);

                } catch (Exception e) {
                        LOG.error("getNewerVersionsWithCves failed for {}: {}", artifact.gav(), GoblinErrors.describe(e));
                        return List.of();
                }
        }

        @Override
        public TransitiveDepsResult resolveTransitiveDepsWithCves(Artifact artifact) {
                try {
                        GoblinWeaverTraversingRequest request = GoblinWeaverTraversingRequest
                                        .forArtifactWithCves(artifact.gav());

                        GoblinWeaverTraversingResponse response = post(TRAVERSING_ENDPOINT, request,
                                        GoblinWeaverTraversingResponse.class);

                        TransitiveDepsResult result = graphMapper.toDomainWithCves(response, Set.of(artifact.gav()));

                        LOG.debug("Resolved {} transitive deps for {} ({} with CVEs)",
                                        result.allDeps().size(), artifact.gav(), result.vulnerableDeps().size());

                        return result;

                } catch (Exception e) {
                        LOG.error("resolveTransitiveDepsWithCves failed for {}: {}", artifact.gav(), GoblinErrors.describe(e));
                        return TransitiveDepsResult.unavailable();
                }
        }

        @Override
        public TransitiveDepsResult resolveGlobalGraph(List<Artifact> artifacts) {
                if (artifacts == null || artifacts.isEmpty()) {
                        return TransitiveDepsResult.unavailable();
                }

                try {
                        Set<String> gavs = artifacts.stream()
                                        .map(Artifact::gav)
                                        .collect(Collectors.toSet());

                        GoblinWeaverTraversingRequest request = GoblinWeaverTraversingRequest
                                        .forMultipleArtifactsWithCves(gavs);

                        GoblinWeaverTraversingResponse response = post(TRAVERSING_ENDPOINT, request,
                                        GoblinWeaverTraversingResponse.class);

                        TransitiveDepsResult result = graphMapper.toDomainWithCves(response, gavs);

                        LOG.debug("Global graph: {} total deps, {} with CVEs across {} fix versions",
                                        result.allDeps().size(), result.vulnerableDeps().size(), gavs.size());

                        return result;

                } catch (Exception e) {
                        LOG.error("resolveGlobalGraph failed: {}", GoblinErrors.describe(e));
                        return TransitiveDepsResult.unavailable();
                }
        }

        private <T> T post(String endpoint, Object requestBody, Class<T> responseType)
                        throws Exception {

                String json = objectMapper.writeValueAsString(requestBody);

                HttpRequest request = HttpRequest.newBuilder()
                                .uri(URI.create(baseUrl + endpoint))
                                .header("Content-Type", "application/json")
                                .POST(HttpRequest.BodyPublishers.ofString(json))
                                .timeout(Duration.ofSeconds(30))
                                .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() != 200) {
                        throw new RuntimeException(
                                        "Goblin Weaver returned status " + response.statusCode()
                                                        + " for " + endpoint);
                }

                return objectMapper.readValue(response.body(), responseType);
        }
}
