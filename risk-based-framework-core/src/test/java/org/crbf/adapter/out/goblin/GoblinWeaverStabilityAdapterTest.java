package org.crbf.adapter.out.goblin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.mockito.ArgumentCaptor;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.Scope;
import org.crbf.domain.model.stability.EcosystemStability;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class GoblinWeaverStabilityAdapterTest {
    private static final Artifact ARTIFACT = Artifact.create("org.example", "library", "1.0.0", Scope.COMPILE);
    private final HttpClient http = mock(HttpClient.class);
    private final GoblinWeaverStabilityAdapter adapter = new GoblinWeaverStabilityAdapter("https://example.invalid", http);
    private final Map<String, HttpResponse<String>> responses = new HashMap<>();

    @BeforeEach
    void respondWithAvailableMetrics() throws Exception {
        responses.put("/release", response(200, fixture("release.json")));
        responses.put("/artifact", response(200, fixture("artifact.json")));
        responses.put("/release/newVersions", response(200, fixture("new-versions.json")));
        when(http.send(any(HttpRequest.class), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any()))
                .thenAnswer(invocation -> responses.get(invocation.<HttpRequest>getArgument(0).uri().getPath()));
    }

    @Test
    void shouldReturnIndicatorsFromSuccessfulEcosystemResponses() {
        Optional<EcosystemStability> result = adapter.loadMetrics(ARTIFACT);

        assertEquals(Optional.of(EcosystemStability.create("3.0.0", 2, 3, 0.25, 120.0, 0.02, 1700000000000L)), result);
    }

    @Test
    void shouldSendTheDependencyCoordinatesAndRequestedIndicatorsToEachEndpoint() throws Exception {
        adapter.loadMetrics(ARTIFACT);

        ArgumentCaptor<HttpRequest> requests = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http, times(3)).send(requests.capture(),
                org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any());
        ObjectMapper json = new ObjectMapper();
        Map<String, JsonNode> expected = Map.of(
                "https://example.invalid/release", json.readTree("""
                        {"groupId":"org.example","artifactId":"library","version":"1.0.0",
                         "addedValues":["FRESHNESS","ADOPTION_RATE","ADOPTION_LIFESPAN","POPULARITY_1_YEAR"]}
                        """),
                "https://example.invalid/artifact", json.readTree("""
                        {"groupId":"org.example","artifactId":"library","addedValues":["SPEED"]}
                        """),
                "https://example.invalid/release/newVersions", json.readTree("""
                        {"groupId":"org.example","artifactId":"library","version":"1.0.0","addedValues":[]}
                        """));
        Map<String, JsonNode> actual = new HashMap<>();
        for (HttpRequest request : requests.getAllValues()) {
            assertEquals("POST", request.method(), request.uri().toString());
            actual.put(request.uri().toString(), json.readTree(requestBody(request)));
        }
        assertEquals(expected, actual);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/release", "/artifact", "/release/newVersions"})
    void shouldReportUnavailableWhenARequiredRequestFails(String endpoint) {
        responses.put(endpoint, response(503, "Service unavailable"));

        assertEquals(Optional.empty(), adapter.loadMetrics(ARTIFACT));
    }

    @Test
    void shouldReportUnavailableWhenTheConnectionFails() throws Exception {
        when(http.send(any(HttpRequest.class), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any()))
                .thenThrow(new IOException("Synthetic connection failure"));

        assertEquals(Optional.empty(), adapter.loadMetrics(ARTIFACT));
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "not-json", "{\"nodes\":[]}", "{\"nodes\":[{}]}"})
    void shouldReportUnavailableWhenReleaseDataCannotSupplyFreshness(String body) {
        responses.put("/release", response(200, body));

        assertEquals(Optional.empty(), adapter.loadMetrics(ARTIFACT));
    }

    private HttpResponse<String> response(int status, String body) {
        @SuppressWarnings("unchecked")
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(status);
        when(response.body()).thenReturn(body);
        return response;
    }

    private String requestBody(HttpRequest request) throws Exception {
        CompletableFuture<String> completed = new CompletableFuture<>();
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        request.bodyPublisher().orElseThrow().subscribe(new Flow.Subscriber<ByteBuffer>() {
            public void onSubscribe(Flow.Subscription subscription) { subscription.request(Long.MAX_VALUE); }
            public void onNext(ByteBuffer buffer) {
                byte[] chunk = new byte[buffer.remaining()];
                buffer.get(chunk);
                bytes.writeBytes(chunk);
            }
            public void onError(Throwable error) { completed.completeExceptionally(error); }
            public void onComplete() { completed.complete(bytes.toString(StandardCharsets.UTF_8)); }
        });
        return completed.get(1, TimeUnit.SECONDS);
    }

    private String fixture(String name) throws IOException {
        try (var input = getClass().getResourceAsStream("/goblin/stability/" + name)) {
            if (input == null) throw new IOException("Missing fixture: " + name);
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
