package org.crbf.adapter.out.epss;

import static org.crbf.fixture.VulnerabilityFixture.vulnerabilityWithoutEpss;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Optional;

import org.crbf.domain.model.vulnerability.EpssScore;
import org.crbf.domain.model.vulnerability.Vulnerability;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;

class EpssAdapterTest {

    private static final String ENDPOINT = "https://example.invalid/epss";
    private HttpClient http;
    private EpssAdapter adapter;

    @BeforeEach
    void setUp() {
        http = mock(HttpClient.class);
        adapter = new EpssAdapter(ENDPOINT, http);
    }

    @Test
    void shouldAssociateReturnedScoresByCveRatherThanResponseOrder() throws Exception {
        Vulnerability first = advisory("GHSA-AAAA-BBBB-CCCC", "CVE-2026-1001");
        Vulnerability second = advisory("GHSA-DDDD-EEEE-FFFF", "CVE-2026-1002");
        respond(200, """
                {"data":[{"cve":"CVE-2026-1002","epss":"0.7","percentile":"0.9"},
                {"cve":"CVE-2026-1001","epss":"0.2","percentile":"0.6"}]}
                """);

        List<Vulnerability> result = adapter.enrich(List.of(first, second));

        assertEquals(List.of(first.withEpss(new EpssScore(0.2, 0.6)),
                second.withEpss(new EpssScore(0.7, 0.9))), result);
        ArgumentCaptor<HttpRequest> request = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http).send(request.capture(), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any());
        assertEquals("GET", request.getValue().method());
        assertEquals(URI.create(ENDPOINT + "?cve=CVE-2026-1001,CVE-2026-1002"), request.getValue().uri());
    }

    @Test
    void shouldUseTheHighestAvailableProbabilityAcrossCveAliases() throws Exception {
        Vulnerability vulnerability = advisory("GHSA-AAAA-BBBB-CCCC", "CVE-2026-1001", "CVE-2026-1002");
        respond(200, """
                {"data":[{"cve":"CVE-2026-1001","epss":"0.1","percentile":"0.8"},
                {"cve":"CVE-2026-1002","epss":"0.6","percentile":"0.9"}]}
                """);

        assertEquals(Optional.of(new EpssScore(0.6, 0.9)), adapter.enrich(List.of(vulnerability)).get(0).epss());
    }

    @Test
    void shouldRepresentAnUnreturnedScoreAsUnavailableWhileRetainingOtherScores() throws Exception {
        Vulnerability available = advisory("GHSA-AAAA-BBBB-CCCC", "CVE-2026-1001");
        Vulnerability unavailable = advisory("GHSA-DDDD-EEEE-FFFF", "CVE-2026-1002");
        respond(200, "{\"data\":[{\"cve\":\"CVE-2026-1001\",\"epss\":\"0.2\",\"percentile\":\"0.6\"}]}");

        List<Vulnerability> result = adapter.enrich(List.of(available, unavailable));

        assertEquals(Optional.of(new EpssScore(0.2, 0.6)), result.get(0).epss());
        assertEquals(Optional.empty(), result.get(1).epss());
        assertEquals(unavailable, result.get(1));
    }

    @Test
    void shouldKeepZeroProbabilityDistinctFromUnavailable() throws Exception {
        respond(200, "{\"data\":[{\"cve\":\"CVE-2026-1001\",\"epss\":\"0.0\",\"percentile\":\"0.0\"}]}");

        assertEquals(Optional.of(new EpssScore(0, 0)),
                adapter.enrich(List.of(advisory("GHSA-AAAA-BBBB-CCCC", "CVE-2026-1001"))).get(0).epss());
    }

    @Test
    void shouldLeaveVulnerabilitiesWithoutCveIdentifiersUnavailableWithoutCallingTheService() {
        Vulnerability vulnerability = advisory("GHSA-AAAA-BBBB-CCCC");

        assertEquals(List.of(vulnerability), adapter.enrich(List.of(vulnerability)));
        verifyNoInteractions(http);
    }

    @ParameterizedTest
    @ValueSource(strings = {"not-json", "null", "{}", "{\"data\":[]}",
            "{\"data\":[{\"cve\":\"CVE-2026-1001\",\"epss\":\"invalid\",\"percentile\":\"0.5\"}]}",
            "{\"data\":[{\"cve\":\"CVE-2026-1001\",\"epss\":\"0.2\"}]}"})
    void shouldKeepScoresUnavailableWhenNoUsableScoreCanBeRead(String body) throws Exception {
        Vulnerability vulnerability = advisory("GHSA-AAAA-BBBB-CCCC", "CVE-2026-1001");
        respond(200, body);

        assertEquals(List.of(vulnerability), adapter.enrich(List.of(vulnerability)));
    }

    @Test
    void shouldPreserveVulnerabilitiesWhenTheEpssServiceReturnsAnError() throws Exception {
        Vulnerability vulnerability = advisory("GHSA-AAAA-BBBB-CCCC", "CVE-2026-1001");
        respond(503, "{\"error\":\"unavailable\"}");

        assertEquals(List.of(vulnerability), adapter.enrich(List.of(vulnerability)));
    }

    @Test
    void shouldPreserveVulnerabilitiesWhenTheConnectionFails() throws Exception {
        Vulnerability vulnerability = advisory("GHSA-AAAA-BBBB-CCCC", "CVE-2026-1001");
        when(http.send(any(HttpRequest.class), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any()))
                .thenThrow(new IOException("Connection unavailable"));

        assertEquals(List.of(vulnerability), adapter.enrich(List.of(vulnerability)));
    }

    @Test
    void shouldRetrieveScoresForPrimaryCveIdentifiersWithoutAliases() throws Exception {
        Vulnerability primaryCve = vulnerabilityWithoutEpss("CVE-2026-1001", 8);
        respond(200, "{\"data\":[{\"cve\":\"CVE-2026-1001\",\"epss\":\"0.2\",\"percentile\":\"0.6\"}]}");

        assertEquals(List.of(primaryCve.withEpss(new EpssScore(0.2, 0.6))), adapter.enrich(List.of(primaryCve)));
        ArgumentCaptor<HttpRequest> request = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http).send(request.capture(), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any());
        assertEquals(URI.create(ENDPOINT + "?cve=CVE-2026-1001"), request.getValue().uri());
    }

    @ParameterizedTest
    @CsvSource({"-0.1,0.5", "1.1,0.5", "NaN,0.5", "Infinity,0.5", "-Infinity,0.5",
            "0.5,-0.1", "0.5,1.1", "0.5,NaN", "0.5,Infinity", "0.5,-Infinity"})
    void shouldLeaveInvalidProbabilityOrPercentileUnavailable(String probability, String percentile) throws Exception {
        respond(200, "{\"data\":[{\"cve\":\"CVE-2026-1001\",\"epss\":\"" + probability
                + "\",\"percentile\":\"" + percentile + "\"}]}");

        assertEquals(Optional.empty(),
                adapter.enrich(List.of(advisory("GHSA-AAAA-BBBB-CCCC", "CVE-2026-1001"))).get(0).epss());
    }

    @Test
    void shouldRetainValidScoresWhenOtherResponseRecordsAreInvalid() throws Exception {
        Vulnerability invalid = advisory("GHSA-AAAA-BBBB-CCCC", "CVE-2026-1001");
        Vulnerability valid = vulnerabilityWithoutEpss("CVE-2026-1002", 8);
        respond(200, """
                {"data":[null,{"cve":"CVE-2026-1001","epss":"NaN","percentile":"0.5"},
                {"cve":"CVE-2026-1002","epss":"1.1","percentile":"0.5"},
                {"cve":"CVE-2026-1002","epss":"0.4","percentile":"0.8"}]}
                """);

        assertEquals(List.of(invalid, valid.withEpss(new EpssScore(0.4, 0.8))), adapter.enrich(List.of(invalid, valid)));
    }

    @Test
    void shouldAcceptMaximumProbabilityAndPercentile() throws Exception {
        respond(200, "{\"data\":[{\"cve\":\"CVE-2026-1001\",\"epss\":\"1.0\",\"percentile\":\"1.0\"}]}");

        assertEquals(Optional.of(new EpssScore(1, 1)),
                adapter.enrich(List.of(vulnerabilityWithoutEpss("CVE-2026-1001", 8))).get(0).epss());
    }

    @Test
    void shouldQueryPrimaryAndAliasCvesWithoutDuplicatingIdentifiers() throws Exception {
        Vulnerability vulnerability = advisory("CVE-2026-1001", "CVE-2026-1001", "CVE-2026-1002");
        respond(200, "{\"data\":[{\"cve\":\"CVE-2026-1002\",\"epss\":\"0.4\",\"percentile\":\"0.8\"}]}");

        assertEquals(Optional.of(new EpssScore(0.4, 0.8)), adapter.enrich(List.of(vulnerability)).get(0).epss());
        ArgumentCaptor<HttpRequest> request = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http).send(request.capture(), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any());
        assertEquals(URI.create(ENDPOINT + "?cve=CVE-2026-1001,CVE-2026-1002"), request.getValue().uri());
    }

    private void respond(int status, String body) throws Exception {
        @SuppressWarnings("unchecked") HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(status);
        when(response.body()).thenReturn(body);
        when(http.send(any(HttpRequest.class), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any()))
                .thenReturn(response);
    }

    private static Vulnerability advisory(String id, String... aliases) {
        return Vulnerability.create(id, 8, "TEST_VECTOR", Optional.empty(), Optional.empty(), List.of(),
                "Synthetic advisory", "Synthetic advisory details", List.of(aliases),
                Optional.empty(), Optional.empty(), "", "");
    }
}
