package org.crbf.adapter.out.epss;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.crbf.application.port.out.LoadEpssScoresPort;
import org.crbf.domain.model.vulnerability.EpssScore;
import org.crbf.domain.model.vulnerability.Vulnerability;
import org.crbf.domain.model.vulnerability.VulnerabilityId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

public class EpssAdapter implements LoadEpssScoresPort {

    private static final String DEFAULT_EPSS_API_URL = "https://api.first.org/data/v1/epss";
    private static final Logger LOG = LoggerFactory.getLogger(EpssAdapter.class);

    private final String epssApiUrl;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public EpssAdapter() {
        this(DEFAULT_EPSS_API_URL);
    }

    public EpssAdapter(String epssApiUrl) {
        this.epssApiUrl = epssApiUrl;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public List<Vulnerability> enrich(List<Vulnerability> vulnerabilities) {
        List<String> cveIds = vulnerabilities.stream()
                .flatMap(v -> v.aliases().stream().filter(VulnerabilityId::isCve))
                .map(VulnerabilityId::value)
                .distinct()
                .toList();

        if (cveIds.isEmpty()) {
            LOG.debug("No CVE aliases found, skipping EPSS enrichment");
            return vulnerabilities;
        }

        return fetchEpssScores(cveIds)
                .filter(epssResponse -> epssResponse.data() != null)
                .map(epssResponse -> vulnerabilities.stream()
                        .map(vulnerability -> enrichVulnerability(vulnerability, epssResponse))
                        .toList())
                .orElse(vulnerabilities);
    }

    private Optional<EpssResponse> fetchEpssScores(List<String> cveIds) {
        String url = epssApiUrl + "?cve=" + String.join(",", cveIds);

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(15))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                LOG.warn("EPSS API returned status {}", response.statusCode());
                return Optional.empty();
            }

            return Optional.of(objectMapper.readValue(response.body(), EpssResponse.class));

        } catch (Exception e) {
            LOG.error("Failed to fetch EPSS scores", e);
            return Optional.empty();
        }
    }

    private Vulnerability enrichVulnerability(Vulnerability vulnerability, EpssResponse epssResponse) {
        return vulnerability.aliases().stream()
                .filter(VulnerabilityId::isCve)
                .flatMap(cveId -> epssResponse.data().stream()
                        .filter(d -> cveId.value().equalsIgnoreCase(d.cve())))
                .map(this::parseEpssScore)
                .flatMap(Optional::stream)
                .max(Comparator.comparingDouble(EpssScore::value))
                .map(vulnerability::withEpss)
                .orElse(vulnerability);
    }

    private Optional<EpssScore> parseEpssScore(EpssResponse.EpssDataDto d) {
        if (d.epssScore() == null || d.percentile() == null) return Optional.empty();
        try {
            return Optional.of(new EpssScore(
                    Double.parseDouble(d.epssScore()),
                    Double.parseDouble(d.percentile())));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }

}