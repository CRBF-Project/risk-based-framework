package org.crbf.adapter.out.goblin;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Request body for the Goblin Weaver REST API.
 * POST http://localhost:8080/api/releases
 * The "addedValues" list instructs the Weaver to compute and attach
 * the requested metrics to the response on demand.
 *
 * Supported values: FRESHNESS_AGGREGATED, POPULARITY_1_YEAR_AGGREGATED, SPEED,
 * CVE, CVE_AGGREGATED, etc.
 * Full Swagger docs available at http://localhost:8080/swagger-ui/index.html
 */
record GoblinWeaverReleaseRequest(
                @JsonProperty("groupId") String groupId,
                @JsonProperty("artifactId") String artifactId,
                @JsonProperty("version") String version,
                @JsonProperty("addedValues") List<String> addedValues) {
        static final List<String> STABILITY_ADDED_VALUES = List.of("FRESHNESS", "ADOPTION_RATE", "ADOPTION_LIFESPAN",
                        "POPULARITY_1_YEAR");

        static final List<String> CVE_ADDED_VALUES = List.of("CVE_AGGREGATED");
}
