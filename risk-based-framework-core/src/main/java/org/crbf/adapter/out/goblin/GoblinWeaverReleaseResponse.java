package org.crbf.adapter.out.goblin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Response body from the Goblin Weaver RELEASE REST API.
 * The Weaver returns a root object containing a list of "nodes".
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GoblinWeaverReleaseResponse(
                @JsonProperty("nodes") List<GoblinNodeDto> nodes) {

        @JsonIgnoreProperties(ignoreUnknown = true)
        public record GoblinNodeDto(
                        @JsonProperty("id") String id,
                        @JsonProperty("nodeType") String nodeType,
                        @JsonProperty("version") String version,
                        @JsonProperty("popularity_1_year") Integer popularity1Year,
                        @JsonProperty("timestamp") Long timestamp,
                        @JsonProperty("freshness") GoblinFreshnessDto freshness,
                        @JsonProperty("cve_aggregated") List<GoblinCveDto> cveAggregated,
                        @JsonProperty("adoption_rate") Double adoptionRate,
                        @JsonProperty("adoption_lifespan") Double adoptionLifespan) {
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        public record GoblinFreshnessDto(
                        @JsonProperty("numberMissedRelease") String numberMissedRelease,
                        @JsonProperty("outdatedTimeInMs") String outdatedTimeInMs) {
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        public record GoblinCveDto(
                        @JsonProperty("name") String name,
                        @JsonProperty("severity") String severity,
                        @JsonProperty("cwe") String cwe) {
        }
}