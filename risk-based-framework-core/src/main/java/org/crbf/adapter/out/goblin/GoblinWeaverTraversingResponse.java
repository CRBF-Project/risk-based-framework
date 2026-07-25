package org.crbf.adapter.out.goblin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
record GoblinWeaverTraversingResponse(
        @JsonProperty("nodes") List<GoblinTraversingNodeDto> nodes,
        @JsonProperty("edges") List<GoblinTraversingEdgeDto> edges
) {
    @JsonIgnoreProperties(ignoreUnknown = true)
    record GoblinTraversingNodeDto(
            @JsonProperty("id")       String id,
            @JsonProperty("nodeType") String nodeType,
            @JsonProperty("version")  String version,
            @JsonProperty("timestamp") long timestamp,
            @JsonProperty("cve_aggregated")  List<CveEntryDto> cveAggregated
    ) {
        boolean hasVulnerabilities() {
            return cveAggregated != null && !cveAggregated.isEmpty();
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record CveEntryDto(
            @JsonProperty("severity") String severity
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record GoblinTraversingEdgeDto(
            @JsonProperty("sourceId")      String sourceId,
            @JsonProperty("targetId")      String targetId,
            @JsonProperty("scope")         String scope,
            @JsonProperty("type")          String type,
            @JsonProperty("targetVersion") String targetVersion
    ) {}
}
