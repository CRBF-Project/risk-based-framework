package org.crbf.adapter.out.epss;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
record EpssResponse(List<EpssDataDto> data) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    record EpssDataDto(
        String cve,
        @JsonProperty("epss") String epssScore,
        String percentile
    ) {}
}