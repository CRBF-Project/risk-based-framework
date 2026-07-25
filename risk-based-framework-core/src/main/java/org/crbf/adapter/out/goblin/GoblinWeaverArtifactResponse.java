package org.crbf.adapter.out.goblin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
record GoblinWeaverArtifactResponse(
                @JsonProperty("nodes") List<GoblinArtifactNodeDto> nodes) {

        @JsonIgnoreProperties(ignoreUnknown = true)
        record GoblinArtifactNodeDto(
                        @JsonProperty("id") String id,
                        @JsonProperty("nodeType") String nodeType,
                        @JsonProperty("speed") Double speed) {
        }
}
