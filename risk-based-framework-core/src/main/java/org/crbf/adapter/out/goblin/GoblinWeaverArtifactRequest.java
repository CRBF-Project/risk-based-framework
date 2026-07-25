package org.crbf.adapter.out.goblin;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

record GoblinWeaverArtifactRequest(
        @JsonProperty("groupId") String groupId,
        @JsonProperty("artifactId") String artifactId,
        @JsonProperty("addedValues") List<String> addedValues) {

    static final List<String> ARTIFACT_ADDED_VALUES = List.of("SPEED");
}
