package org.crbf.adapter.out.goblin;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Set;

record GoblinWeaverTraversingRequest(
        @JsonProperty("startReleasesGav") Set<String> startReleasesGav,
        @JsonProperty("libToExpendsGa")   Set<String> libToExpendsGa,
        @JsonProperty("filters")          List<String> filters,
        @JsonProperty("addedValues")      List<String> addedValues
) {

    public static final String CVE_AGGREGATED = "CVE_AGGREGATED";

    static GoblinWeaverTraversingRequest forArtifactWithCves(String gav) {
        return new GoblinWeaverTraversingRequest(
                Set.of(gav),
                Set.of(),
                List.of(),
                List.of(CVE_AGGREGATED)
        );
    }

    static GoblinWeaverTraversingRequest forMultipleArtifactsWithCves(Set<String> gavs) {
        return new GoblinWeaverTraversingRequest(
                gavs,
                Set.of(),
                List.of(),
                List.of(CVE_AGGREGATED)
        );
    }
}
