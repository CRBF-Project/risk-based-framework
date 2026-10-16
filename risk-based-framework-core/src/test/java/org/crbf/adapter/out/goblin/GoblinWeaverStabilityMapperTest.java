package org.crbf.adapter.out.goblin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.util.Optional;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.Scope;
import org.crbf.domain.model.stability.EcosystemStability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class GoblinWeaverStabilityMapperTest {
    private static final Artifact ARTIFACT = Artifact.create("org.example", "library", "1.0.0", Scope.COMPILE);
    private final ObjectMapper json = new ObjectMapper();
    private final GoblinWeaverStabilityMapper mapper = new GoblinWeaverStabilityMapper();

    @Test
    void shouldConvertReportedIndicatorsAndSelectTheMostRecentRelease() throws IOException {
        GoblinWeaverReleaseResponse release = fixture("release.json", GoblinWeaverReleaseResponse.class);
        GoblinWeaverArtifactResponse artifact = fixture("artifact.json", GoblinWeaverArtifactResponse.class);
        GoblinWeaverReleaseResponse versions = fixture("new-versions.json", GoblinWeaverReleaseResponse.class);

        EcosystemStability result = mapper.toDomain(release, artifact, versions, ARTIFACT);

        assertEquals(EcosystemStability.create("3.0.0", 2, 3, 0.25, 120.0, 0.02, 1700000000000L), result);
    }

    @Test
    void shouldKeepMissingOptionalIndicatorsUnavailable() throws IOException {
        GoblinWeaverReleaseResponse release = json.readValue("""
                {"nodes":[{"freshness":{"numberMissedRelease":"0","outdatedTimeInMs":"0"}}]}
                """, GoblinWeaverReleaseResponse.class);
        GoblinWeaverArtifactResponse artifact = json.readValue("{\"nodes\":[{}]}", GoblinWeaverArtifactResponse.class);

        EcosystemStability result = mapper.toDomain(release, artifact, null, ARTIFACT);

        assertEquals(Optional.empty(), result.adoptionRate());
        assertEquals(Optional.empty(), result.adoptionLifespan());
        assertEquals(Optional.empty(), result.maintenanceRate());
    }

    @Test
    void shouldPreserveMeasuredZeroIndicators() throws IOException {
        GoblinWeaverReleaseResponse release = json.readValue("""
                {"nodes":[{"freshness":{"numberMissedRelease":"0","outdatedTimeInMs":"0"},
                           "adoption_rate":0,"adoption_lifespan":0}]}
                """, GoblinWeaverReleaseResponse.class);
        GoblinWeaverArtifactResponse artifact = json.readValue("{\"nodes\":[{\"speed\":0}]}", GoblinWeaverArtifactResponse.class);

        EcosystemStability result = mapper.toDomain(release, artifact, null, ARTIFACT);

        assertEquals(EcosystemStability.create("1.0.0", 0, 0, 0.0, 0.0, 0.0, 0), result);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{}", "{\"nodes\":[]}", "{\"nodes\":[{}]}",
            "{\"nodes\":[{\"freshness\":{\"numberMissedRelease\":\"0\"}}]}",
            "{\"nodes\":[{\"freshness\":{\"outdatedTimeInMs\":\"0\"}}]}",
            "{\"nodes\":[{\"freshness\":{\"numberMissedRelease\":\"invalid\",\"outdatedTimeInMs\":\"0\"}}]}",
            "{\"nodes\":[{\"freshness\":{\"numberMissedRelease\":\"0\",\"outdatedTimeInMs\":\"invalid\"}}]}",
            "{\"nodes\":[{\"freshness\":{\"numberMissedRelease\":\"-1\",\"outdatedTimeInMs\":\"0\"}}]}",
            "{\"nodes\":[{\"freshness\":{\"numberMissedRelease\":\"0\",\"outdatedTimeInMs\":\"-1\"}}]}"
    })
    void shouldRejectUnavailableOrInvalidFreshnessInsteadOfReportingZero(String body) throws IOException {
        GoblinWeaverReleaseResponse release = json.readValue(body, GoblinWeaverReleaseResponse.class);

        GoblinWeaverArtifactResponse artifact = fixture("artifact.json", GoblinWeaverArtifactResponse.class);
        GoblinWeaverReleaseResponse versions = fixture("new-versions.json", GoblinWeaverReleaseResponse.class);

        assertThrows(IllegalArgumentException.class, () -> mapper.toDomain(release, artifact, versions, ARTIFACT));
    }

    private <T> T fixture(String name, Class<T> type) throws IOException {
        try (var input = getClass().getResourceAsStream("/goblin/stability/" + name)) {
            if (input == null) throw new IOException("Missing fixture: " + name);
            return json.readValue(input, type);
        }
    }
}
