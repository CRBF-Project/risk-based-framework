package org.crbf.adapter.out.goblin;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;

import org.crbf.domain.model.artifact.TransitiveDepsResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A release published after the ecosystem graph snapshot was taken is absent
 * from the graph, and traversing from it returns an empty neighbourhood. That
 * emptiness says nothing about the release, so it must not be reported as a
 * release without vulnerable dependencies.
 */
class GoblinWeaverGraphMapperTest {

    private static final String ROOT_GAV = "org.codehaus.plexus:plexus-utils:3.6.1";
    private static final String RELEASE = "RELEASE";
    private static final long ANY_TIMESTAMP = 1_700_000_000_000L;

    private final GoblinWeaverGraphMapper mapper = new GoblinWeaverGraphMapper();

    @Test
    @DisplayName("A root release missing from the graph makes transitive data unavailable")
    void absentRootReleaseIsReportedAsUnavailable() {
        GoblinWeaverTraversingResponse response = new GoblinWeaverTraversingResponse(
                List.of(releaseNode("ROOT")),
                List.of());

        TransitiveDepsResult result = mapper.toDomainWithCves(response, Set.of(ROOT_GAV));

        assertTrue(result.isUnavailable());
    }

    @Test
    @DisplayName("A root release present in the graph with no dependencies is available")
    void presentRootWithoutDependenciesIsAvailable() {
        GoblinWeaverTraversingResponse response = new GoblinWeaverTraversingResponse(
                List.of(releaseNode(ROOT_GAV)),
                List.of());

        TransitiveDepsResult result = mapper.toDomainWithCves(response, Set.of(ROOT_GAV));

        assertFalse(result.isUnavailable());
    }

    private static GoblinWeaverTraversingResponse.GoblinTraversingNodeDto releaseNode(String id) {
        return new GoblinWeaverTraversingResponse.GoblinTraversingNodeDto(
                id, RELEASE, "3.6.1", ANY_TIMESTAMP, List.of());
    }
}
