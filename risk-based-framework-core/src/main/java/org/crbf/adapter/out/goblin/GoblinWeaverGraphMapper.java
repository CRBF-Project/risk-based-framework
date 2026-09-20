package org.crbf.adapter.out.goblin;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.Scope;
import org.crbf.domain.model.artifact.TransitiveDepsResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

class GoblinWeaverGraphMapper {

    private static final Logger LOG = LoggerFactory.getLogger(GoblinWeaverGraphMapper.class);

    Set<Artifact> toDomain(GoblinWeaverTraversingResponse response) {
        if (response == null || response.edges() == null) return Set.of();

        return response.edges().stream()
                .filter(edge -> "DEPENDENCY".equals(edge.type()))
                .filter(edge -> edge.targetId() != null && edge.targetId().contains(":"))
                .filter(edge -> edge.targetVersion() != null && !edge.targetVersion().isBlank())
                .map(this::edgeToDomain)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

    /**
     * @param rootGavs the releases the traversal started from. A root that has
     *                 no node in the response is not present in the ecosystem
     *                 graph at all — typically a release published after the
     *                 graph snapshot was taken. The traversal then returns an
     *                 empty neighbourhood, which must not be read as "this
     *                 release has no vulnerable dependencies".
     */
    TransitiveDepsResult toDomainWithCves(
            GoblinWeaverTraversingResponse response, Set<String> rootGavs) {

        if (response == null) return TransitiveDepsResult.unavailable();

        Set<Artifact> allDeps = toDomain(response);

        if (response.nodes() == null) {
            return new TransitiveDepsResult(allDeps, List.of(), true);
        }

        Set<String> resolvedReleaseIds = response.nodes().stream()
                .filter(node -> "RELEASE".equals(node.nodeType()))
                .map(GoblinWeaverTraversingResponse.GoblinTraversingNodeDto::id)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        List<String> missingRoots = rootGavs.stream()
                .filter(gav -> !resolvedReleaseIds.contains(gav))
                .toList();

        if (!missingRoots.isEmpty()) {
            LOG.warn("{} not present in the ecosystem graph; transitive data reported as unavailable",
                    missingRoots);
            return TransitiveDepsResult.unavailable();
        }

        List<Artifact> vulnerableDeps = response.nodes().stream()
                .filter(node -> "RELEASE".equals(node.nodeType()))
                .filter(GoblinWeaverTraversingResponse.GoblinTraversingNodeDto::hasVulnerabilities)
                .filter(node -> node.id() != null && node.id().split(":").length >= 3)
                .map(this::releaseNodeToDomain)
                .filter(Objects::nonNull)
                .toList();

        return new TransitiveDepsResult(allDeps, vulnerableDeps,false);
    }

    private Artifact edgeToDomain(GoblinWeaverTraversingResponse.GoblinTraversingEdgeDto edge) {
        try {
            String[] parts = edge.targetId().split(":");
            if (parts.length < 2) return null;
            String scope = edge.scope() != null ? edge.scope() : "compile";
            return Artifact.create(parts[0], parts[1], edge.targetVersion(), Scope.fromString(scope));
        } catch (Exception e) {
            LOG.warn("Failed to parse artifact from edge '{}': {}", edge.targetId(), e.getMessage());
            return null;
        }
    }

    private Artifact releaseNodeToDomain(GoblinWeaverTraversingResponse.GoblinTraversingNodeDto node) {
        try {
            // RELEASE node id format: "groupId:artifactId:version"
            String[] parts = node.id().split(":");
            if (parts.length < 3) return null;
            return Artifact.create(parts[0], parts[1], parts[2], Scope.COMPILE);
        } catch (Exception e) {
            LOG.warn("Failed to parse release node '{}': {}", node.id(), e.getMessage());
            return null;
        }
    }
}
