package org.crbf.domain.model.artifact;

import java.util.List;
import java.util.Set;

/**
 * Result of resolving the full transitive dependency graph of an artifact,
 * enriched with vulnerability data from the ecosystem.
 *
 * @param allDeps All artifacts reachable transitively from the
 *                given root.
 * @param vulnerableDeps Subset of allDeps that carry known CVEs.
 * @param graphDataUnavailable True if the graph data source could not
 *                             be reached. Distinct from an empty result — a 
 *                             project with no transitive dependencies is valid 
 *                             and should not be treated as unavailable.
 */
public record TransitiveDepsResult(
        Set<Artifact> allDeps,
        List<Artifact> vulnerableDeps,
        boolean graphDataUnavailable) {

    public TransitiveDepsResult {
        allDeps = allDeps == null ? Set.of() : Set.copyOf(allDeps);
        vulnerableDeps = vulnerableDeps == null ? List.of() : List.copyOf(vulnerableDeps);
    }

    public static TransitiveDepsResult unavailable() {
        return new TransitiveDepsResult(Set.of(), List.of(), true);
    }

    public static TransitiveDepsResult of(Set<Artifact> deps, List<Artifact> vulnerable) {
        return new TransitiveDepsResult(deps, vulnerable, false);
    }

    public boolean isUnavailable() {
        return graphDataUnavailable;
    }
}
