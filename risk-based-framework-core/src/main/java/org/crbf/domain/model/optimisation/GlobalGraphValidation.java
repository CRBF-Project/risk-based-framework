package org.crbf.domain.model.optimisation;

import org.crbf.domain.model.artifact.Artifact;

import java.util.List;

/**
 * Result of the global graph validation performed after Z3 optimisation.
 *
 * Validates that the COMBINATION of all recommended upgrades, applied
 * simultaneously, does not introduce new vulnerable transitive dependencies
 * that would not be visible when validating each artifact in isolation.
 *
 * @param analyzedArtifacts Fix versions submitted to the combined traversal.
 * @param newVulnerableDeps Deps with CVE_AGGREGATED > 0 in the combined graph.
 * @param isClean True if no new vulnerable deps were found.
 * @param graphDataUnavailable True if Graph Data could not be obtained.
 */
public record GlobalGraphValidation(
        List<Artifact> analyzedArtifacts,
        List<Artifact> newVulnerableDeps,
        boolean isClean,
        boolean graphDataUnavailable
) {
    public GlobalGraphValidation {
        analyzedArtifacts = analyzedArtifacts == null ? List.of() : List.copyOf(analyzedArtifacts);
        newVulnerableDeps = newVulnerableDeps == null ? List.of() : List.copyOf(newVulnerableDeps);
    }

    public static GlobalGraphValidation notRun() {
        return new GlobalGraphValidation(List.of(), List.of(), false, false);
    }

    public static GlobalGraphValidation unavailable() {
        return new GlobalGraphValidation(List.of(), List.of(), false, true);
    }

    public static GlobalGraphValidation clean(List<Artifact> analyzed) {
        return new GlobalGraphValidation(analyzed, List.of(), true, false);
    }

    public static GlobalGraphValidation withRisks(List<Artifact> analyzed, List<Artifact> vulnerable) {
        return new GlobalGraphValidation(analyzed, vulnerable, false, false);
    }
}
