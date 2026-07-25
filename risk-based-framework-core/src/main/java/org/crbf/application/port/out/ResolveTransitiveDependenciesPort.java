package org.crbf.application.port.out;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.TransitiveDepsResult;
import org.crbf.domain.model.optimisation.UpgradeCandidate;

import java.util.List;
import java.util.Set;

public interface ResolveTransitiveDependenciesPort {

    Set<Artifact> resolveTransitiveDeps(Artifact artifact);

    List<UpgradeCandidate> getNewerVersionsWithCves(Artifact artifact);

    /**
     * Resolves the full transitive dependency graph of an artifact, enriching
     * each node with CVE_AGGREGATED data from Goblin.
     *
     * Used by validateUpgradePath to compute the before/after graph diff and
     * identify new vulnerabilities introduced by an upgrade — replacing N
     * individual OSV calls with a single Goblin traversal.
     *
     * @return allDeps (for diff) + vulnerableDeps (deps with CVE_AGGREGATED > 0)
     */
    TransitiveDepsResult resolveTransitiveDepsWithCves(Artifact artifact);

    TransitiveDepsResult resolveGlobalGraph(List<Artifact> artifacts);
}
