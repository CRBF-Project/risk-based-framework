package org.crbf.domain.model.optimisation;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.compatibility.CompatibilityReport;
import org.crbf.domain.model.vulnerability.Vulnerability;

import java.util.List;
import java.util.Optional;

public record UpgradePathValidation(
                Artifact currentArtifact,
                String proposedVersion,
                List<Vulnerability> fixVersionVulns,
                List<Artifact> addedTransitiveDeps,
                List<Artifact> removedTransitiveDeps,
                List<Artifact> newTransitiveVulnerableDeps,
                Optional<CompatibilityReport> compatibilityReport,
                double netRiskDelta,
                boolean isCleanPath,
                Optional<String> alternativeSafeVersion) {
        public UpgradePathValidation {
                fixVersionVulns = fixVersionVulns == null
                                ? List.of()
                                : List.copyOf(fixVersionVulns);
                addedTransitiveDeps = addedTransitiveDeps == null
                                ? List.of()
                                : List.copyOf(addedTransitiveDeps);
                removedTransitiveDeps = removedTransitiveDeps == null
                                ? List.of()
                                : List.copyOf(removedTransitiveDeps);
                newTransitiveVulnerableDeps = newTransitiveVulnerableDeps == null
                                ? List.of()
                                : List.copyOf(newTransitiveVulnerableDeps);
                compatibilityReport = compatibilityReport == null
                                ? Optional.empty()
                                : compatibilityReport;
                alternativeSafeVersion = alternativeSafeVersion == null
                                ? Optional.empty()
                                : alternativeSafeVersion;
        }

        public boolean hasNewRisks() {
                return !fixVersionVulns.isEmpty() || !newTransitiveVulnerableDeps.isEmpty();
        }

        public int totalNewVulns() {
                return fixVersionVulns.size() + newTransitiveVulnerableDeps.size();
        }
}