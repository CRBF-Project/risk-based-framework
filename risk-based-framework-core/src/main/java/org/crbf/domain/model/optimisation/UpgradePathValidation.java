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
                Optional<Double> upgradePathSecuritySignal,
                UpgradePathStatus upgradePathStatus,
                Optional<String> alternativeSafeVersion) {
        public UpgradePathValidation {
                upgradePathSecuritySignal = upgradePathSecuritySignal == null ? Optional.empty() : upgradePathSecuritySignal;
                upgradePathStatus = upgradePathStatus == null ? UpgradePathStatus.UNKNOWN : upgradePathStatus;
                
                upgradePathSecuritySignal.ifPresent(signal -> 
                {        
                        if (signal < -1.0 || signal > 1.0)
                                throw new IllegalArgumentException("Upgrade path security signal must be in [-1.0, 1.0].");
                });

                if (upgradePathStatus == UpgradePathStatus.UNKNOWN && upgradePathSecuritySignal.isPresent())
                        throw new IllegalArgumentException("Unknown upgrade path cannot have a security signal.");

                if (upgradePathStatus != UpgradePathStatus.UNKNOWN && upgradePathSecuritySignal.isEmpty())
                        throw new IllegalArgumentException("Known upgrade path must have a security signal.");
                
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
                return upgradePathStatus == UpgradePathStatus.HAS_RISKS;
        }

        public int totalNewVulns() {
                return fixVersionVulns.size() + newTransitiveVulnerableDeps.size();
        }

        public boolean isCleanPath() {
                return upgradePathStatus == UpgradePathStatus.CLEAN;
        }
}