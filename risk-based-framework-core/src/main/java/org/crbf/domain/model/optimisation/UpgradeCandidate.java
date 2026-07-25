package org.crbf.domain.model.optimisation;

import org.crbf.domain.model.artifact.Version;
import org.crbf.domain.model.vulnerability.VulnerabilityId;
import java.util.List;

public record UpgradeCandidate(
        Version version,
        List<VulnerabilityId> knownVulnerabilities
) {
    public UpgradeCandidate {
        if (version == null) throw new IllegalArgumentException("Version must not be null");
        knownVulnerabilities = knownVulnerabilities == null
                ? List.of()
                : List.copyOf(knownVulnerabilities);
    }

    public static UpgradeCandidate create(String version, List<String> cveIds) {
        return new UpgradeCandidate(
                new Version(version),
                cveIds == null ? List.of() :
                        cveIds.stream()
                        .filter(id -> id != null && !id.isBlank())
                        .map(VulnerabilityId::new)
                        .toList()
        );
    }

    public boolean isClean() {
        return knownVulnerabilities.isEmpty();
    }

    public int vulnerabilityCount() {
        return knownVulnerabilities.size();
    }
}
