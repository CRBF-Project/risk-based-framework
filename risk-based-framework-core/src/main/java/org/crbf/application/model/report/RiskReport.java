package org.crbf.application.model.report;

import java.util.List;

public record RiskReport(
        String projectName,
        int totalDependenciesScanned,
        int totalDependencyPaths,
        List<String> scannedArtifacts,
        List<ArtifactFinding> findings,
        GlobalGraphValidationSummary globalGraphValidation,
        List<String> vulnerabilityLookupFailures) {
    public RiskReport {
        scannedArtifacts = scannedArtifacts == null ? List.of() : List.copyOf(scannedArtifacts);
        findings = findings == null ? List.of() : List.copyOf(findings);
        vulnerabilityLookupFailures = vulnerabilityLookupFailures == null
                ? List.of()
                : List.copyOf(vulnerabilityLookupFailures);
    }

    public int totalVulnerableArtifacts() {
        return findings.size();
    }

    public int totalCves() {
        return findings.stream()
                .mapToInt(f -> f.vulnerabilities().size())
                .sum();
    }

    public boolean hasLookupFailures() {
        return !vulnerabilityLookupFailures.isEmpty();
    }
}
