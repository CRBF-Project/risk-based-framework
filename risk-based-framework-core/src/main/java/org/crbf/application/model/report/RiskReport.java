package org.crbf.application.model.report;

import java.util.List;
import java.util.Optional;
import org.crbf.domain.model.optimisation.InfeasibilityDetails;
import org.crbf.domain.model.optimisation.OptimisationStatus;

public record RiskReport(
        String projectName,
        int totalDependenciesScanned,
        int totalDependencyPaths,
        List<String> scannedArtifacts,
        List<ArtifactFinding> findings,
        OptimisationStatus optimisationStatus,
        Optional<InfeasibilityDetails> infeasibility,
        ResidualRiskSummary residualRisk,
        GlobalGraphValidationSummary globalGraphValidation,
        List<String> vulnerabilityLookupFailures,
        Optional<Double> availableEffortBudget) {
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
