package org.crbf.application.model.report;

import java.util.List;

public record GlobalGraphValidationSummary(
        GraphValidationStatus status,
        List<String> analyzedArtifacts,
        List<String> newVulnerableDeps
) {}
