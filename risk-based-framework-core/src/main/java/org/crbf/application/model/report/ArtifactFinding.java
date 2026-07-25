package org.crbf.application.model.report;

import java.util.List;

public record ArtifactFinding(
        String artifact,
        List<CveSummary> vulnerabilities,
        ReachabilitySummary reachability,
        CompatibilitySummary compatibility,
        RemediationSummary remediation,
        String stabilitySummary
) {}