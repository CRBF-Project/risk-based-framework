package org.crbf.application.model.report;

import java.util.List;

/**
 * @param contextualRisk The risk of leaving this artifact as it is. Distinct
 *                       from {@code remediation.potentialRiskAddressed}, which is the
 *                       current risk the selected plan potentially addresses and is zero
 *                       whenever no automatic upgrade exists.
 */
public record ArtifactFinding(
        String artifact,
        double contextualRisk,
        List<CveSummary> vulnerabilities,
        ReachabilitySummary reachability,
        CompatibilitySummary compatibility,
        RemediationSummary remediation,
        String stabilitySummary
) {}