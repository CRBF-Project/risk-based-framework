package org.crbf.application.model.report;

import java.util.List;

/**
 * @param contextualRisk The risk of leaving this artifact as it is. Distinct
 *                       from {@code remediation.riskReduction}, which is the
 *                       risk the selected plan actually removes and is zero
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