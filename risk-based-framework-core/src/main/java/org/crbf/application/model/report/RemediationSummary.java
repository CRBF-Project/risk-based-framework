package org.crbf.application.model.report;

import java.util.Optional;

/** Current contextual risk potentially addressed; neither measured reduction nor posterior risk. */
public record RemediationSummary(
        UpgradeDecision decision,
        String rationale,
        double potentialRiskAddressed,
        double effortCost,
        String recommendedVersion,
        Optional<AlternativeFixSummary> alternativeFix
) {}
