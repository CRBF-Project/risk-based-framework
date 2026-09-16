package org.crbf.application.model.report;

import java.util.Optional;

public record RemediationSummary(
        UpgradeDecision decision,
        String rationale,
        double riskReduction,
        double effortCost,
        String recommendedVersion,
        Optional<AlternativeFixSummary> alternativeFix
) {}
