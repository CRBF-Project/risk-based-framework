package org.crbf.domain.model.optimisation;

import org.crbf.domain.model.artifact.Artifact;

/**
 * Represents the Z3 optimiser's decision for a single artifact.
 *
 * @param artifact The artifact this decision applies to.
 * @param shouldUpgrade Whether the optimiser recommends upgrading this artifact.
 * @param targetVersion The fix version to upgrade to, or {@code null} if not upgrading.
 * @param riskReduction Risk score eliminated by this upgrade (0.0 if not upgrading).
 * @param effortCost Effort units consumed by this upgrade (0.0 if not upgrading).
 * @param rationale Human-readable explanation of why this decision was taken.
 */
public record RemediationDecision(
        Artifact artifact,
        boolean shouldUpgrade,
        String targetVersion,
        double riskReduction,
        double effortCost,
        String rationale
) {
    public static RemediationDecision upgrade(
            Artifact artifact,
            String targetVersion,
            double riskReduction,
            double effortCost,
            String rationale) {
        return new RemediationDecision(artifact, true, targetVersion, riskReduction, effortCost, rationale);
    }

    public static RemediationDecision defer(
            Artifact artifact,
            String rationale) {
        return new RemediationDecision(artifact, false, null, 0.0, 0.0, rationale);
    }
}