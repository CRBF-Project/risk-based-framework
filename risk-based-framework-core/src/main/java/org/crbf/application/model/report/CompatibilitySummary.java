package org.crbf.application.model.report;

import java.util.List;
import java.util.Map;

import org.crbf.domain.model.compatibility.CompatibilityStatus;

/** Original japicmp status and separate contextual heuristic; neither guarantees runtime correctness. */
public record CompatibilitySummary(
                CompatibilityStatus status,
                int breakingChangeCount,
                Map<String, Integer> breakingChangesByType,
                List<String> topBreakingChanges,
                CompatibilityStatus contextualStatus) {
}
