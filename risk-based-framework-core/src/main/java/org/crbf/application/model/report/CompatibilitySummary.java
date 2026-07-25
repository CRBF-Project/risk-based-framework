package org.crbf.application.model.report;

import java.util.List;
import java.util.Map;

import org.crbf.domain.model.compatibility.CompatibilityStatus;

public record CompatibilitySummary(
                CompatibilityStatus status,
                int breakingChangeCount,
                Map<String, Integer> breakingChangesByType,
                List<String> topBreakingChanges,
                boolean contextuallyAdjusted) {
}
