package org.crbf.application.model.report;

import java.util.List;

import org.crbf.domain.model.reachability.ReachabilityStatus;

public record ReachabilitySummary(
        ReachabilityStatus status,
        List<String> reachableMethods
) {
    public boolean isReachable() {
        return status.isReachable();
    }
}
