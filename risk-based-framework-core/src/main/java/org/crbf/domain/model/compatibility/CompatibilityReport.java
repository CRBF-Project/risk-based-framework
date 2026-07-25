package org.crbf.domain.model.compatibility;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.reachability.ProjectCallGraph;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Value Object that represents the result of a binary compatibility
 * analysis between two versions of the same {@link Artifact}.
 *
 * The "breakingChanges" list contains descriptions of each
 * individual API change detected by japicmp (e.g. "Method removed:
 * org.apache.commons.lang3.StringUtils#isEmpty(String)").
 */
public record CompatibilityReport(
        Artifact fromVersion,
        Artifact toVersion,
        CompatibilityStatus status,
        List<String> breakingChanges) {
    public CompatibilityReport {
        if (fromVersion == null || toVersion == null) {
            throw new IllegalArgumentException("Both artifact versions must be provided.");
        }
        if (status == null) {
            throw new IllegalArgumentException("CompatibilityStatus cannot be null.");
        }
        breakingChanges = (breakingChanges == null) ? List.of() : List.copyOf(breakingChanges);
    }

    public boolean hasBreakingChanges() {
        return status == CompatibilityStatus.BINARY_INCOMPATIBLE
                || status == CompatibilityStatus.SOURCE_INCOMPATIBLE;
    }

    public int breakingChangeCount() {
        return breakingChanges.size();
    }

    /**
     * Returns structured method identifiers ("className#methodName(Param1,
     * Param2)")
     * Class-level changes (no '#') are excluded — they have no method to intersect.
     */
    public Set<String> breakingMethodIds() {
        return breakingChanges.stream()
                .map(CompatibilityReport::extractMethodId)
                .filter(id -> !id.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
    }

    // "[BINARY] Method org.Class#method(String, int) — METHOD_REMOVED"
    // → "org.Class#method(String, int)"
    private static String extractMethodId(String breakingChange) {
        int hash = breakingChange.indexOf('#');
        if (hash < 0)
            return "";
        int classStart = breakingChange.lastIndexOf(' ', hash) + 1;
        String className = breakingChange.substring(classStart, hash);
        String afterHash = breakingChange.substring(hash + 1);
        int dash = afterHash.indexOf(" —");
        String methodWithSig = dash > 0 ? afterHash.substring(0, dash) : afterHash;
        return className + "#" + methodWithSig;
    }

    /**
     * Returns a contextually-adjusted report where BINARY_INCOMPATIBLE is
     * downgraded to COMPATIBLE when none of the breaking methods appear in
     * the project's call graph.
     *
     * The original breaking changes are preserved for reporting purposes.
     */
    public CompatibilityReport contextualise(ProjectCallGraph callGraph) {
        if (status != CompatibilityStatus.BINARY_INCOMPATIBLE || breakingChanges.isEmpty()) {
            return this;
        }
        boolean anyReachable = breakingMethodIds().stream()
                .anyMatch(callGraph::containsMethodId);
        if (!anyReachable) {
            return new CompatibilityReport(fromVersion, toVersion,
                    CompatibilityStatus.COMPATIBLE, breakingChanges);
        }
        return this;
    }

    public static CompatibilityReport compatible(Artifact from, Artifact to) {
        return new CompatibilityReport(from, to, CompatibilityStatus.COMPATIBLE, List.of());
    }

    public static CompatibilityReport unknown(Artifact from, Artifact to) {
        return new CompatibilityReport(from, to, CompatibilityStatus.UNKNOWN, List.of());
    }
}
