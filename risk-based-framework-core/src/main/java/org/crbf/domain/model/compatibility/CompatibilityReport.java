package org.crbf.domain.model.compatibility;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.reachability.ProjectCallGraph;
import java.util.regex.Pattern;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Value Object that represents the result of a binary compatibility
 * analysis between two versions of the same {@link Artifact}.
 * The original status is immutable; contextualStatus is a separate effort heuristic.
 *
 * The "breakingChanges" list contains descriptions of each
 * individual API change detected by japicmp (e.g. "Method removed:
 * org.apache.commons.lang3.StringUtils#isEmpty(String)").
 */
public record CompatibilityReport(
        Artifact fromVersion,
        Artifact toVersion,
        CompatibilityStatus status,
        List<String> breakingChanges,
        CompatibilityStatus contextualStatus) {
    private static final Pattern MAPPABLE_CHANGE = Pattern.compile(
            "^\\[(?:BINARY|SOURCE)\\] (?:Method [^\\s#]+#[^\\s(]+\\([^)]*\\)"
                    + "|Constructor [^\\s#]+#<init>(?:\\([^)]*\\))?) — \\S.*$");

    public CompatibilityReport(Artifact fromVersion, Artifact toVersion, CompatibilityStatus status,
            List<String> breakingChanges) {
        this(fromVersion, toVersion, status, breakingChanges,
                status == CompatibilityStatus.BINARY_INCOMPATIBLE ? CompatibilityStatus.UNKNOWN : status);
    }

    public CompatibilityReport {
        if (fromVersion == null || toVersion == null) {
            throw new IllegalArgumentException("Both artifact versions must be provided.");
        }
        if (status == null) {
            throw new IllegalArgumentException("CompatibilityStatus cannot be null.");
        }
        if (contextualStatus == null) {
            throw new IllegalArgumentException("Contextual compatibility cannot be null.");
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
     * Only recognised method and constructor changes can be mapped to the call graph.
     */
    public Set<String> breakingMethodIds() {
        return breakingChanges.stream()
                .filter(change -> MAPPABLE_CHANGE.matcher(change).matches())
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

    /** Contextual effort heuristic; the original japicmp status is never overwritten. */
    public CompatibilityReport contextualise(ProjectCallGraph callGraph) {
        if (status != CompatibilityStatus.BINARY_INCOMPATIBLE) return this;
        CompatibilityStatus contextual = CompatibilityStatus.UNKNOWN;
        if (!callGraph.isEmpty() && !breakingChanges.isEmpty()) {
            boolean affectedUsage = breakingMethodIds().stream().anyMatch(callGraph::containsMethodId);
            if (affectedUsage) {
                contextual = CompatibilityStatus.BINARY_INCOMPATIBLE;
            } else if (breakingChanges.stream().allMatch(change -> MAPPABLE_CHANGE.matcher(change).matches())) {
                contextual = CompatibilityStatus.COMPATIBLE;
            }
        }
        return new CompatibilityReport(fromVersion, toVersion, status, breakingChanges, contextual);
    }

    /** Unknown contextual impact retains the original effort category. */
    public CompatibilityStatus effortStatus() {
        return status == CompatibilityStatus.BINARY_INCOMPATIBLE
                && contextualStatus == CompatibilityStatus.COMPATIBLE ? CompatibilityStatus.COMPATIBLE : status;
    }

    public static CompatibilityReport compatible(Artifact from, Artifact to) {
        return new CompatibilityReport(from, to, CompatibilityStatus.COMPATIBLE, List.of());
    }

    public static CompatibilityReport unknown(Artifact from, Artifact to) {
        return new CompatibilityReport(from, to, CompatibilityStatus.UNKNOWN, List.of());
    }
}
