package org.crbf.domain.model.reachability;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Value object representing the pre-built call graph of the project under
 * analysis.
 *
 * Stores typed reachable methods and derives string identifiers only at
 * boundaries where textual payloads are still expected.
 *
 * Build this once per analysis run via
 * {@link org.contextframework.application.port.out.AnalyseReachabilityPort#buildCallGraph}
 * and reuse it for every vulnerable artifact.
 */
public record ProjectCallGraph(Set<ReachableMethod> reachableMethods) {

    public ProjectCallGraph {
        reachableMethods = reachableMethods == null ? Set.of() : Set.copyOf(reachableMethods);
    }

    public static ProjectCallGraph empty() {
        return new ProjectCallGraph(Set.of());
    }

    public boolean isEmpty() {
        return reachableMethods.isEmpty();
    }

    public Set<String> reachableMethodIds() {
        return reachableMethods.stream()
                .map(ReachableMethod::toString)
                .collect(Collectors.toUnmodifiableSet());
    }

    public Set<ReachableClass> reachableClasses() {
        return reachableMethods.stream()
                .map(m -> ReachableClass.of(m.container()))
                .collect(Collectors.toUnmodifiableSet());
    }

    /**
     * Returns true if any reachable method matches the given identifier.
     *
     * Format: "org.Class#methodName(Param1, Param2)" or "org.Class#methodName".
     *
     * Signature matching is exact when both sides have signature data.
     * If Optional.empty(), the method
     * is conservatively treated as reachable to avoid false downgrades.
     */
    public boolean containsMethodId(String classAndMethod) {
        int hash = classAndMethod.indexOf('#');
        if (hash < 0)
            return false;
        String container = classAndMethod.substring(0, hash);
        String afterHash = classAndMethod.substring(hash + 1);
        int paren = afterHash.indexOf('(');
        String name = paren > 0 ? afterHash.substring(0, paren) : afterHash;
        String sig = paren > 0 ? afterHash.substring(paren) : null;

        return reachableMethods.stream().anyMatch(m -> m.container().equals(container)
                && m.name().equals(name)
                && (sig == null
                        || m.signature().isEmpty()
                        || m.signature().filter(s -> s.equals(sig)).isPresent()));
    }
}
