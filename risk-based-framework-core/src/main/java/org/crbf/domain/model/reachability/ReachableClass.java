package org.crbf.domain.model.reachability;

import java.util.Objects;

/**
 * Value Object representing a reachable class in the project call graph.
 */
public record ReachableClass(String identifier) {

    public ReachableClass {
        Objects.requireNonNull(identifier, "Identifier cannot be null");
        identifier = identifier.trim();
        if (identifier.isBlank()) {
            throw new IllegalArgumentException("Identifier cannot be blank");
        }
    }

    public static ReachableClass of(String identifier) {
        return new ReachableClass(identifier);
    }

    public boolean belongsToNamespace(String namespacePrefix) {
        if (namespacePrefix == null || namespacePrefix.isBlank()) {
            return false;
        }

        String normalizedPrefix = namespacePrefix.trim();
        if (!identifier.startsWith(normalizedPrefix)) {
            return false;
        }

        if (identifier.length() == normalizedPrefix.length()) {
            return true;
        }

        char next = identifier.charAt(normalizedPrefix.length());
        return !Character.isLetterOrDigit(next);
    }
}