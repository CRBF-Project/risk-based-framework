package org.crbf.domain.model.reachability;

import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Value Object representing a reachable method in the project call graph.
 */
public record ReachableMethod(
        String container,
        String name,
        Optional<String> signature
) {

    public ReachableMethod {
        Objects.requireNonNull(container, "Container cannot be null");
        Objects.requireNonNull(name, "Name cannot be null");

        container = container.trim();
        name = name.trim();
        signature = signature == null ? Optional.empty() : signature.map(String::trim).filter(s -> !s.isBlank());

        if (container.isBlank()) {
            throw new IllegalArgumentException("Container cannot be blank");
        }
        if (name.isBlank()) {
            throw new IllegalArgumentException("Name cannot be blank");
        }
    }

    public static ReachableMethod of(String container, String name) {
        return new ReachableMethod(container, name, Optional.empty());
    }

    public static ReachableMethod of(String container, String name, Optional<String> signature) {
        return new ReachableMethod(container, name, signature);
    }

    public static ReachableMethod parse(String identifier) {
        Objects.requireNonNull(identifier, "Method identifier cannot be null");
        int hash = identifier.indexOf('#');
        if (hash <= 0 || hash >= identifier.length() - 1) {
            throw new IllegalArgumentException(
                    "Invalid method identifier format. Expected 'class#method': " + identifier);
        }

        String parsedName = identifier.substring(hash + 1);
        Optional<String> parsedSignature = Optional.empty();
        int signatureStart = parsedName.indexOf('(');

        if (signatureStart > 0 && parsedName.endsWith(")")) {
            parsedSignature = Optional.of(parsedName.substring(signatureStart));
            parsedName = parsedName.substring(0, signatureStart);
        }

        return new ReachableMethod(
                identifier.substring(0, hash),
                parsedName,
                parsedSignature);
    }

    @Override
    public String toString() {
        return container + "#" + name + signature.orElse("");
    }

    public boolean belongsToNamespace(String namespacePrefix) {
        if (namespacePrefix == null || namespacePrefix.isBlank()) {
            return false;
        }

        String normalizedPrefix = namespacePrefix.trim();
        if (!container.startsWith(normalizedPrefix)) {
            return false;
        }

        if (container.length() == normalizedPrefix.length()) {
            return true;
        }

        char next = container.charAt(normalizedPrefix.length());
        return !Character.isLetterOrDigit(next);
    }

    public boolean belongsToNamespace(Set<String> namespacePrefixes) {
        if (namespacePrefixes == null || namespacePrefixes.isEmpty()) {
            return false;
        }
        return namespacePrefixes.stream().anyMatch(this::belongsToNamespace);
    }
}