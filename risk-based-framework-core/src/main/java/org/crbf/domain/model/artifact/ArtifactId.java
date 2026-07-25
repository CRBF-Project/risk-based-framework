package org.crbf.domain.model.artifact;

import java.util.regex.Pattern;

public record ArtifactId(String value) {

    private static final Pattern VALID_FORMAT = Pattern.compile("^[a-zA-Z0-9_.-]+$");

    public ArtifactId {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("The ArtifactId cannot be null or empty.");
        }

        value = value.trim();

        if (!VALID_FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("The ArtifactId contains invalid characters: " + value);
        }
    }
}