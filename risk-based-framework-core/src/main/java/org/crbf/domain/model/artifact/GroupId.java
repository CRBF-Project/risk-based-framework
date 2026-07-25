package org.crbf.domain.model.artifact;

import java.util.regex.Pattern;

public record GroupId(String value) {

    private static final Pattern VALID_FORMAT = Pattern.compile("^[a-zA-Z0-9_.-]+$");

    public GroupId {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("The GroupId cannot be null or empty.");
        }

        value = value.trim();

        if (!VALID_FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("The GroupId contains invalid characters: " + value);
        }
    }
}
