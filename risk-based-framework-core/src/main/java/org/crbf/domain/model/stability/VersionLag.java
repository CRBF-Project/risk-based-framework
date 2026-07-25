package org.crbf.domain.model.stability;

public record VersionLag(int value) {
    public VersionLag {
        if (value < 0) {
            throw new IllegalArgumentException(
                "The Version Lag (release delay) cannot be negative. Received value: " + value
            );
        }
    }
}