package org.crbf.domain.model.artifact;

import java.util.Objects;

import org.apache.maven.artifact.versioning.ComparableVersion;

public record Version(String value) implements Comparable<Version> {

    public Version {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("The version cannot be null or empty.");
        }
        value = value.trim();
    }

    @Override
    public int compareTo(Version other) {
        return new ComparableVersion(this.value)
                .compareTo(new ComparableVersion(other.value));
    }

    public boolean isOlderThan(Version other) {
        return compareTo(other) < 0;
    }

    public boolean isNewerThan(Version other) {
        return compareTo(other) > 0;
    }

    public boolean isNewerThanOrEqual(Version other) {
        return compareTo(other) >= 0;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof Version other))
            return false;
        return compareTo(other) == 0;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(new ComparableVersion(value).toString());
    }
}
