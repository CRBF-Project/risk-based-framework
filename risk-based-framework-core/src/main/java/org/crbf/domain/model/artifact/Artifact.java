package org.crbf.domain.model.artifact;

import java.util.Objects;

public record Artifact(
        GroupId groupId,
        ArtifactId artifactId,
        Version version,
        Scope scope) {

    public Artifact {
        Objects.requireNonNull(groupId, "GroupId cannot be null");
        Objects.requireNonNull(artifactId, "ArtifactId cannot be null");
        Objects.requireNonNull(version, "Version cannot be null");
        Objects.requireNonNull(scope, "Scope cannot be null");
    }

    public String gav() {
        return groupId.value() + ":" + artifactId.value() + ":" + version.value();
    }

    public String ga() {
        return groupId.value() + ":" + artifactId.value();
    }

    public static Artifact create(
            String groupId, String artifactId,
            String version, Scope scope) {
        return new Artifact(
                new GroupId(groupId),
                new ArtifactId(artifactId),
                new Version(version),
                scope);
    }
}
