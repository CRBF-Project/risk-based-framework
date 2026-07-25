package org.crbf.domain.model.artifact;

import java.nio.file.Path;
import java.util.Objects;

/**
 * An {@link Artifact} whose JAR has been physically located on the local filesystem.
 * Produced by {@link org.contextframework.application.port.out.ResolveArtifactPort}.
 *
 * Both fields are guaranteed non-null — resolution failure is expressed as
 * {@code Optional.empty()} at the port boundary, never as a null path here.
 */
public record LocatedArtifact(Artifact artifact, Path physicalJarPath) {

    public LocatedArtifact {
        Objects.requireNonNull(artifact, "artifact cannot be null");
        Objects.requireNonNull(physicalJarPath, "physicalJarPath cannot be null — use Optional.empty() to signal resolution failure");
    }

    public String gav() { return artifact.gav(); }
    public GroupId groupId() { return artifact.groupId(); }
    public ArtifactId artifactId() { return artifact.artifactId(); }
    public Version version() { return artifact.version(); }
    public Scope scope() { return artifact.scope(); }
}
