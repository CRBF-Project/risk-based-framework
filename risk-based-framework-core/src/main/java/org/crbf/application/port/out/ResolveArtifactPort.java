package org.crbf.application.port.out;

import org.crbf.domain.model.artifact.LocatedArtifact;

import java.util.Optional;

public interface ResolveArtifactPort {
    /**
     * Resolves an artifact by GAV coordinates and locates its JAR on the local
     * filesystem. Returns {@code Optional.empty()} if the JAR cannot be found
     * or downloaded.
     */
    Optional<LocatedArtifact> resolve(String groupId, String artifactId, String version, String scope);
}
