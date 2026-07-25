package org.crbf.plugin.adapter.out;

import org.crbf.application.port.out.ResolveArtifactPort;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.LocatedArtifact;
import org.crbf.domain.model.artifact.Scope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResult;
import org.eclipse.aether.repository.RemoteRepository;

import java.io.File;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

public class MavenRuntimeArtifactResolverAdapter implements ResolveArtifactPort {

    private static final Logger LOG = LoggerFactory.getLogger(MavenRuntimeArtifactResolverAdapter.class);

    private final RepositorySystem repoSystem;
    private final RepositorySystemSession repoSession;
    private final List<RemoteRepository> remoteRepositories;

    public MavenRuntimeArtifactResolverAdapter(RepositorySystem repoSystem,
                                               RepositorySystemSession repoSession,
                                               List<RemoteRepository> remoteRepositories) {
        this.repoSystem = repoSystem;
        this.repoSession = repoSession;
        this.remoteRepositories = remoteRepositories;
    }

    @Override
    public Optional<LocatedArtifact> resolve(String groupId, String artifactId, String version, String scope) {
        Artifact artifact = Artifact.create(groupId, artifactId, version, Scope.fromString(scope));
        try {
            org.eclipse.aether.artifact.Artifact aetherArtifact =
                    new DefaultArtifact(groupId, artifactId, "jar", version);

            ArtifactRequest request = new ArtifactRequest();
            request.setArtifact(aetherArtifact);
            request.setRepositories(remoteRepositories);

            ArtifactResult result = repoSystem.resolveArtifact(repoSession, request);

            File jarFile = result.getArtifact().getFile();
            if (jarFile == null) {
                LOG.warn("JAR file is null for {}:{}:{}", groupId, artifactId, version);
                return Optional.empty();
            }

            Path physicalPath = jarFile.toPath();
            return Optional.of(new LocatedArtifact(artifact, physicalPath));

        } catch (Exception e) {
            LOG.error("Could not resolve {}:{}:{}", groupId, artifactId, version);
            return Optional.empty();
        }
    }
}
