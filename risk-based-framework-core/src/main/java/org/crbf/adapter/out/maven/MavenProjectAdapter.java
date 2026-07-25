package org.crbf.adapter.out.maven;

import org.apache.maven.repository.internal.MavenRepositorySystemUtils;
import org.crbf.application.port.out.ResolveArtifactPort;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.LocatedArtifact;
import org.crbf.domain.model.artifact.Scope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.LocalRepository;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.supplier.RepositorySystemSupplier;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResolutionException;
import org.eclipse.aether.resolution.ArtifactResult;

import java.util.Optional;

public class MavenProjectAdapter implements ResolveArtifactPort {

    private static final Logger LOG = LoggerFactory.getLogger(MavenProjectAdapter.class);

    @Override
    public Optional<LocatedArtifact> resolve(String groupId, String artifactId, String version, String scope) {
        Artifact artifact = Artifact.create(groupId, artifactId, version, Scope.fromString(scope));
        RepositorySystem system = new RepositorySystemSupplier().get();
        DefaultRepositorySystemSession session = MavenRepositorySystemUtils.newSession();

        LocalRepository localRepo = new LocalRepository(System.getProperty("user.home") + "/.m2/repository");
        session.setLocalRepositoryManager(system.newLocalRepositoryManager(session, localRepo));

        org.eclipse.aether.artifact.Artifact aetherArtifact = new DefaultArtifact(
                groupId, artifactId, "jar", version);

        ArtifactRequest request = new ArtifactRequest();
        request.setArtifact(aetherArtifact);
        request.addRepository(
                new RemoteRepository.Builder("central", "default", "https://repo.maven.apache.org/maven2/").build());

        try {
            ArtifactResult result = system.resolveArtifact(session, request);

            java.io.File jarFile = result.getArtifact().getFile();
            if (jarFile == null) {
                LOG.warn("JAR file is null for {}:{}:{}", groupId, artifactId, version);
                return Optional.empty();
            }

            LOG.debug("Resolved {}:{}:{} at {}", groupId, artifactId, version, jarFile);
            return Optional.of(new LocatedArtifact(artifact, jarFile.toPath()));

        } catch (ArtifactResolutionException e) {
            LOG.error("Failed to resolve {}:{}:{}: {}", groupId, artifactId, version, e.getMessage());
            return Optional.empty();
        }
    }

   
    
}