package org.crbf.adapter.out.wala;

import static org.crbf.fixture.VulnerabilityFixture.vulnerability;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.LocatedArtifact;
import org.crbf.domain.model.artifact.Scope;
import org.crbf.domain.model.reachability.ProjectCallGraph;
import org.crbf.domain.model.reachability.ReachabilityStatus;
import org.crbf.domain.model.reachability.ReachableMethod;
import org.crbf.domain.model.reachability.VulnerabilityReachability;
import org.crbf.domain.model.vulnerability.Vulnerability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The call graph does not model {@code ServiceLoader}, so an artifact that is
 * only ever entered that way leaves no static trace. These tests pin the
 * verdict withheld in that case.
 */
class WalaServiceLoaderGuardTest {

    // Arbitrary values: the behaviour under test does not depend on severity.
    private static final double ANY_CVSS = 7.5;
    private static final double ANY_EPSS = 0.5;

    private final WalaReachabilityAdapter adapter = new WalaReachabilityAdapter();

    @Test
    void artifactRegisteringServiceProvidersShouldBeUnknownRatherThanUnreachable(@TempDir Path tempDir)
            throws Exception {

        Path jar = jarContaining(tempDir.resolve("with-providers.jar"),
                "META-INF/services/java.sql.Driver");

        assertEquals(ReachabilityStatus.UNKNOWN, statusFromCallGraphWithout(jar));
    }

    @Test
    void artifactWithoutServiceProvidersShouldStayUnreachable(@TempDir Path tempDir) throws Exception {
        Path jar = jarContaining(tempDir.resolve("no-providers.jar"),
                "com/example/Absent.class");

        assertEquals(ReachabilityStatus.UNREACHABLE, statusFromCallGraphWithout(jar));
    }

    /**
     * Analyses the artifact against a call graph that contains an unrelated
     * method, so the graph is non-empty but nothing in the artifact is reached.
     */
    private ReachabilityStatus statusFromCallGraphWithout(Path jar) {
        ProjectCallGraph callGraph = new ProjectCallGraph(
                java.util.Set.of(new ReachableMethod(
                        "org.other.Unrelated", "run", java.util.Optional.empty())));

        LocatedArtifact artifact = new LocatedArtifact(
                Artifact.create("com.example", "library", "1.0.0", Scope.COMPILE), jar);

        Vulnerability vulnerability = vulnerability("CVE-2026-0001", ANY_CVSS, ANY_EPSS);

        List<VulnerabilityReachability> reports =
                adapter.analyseReachability(callGraph, artifact, List.of(vulnerability));

        return reports.get(0).status();
    }

    private Path jarContaining(Path jarPath, String... entryNames) throws Exception {
        try (OutputStream out = Files.newOutputStream(jarPath);
                JarOutputStream jar = new JarOutputStream(out)) {
            for (String entryName : entryNames) {
                jar.putNextEntry(new ZipEntry(entryName));
                jar.write("placeholder".getBytes(StandardCharsets.UTF_8));
                jar.closeEntry();
            }
        }
        return jarPath;
    }
}
