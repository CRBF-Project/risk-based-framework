package org.crbf.adapter.out.wala;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import javax.tools.ToolProvider;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.LocatedArtifact;
import org.crbf.domain.model.artifact.Scope;
import org.crbf.domain.model.reachability.ProjectCallGraph;
import org.crbf.domain.model.reachability.ReachabilityStatus;
import org.crbf.domain.model.reachability.VulnerabilityReachability;
import org.crbf.domain.model.vulnerability.Vulnerability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** Exercises real 0-CFA construction against locally compiled Java fixtures. */
class WalaReachabilityAdapterTest {

    private final WalaReachabilityAdapter adapter = new WalaReachabilityAdapter();

    @TempDir
    Path directory;

    @ParameterizedTest
    @CsvSource({
            "fixture.library.VulnerableApi.execute();, REACHABLE_CONFIRMED",
            "fixture.library.SafeApi.execute();, REACHABLE_PROBABLE",
            "int value = 1;, UNREACHABLE"
    })
    void shouldClassifyVulnerabilityFromTheActualApplicationCallGraph(
            String applicationBody, ReachabilityStatus expected) throws IOException {
        LocatedArtifact library = library();
        ProjectCallGraph graph = applicationGraph(library, applicationBody);
        Vulnerability vulnerability = vulnerability("CVE-2026-1001", "VulnerableApi");

        List<VulnerabilityReachability> result = adapter.analyseReachability(
                graph, library, List.of(vulnerability));

        assertEquals(List.of(new Assessment("CVE-2026-1001", expected)), assessments(result));
    }

    @Test
    void shouldKeepClassificationsAssociatedWithEachVulnerabilityInTheSameLibrary() throws IOException {
        LocatedArtifact library = library();
        ProjectCallGraph graph = applicationGraph(library, "fixture.library.VulnerableApi.execute();");
        Vulnerability called = vulnerability("CVE-2026-1001", "VulnerableApi");
        Vulnerability notCalled = vulnerability("CVE-2026-1002", "SafeApi");

        List<VulnerabilityReachability> result = adapter.analyseReachability(
                graph, library, List.of(called, notCalled));

        assertEquals(List.of(
                new Assessment("CVE-2026-1001", ReachabilityStatus.REACHABLE_CONFIRMED),
                new Assessment("CVE-2026-1002", ReachabilityStatus.REACHABLE_PROBABLE)), assessments(result));
    }

    @Test
    void shouldClassifyEveryVulnerabilityAsUnknownWhenProjectClassesAreMissing() throws IOException {
        LocatedArtifact library = library();
        ProjectCallGraph graph = adapter.buildCallGraph(
                directory.resolve("missing-classes"), List.of(library.physicalJarPath()));

        List<VulnerabilityReachability> result = adapter.analyseReachability(graph, library, List.of(
                vulnerability("CVE-2026-1001", "VulnerableApi"),
                vulnerability("CVE-2026-1002", "SafeApi")));

        assertEquals(List.of(
                new Assessment("CVE-2026-1001", ReachabilityStatus.UNKNOWN),
                new Assessment("CVE-2026-1002", ReachabilityStatus.UNKNOWN)), assessments(result));
    }

    private LocatedArtifact library() throws IOException {
        Path sources = Files.createDirectories(directory.resolve("library-sources"));
        Path vulnerable = sources.resolve("VulnerableApi.java");
        Path safe = sources.resolve("SafeApi.java");
        Files.writeString(vulnerable, """
                package fixture.library;
                public class VulnerableApi {
                    public static int execute() { return 1; }
                }
                """);
        Files.writeString(safe, """
                package fixture.library;
                public class SafeApi {
                    public static int execute() { return 2; }
                }
                """);
        Path classes = Files.createDirectories(directory.resolve("library-classes"));
        compile(List.of("--release", "17", "-proc:none", "-d", classes.toString(),
                vulnerable.toString(), safe.toString()));
        Path jar = directory.resolve("library.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            for (String name : List.of("VulnerableApi", "SafeApi")) {
                String entryName = "fixture/library/" + name + ".class";
                JarEntry entry = new JarEntry(entryName);
                entry.setTime(0);
                output.putNextEntry(entry);
                Files.copy(classes.resolve(entryName), output);
                output.closeEntry();
            }
        }
        return new LocatedArtifact(Artifact.create("fixture", "library", "1.0.0", Scope.COMPILE), jar);
    }

    private ProjectCallGraph applicationGraph(LocatedArtifact library, String body) throws IOException {
        Path source = directory.resolve("Main.java");
        Files.writeString(source, """
                package fixture.application;
                public class Main {
                    public static void main(String[] args) { %s }
                }
                """.formatted(body));
        Path classes = Files.createDirectories(directory.resolve("application-classes"));
        compile(List.of("--release", "17", "-proc:none", "-classpath", library.physicalJarPath().toString(),
                "-d", classes.toString(), source.toString()));
        ProjectCallGraph graph = adapter.buildCallGraph(classes, List.of(library.physicalJarPath()));
        assertFalse(graph.isEmpty(), "The real WALA graph must be available for classification");
        return graph;
    }

    private void compile(List<String> arguments) {
        int exitCode = ToolProvider.getSystemJavaCompiler().run(null, null, null, arguments.toArray(String[]::new));
        assertEquals(0, exitCode, "Fixture sources must compile successfully");
    }

    private Vulnerability vulnerability(String id, String className) {
        return Vulnerability.create(id, 8, "TEST_VECTOR", Optional.empty(), Optional.empty(), List.of(),
                "Issue in " + className + "#execute()", "Synthetic advisory for the local fixture.",
                List.of(), Optional.empty(), Optional.empty(), "", "");
    }

    private List<Assessment> assessments(List<VulnerabilityReachability> result) {
        return result.stream().map(r -> new Assessment(r.vulnerability().id().value(), r.status())).toList();
    }

    private record Assessment(String vulnerabilityId, ReachabilityStatus status) {}
}
