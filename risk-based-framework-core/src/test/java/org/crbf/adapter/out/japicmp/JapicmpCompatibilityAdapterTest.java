package org.crbf.adapter.out.japicmp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import javax.tools.ToolProvider;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.LocatedArtifact;
import org.crbf.domain.model.artifact.Scope;
import org.crbf.domain.model.compatibility.CompatibilityReport;
import org.crbf.domain.model.compatibility.CompatibilityStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class JapicmpCompatibilityAdapterTest {

    private static final Artifact CURRENT = Artifact.create("org.example", "library", "1.0.0", Scope.COMPILE);
    private static final Artifact CANDIDATE = Artifact.create("org.example", "library", "2.0.0", Scope.COMPILE);
    private final JapicmpCompatibilityAdapter adapter = new JapicmpCompatibilityAdapter();

    @TempDir
    Path directory;

    @Test
    void shouldClassifyAnAdditivePublicApiUpdateAsCompatible() throws IOException {
        Path oldJar = jar("old", "public String greet() { return \"hello\"; }");
        Path newJar = jar("new", "public String greet() { return \"hello\"; } public int count() { return 1; }");

        CompatibilityReport report = compare(oldJar, newJar);

        assertEquals(CompatibilityStatus.COMPATIBLE, report.status());
        assertEquals(List.of(), report.breakingChanges());
        assertEquals(CURRENT, report.fromVersion());
        assertEquals(CANDIDATE, report.toVersion());
    }

    @Test
    void shouldClassifyRemovedPublicMethodsAsBinaryIncompatible() throws IOException {
        Path oldJar = jar("old", "public String greet() { return \"hello\"; }");
        Path newJar = jar("new", "");

        CompatibilityReport report = compare(oldJar, newJar);

        assertEquals(CompatibilityStatus.BINARY_INCOMPATIBLE, report.status());
        assertTrue(report.breakingMethodIds().contains("fixture.Api#greet()"));
        assertTrue(report.breakingChanges().stream().anyMatch(change -> change.contains("METHOD_REMOVED")));
    }

    @Test
    void shouldClassifyGenericParameterChangesAsSourceIncompatible() throws IOException {
        Path oldJar = jar("old", "public void accept(java.util.List<String> values) {}");
        Path newJar = jar("new", "public void accept(java.util.List<Integer> values) {}");

        CompatibilityReport report = compare(oldJar, newJar);

        assertEquals(CompatibilityStatus.SOURCE_INCOMPATIBLE, report.status());
        assertTrue(report.breakingChanges().stream().anyMatch(change -> change.startsWith("[SOURCE]")));
    }

    @Test
    void shouldRetainBinaryIncompatibilityWhenGenericAndBinaryBreaksCoexist() throws IOException {
        Path oldJar = jar("old", "public void accept(java.util.List<String> values) {} public void greet() {}");
        Path newJar = jar("new", "public void accept(java.util.List<Integer> values) {}");

        CompatibilityReport report = compare(oldJar, newJar);

        assertEquals(CompatibilityStatus.BINARY_INCOMPATIBLE, report.status());
        assertTrue(report.breakingChanges().stream().anyMatch(change -> change.contains("METHOD_REMOVED")));
    }

    @Test
    void shouldClassifyAnAddedAbstractInterfaceMethodAsSourceIncompatible() throws IOException {
        Path oldJar = jarType("old", "public interface Api {}");
        Path newJar = jarType("new", "public interface Api { void greet(); }");

        CompatibilityReport report = compare(oldJar, newJar);

        assertEquals(CompatibilityStatus.SOURCE_INCOMPATIBLE, report.status());
        assertTrue(report.breakingChanges().stream().anyMatch(change -> change.startsWith("[SOURCE]")));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldReturnUnknownWhenEitherJarIsMissing(boolean missingCurrent) throws IOException {
        Path valid = jar("valid", "public void greet() {}");
        Path missing = directory.resolve("missing.jar");

        CompatibilityReport report = compare(missingCurrent ? missing : valid, missingCurrent ? valid : missing);

        assertEquals(CompatibilityStatus.UNKNOWN, report.status());
        assertEquals(List.of(), report.breakingChanges());
    }

    @Test
    void shouldReturnUnknownForAnInvalidJarInsteadOfClaimingCompatibility() throws IOException {
        Path valid = jar("valid", "public void greet() {}");
        Path invalid = Files.writeString(directory.resolve("invalid.jar"), "Not a ZIP archive");

        assertEquals(CompatibilityStatus.UNKNOWN, compare(valid, invalid).status());
    }

    @Test
    void shouldReturnUnknownWhenTheComparatorCannotReadAClassFile() throws IOException {
        Path valid = jar("valid", "public void greet() {}");
        Path corrupt = directory.resolve("corrupt-class.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(corrupt))) {
            output.putNextEntry(new JarEntry("fixture/Api.class"));
            output.write(new byte[] {0, 1, 2, 3});
            output.closeEntry();
        }

        assertEquals(CompatibilityStatus.UNKNOWN, compare(valid, corrupt).status());
    }

    private CompatibilityReport compare(Path current, Path candidate) {
        return adapter.detect(new LocatedArtifact(CURRENT, current), new LocatedArtifact(CANDIDATE, candidate));
    }

    private Path jar(String name, String members) throws IOException {
        return jarType(name, "public class Api { " + members + " }");
    }

    private Path jarType(String name, String declaration) throws IOException {
        Path workspace = Files.createDirectories(directory.resolve(name));
        Path source = workspace.resolve("Api.java");
        Files.writeString(source, "package fixture; " + declaration);
        int result = ToolProvider.getSystemJavaCompiler().run(null, null, null,
                "--release", "17", "-proc:none", "-d", workspace.toString(), source.toString());
        assertEquals(0, result, "Fixture source must compile successfully");
        Path jar = directory.resolve(name + ".jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            JarEntry entry = new JarEntry("fixture/Api.class");
            entry.setTime(0);
            output.putNextEntry(entry);
            Files.copy(workspace.resolve("fixture/Api.class"), output);
            output.closeEntry();
        }
        return jar;
    }
}
