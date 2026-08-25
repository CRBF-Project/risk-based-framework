package org.crbf.plugin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;

import org.apache.maven.shared.dependency.graph.DependencyNode;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.DependencyPath;
import org.crbf.domain.model.artifact.Scope;
import org.junit.Test;

/**
 * Unit tests for FR1's extraction logic (Tier 1 of the FR1 acceptance
 * criteria).
 * <p>
 * These tests exercise only {@link MavenDependencyGraphResolver#flatten}
 * and {@link MavenDependencyGraphResolver#toArtifact} against mocked
 * {@link DependencyNode} trees. They verify that <b>our</b> flattening and
 * mapping code is correct — not that Maven's own dependency resolution
 * (conflict handling, version selection) is correct, which is Maven's
 * responsibility and out of scope for this project. A mocked tree can never
 * disagree with the code under test about what Maven "would" resolve; the
 * real-resolution claim is instead covered by the Tier 2 integration test
 * (against a vendored local repository via {@code AbstractMojoTestCase}).
 */
public class MavenDependencyGraphResolverTest {

    @Test
    public void linearChain_producesOnePathPerNodeExcludingRoot() {
        DependencyNode b = node("b", "compile");
        DependencyNode a = node("a", "compile", b);
        DependencyNode root = node("root", "compile", a);

        List<DependencyPath> paths = MavenDependencyGraphResolver.flatten(root);

        // Structural equality (DependencyPath is a record) rather than
        // string-matching toString() output: this must fail only if the
        // extracted lineage is wrong, never because someone reformatted how
        // a path prints. Comparing the whole list also makes the size (2)
        // implicit instead of a bare literal.
        assertEquals(
                List.of(
                        new DependencyPath(List.of(artifact("root"), artifact("a"))),
                        new DependencyPath(List.of(artifact("root"), artifact("a"), artifact("b")))),
                paths);
    }

    @Test
    public void branchingTree_pathsDoNotLeakBetweenSiblings() {
        DependencyNode c = node("c", "compile");
        DependencyNode a = node("a", "compile", c);
        DependencyNode b = node("b", "compile");
        DependencyNode root = node("root", "compile", a, b);

        List<DependencyPath> paths = MavenDependencyGraphResolver.flatten(root);

        // b's path must not carry over a's descendant (c) — this guards the
        // defensive `new ArrayList<>(currentPath)` copy in traverseAllPaths
        // against a future change that reintroduces shared mutable state
        // between sibling branches. Asserting the full expected list proves
        // this on its own: if c leaked into b's path, this equality fails.
        assertEquals(
                List.of(
                        new DependencyPath(List.of(artifact("root"), artifact("a"))),
                        new DependencyPath(List.of(artifact("root"), artifact("a"), artifact("c"))),
                        new DependencyPath(List.of(artifact("root"), artifact("b")))),
                paths);
    }

    @Test
    public void rootWithNoChildren_producesNoPaths() {
        DependencyNode root = node("root", "compile");

        assertTrue(MavenDependencyGraphResolver.flatten(root).isEmpty());
    }

    @Test
    public void toArtifact_preservesEveryDeclaredScope() {
        assertEquals("'compile' scope", Scope.COMPILE, scopeOf("compile"));
        assertEquals("'TEST' scope (case-insensitive)", Scope.TEST, scopeOf("TEST"));
        assertEquals("'provided' scope", Scope.PROVIDED, scopeOf("provided"));
        assertEquals("'runtime' scope", Scope.RUNTIME, scopeOf("runtime"));
        assertEquals("'system' scope", Scope.SYSTEM, scopeOf("system"));
    }

    @Test
    public void toArtifact_defaultsMissingScopeToCompile() {
        assertEquals("null scope", Scope.COMPILE, scopeOf(null));
        assertEquals("empty-string scope", Scope.COMPILE, scopeOf(""));
        assertEquals("blank (whitespace-only) scope", Scope.COMPILE, scopeOf("   "));
    }

    @Test
    public void toArtifact_mapsUnrecognisedScopeToUnknownRatherThanFailing() {
        assertEquals(Scope.UNKNOWN, scopeOf("not-a-real-scope"));
    }

    @Test
    public void toArtifact_preservesGroupArtifactAndVersion() {
        org.apache.maven.artifact.Artifact mvnArtifact = mock(org.apache.maven.artifact.Artifact.class);
        when(mvnArtifact.getGroupId()).thenReturn("com.example.group");
        when(mvnArtifact.getArtifactId()).thenReturn("some-lib");
        when(mvnArtifact.getVersion()).thenReturn("2.3.4");
        when(mvnArtifact.getScope()).thenReturn("compile");

        var artifact = MavenDependencyGraphResolver.toArtifact(mvnArtifact);

        assertEquals("com.example.group:some-lib:2.3.4", artifact.gav());
    }

    // --- fixtures ---------------------------------------------------------

    private static DependencyNode node(String artifactId, String scope, DependencyNode... children) {
        org.apache.maven.artifact.Artifact mvnArtifact = mock(org.apache.maven.artifact.Artifact.class);
        when(mvnArtifact.getGroupId()).thenReturn("org.example");
        when(mvnArtifact.getArtifactId()).thenReturn(artifactId);
        when(mvnArtifact.getVersion()).thenReturn("1.0");
        when(mvnArtifact.getScope()).thenReturn(scope);

        DependencyNode dependencyNode = mock(DependencyNode.class);
        when(dependencyNode.getArtifact()).thenReturn(mvnArtifact);
        when(dependencyNode.getChildren()).thenReturn(List.of(children));
        return dependencyNode;
    }

    /** The {@link Artifact} a {@code node(artifactId, "compile", ...)} maps to. */
    private static Artifact artifact(String artifactId) {
        return Artifact.create("org.example", artifactId, "1.0", Scope.COMPILE);
    }

    private static Scope scopeOf(String rawScope) {
        org.apache.maven.artifact.Artifact mvnArtifact = mock(org.apache.maven.artifact.Artifact.class);
        when(mvnArtifact.getGroupId()).thenReturn("org.example");
        when(mvnArtifact.getArtifactId()).thenReturn("a");
        when(mvnArtifact.getVersion()).thenReturn("1.0");
        when(mvnArtifact.getScope()).thenReturn(rawScope);
        return MavenDependencyGraphResolver.toArtifact(mvnArtifact).scope();
    }
}
