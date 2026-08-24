package org.crbf.plugin.adapter.out;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.apache.maven.shared.dependency.graph.DependencyNode;
import org.crbf.domain.model.artifact.DependencyPath;
import org.crbf.domain.model.artifact.Scope;
import org.junit.Test;

/**
 * Unit tests for FR1's extraction logic (Tier 1 of the FR1 acceptance
 * criteria).
 * <p>
 * These tests exercise only {@link MavenDependencyGraphResolver#traverseAllPaths}
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

        List<DependencyPath> paths = traverse(root);

        assertEquals(2, paths.size());
        assertEquals("org.example:root:1.0 -> org.example:a:1.0", paths.get(0).toString());
        assertEquals("org.example:root:1.0 -> org.example:a:1.0 -> org.example:b:1.0", paths.get(1).toString());
    }

    @Test
    public void branchingTree_pathsDoNotLeakBetweenSiblings() {
        // root
        // |- a
        // |   `- c
        // `- b
        DependencyNode c = node("c", "compile");
        DependencyNode a = node("a", "compile", c);
        DependencyNode b = node("b", "compile");
        DependencyNode root = node("root", "compile", a, b);

        List<DependencyPath> paths = traverse(root);

        assertEquals(3, paths.size());
        assertEquals("org.example:root:1.0 -> org.example:a:1.0", paths.get(0).toString());
        assertEquals("org.example:root:1.0 -> org.example:a:1.0 -> org.example:c:1.0", paths.get(1).toString());
        assertEquals("org.example:root:1.0 -> org.example:b:1.0", paths.get(2).toString());

        // b's path must not carry over a's descendant (c). This guards the
        // defensive `new ArrayList<>(currentPath)` copy in traverseAllPaths
        // against a future change that reintroduces shared mutable state
        // between sibling branches.
        assertTrue(paths.get(2).path().stream()
                .noneMatch(artifact -> artifact.artifactId().value().equals("c")));
    }

    @Test
    public void rootWithNoChildren_producesNoPaths() {
        DependencyNode root = node("root", "compile");

        assertTrue(traverse(root).isEmpty());
    }

    @Test
    public void toArtifact_preservesEveryDeclaredScope() {
        assertEquals(Scope.COMPILE, scopeOf("compile"));
        assertEquals(Scope.TEST, scopeOf("TEST"));
        assertEquals(Scope.PROVIDED, scopeOf("provided"));
        assertEquals(Scope.RUNTIME, scopeOf("runtime"));
        assertEquals(Scope.SYSTEM, scopeOf("system"));
    }

    @Test
    public void toArtifact_defaultsMissingScopeToCompile() {
        assertEquals(Scope.COMPILE, scopeOf(null));
        assertEquals(Scope.COMPILE, scopeOf(""));
        assertEquals(Scope.COMPILE, scopeOf("   "));
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

    private static Scope scopeOf(String rawScope) {
        org.apache.maven.artifact.Artifact mvnArtifact = mock(org.apache.maven.artifact.Artifact.class);
        when(mvnArtifact.getGroupId()).thenReturn("org.example");
        when(mvnArtifact.getArtifactId()).thenReturn("a");
        when(mvnArtifact.getVersion()).thenReturn("1.0");
        when(mvnArtifact.getScope()).thenReturn(rawScope);
        return MavenDependencyGraphResolver.toArtifact(mvnArtifact).scope();
    }

    private static List<DependencyPath> traverse(DependencyNode root) {
        List<DependencyPath> paths = new ArrayList<>();
        MavenDependencyGraphResolver.traverseAllPaths(root, new ArrayList<>(), paths);
        return paths;
    }
}
