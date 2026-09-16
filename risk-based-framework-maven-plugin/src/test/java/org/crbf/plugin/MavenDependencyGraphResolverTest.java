package org.crbf.plugin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;

import org.apache.maven.project.ProjectBuildingRequest;
import org.apache.maven.shared.dependency.graph.DependencyGraphBuilder;
import org.apache.maven.shared.dependency.graph.DependencyGraphBuilderException;
import org.apache.maven.shared.dependency.graph.DependencyNode;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.DependencyPath;
import org.crbf.domain.model.artifact.Scope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for dependency paths extraction logic.
 * <p>
 * These tests exercise only {@link MavenDependencyGraphResolver#flatten}
 * and {@link MavenDependencyGraphResolver#toArtifact} against mocked
 * {@link DependencyNode} trees.
 */
class MavenDependencyGraphResolverTest {

    @Test
    @DisplayName("A linear chain of dependencies produces one path per node, excluding the root")
    void flatten_producesOnePathPerNodeExcludingRoot() {
        DependencyNode b = node("b", "compile");
        DependencyNode a = node("a", "compile", b);
        DependencyNode root = node("root", "compile", a);

        List<DependencyPath> paths = MavenDependencyGraphResolver.flatten(root);

        assertEquals(
                List.of(
                        new DependencyPath(List.of(artifact("root"), artifact("a"))),
                        new DependencyPath(List.of(artifact("root"), artifact("a"), artifact("b")))),
                paths);
    }

    @Test
    @DisplayName("A branching tree does not leak paths between sibling subtrees")
    void flatten_branchingTreeDoesNotLeakPathsBetweenSiblings() {
        DependencyNode c = node("c", "compile");
        DependencyNode a = node("a", "compile", c);
        DependencyNode b = node("b", "compile");
        DependencyNode root = node("root", "compile", a, b);

        List<DependencyPath> paths = MavenDependencyGraphResolver.flatten(root);

        assertEquals(
                List.of(
                        new DependencyPath(List.of(artifact("root"), artifact("a"))),
                        new DependencyPath(List.of(artifact("root"), artifact("a"), artifact("c"))),
                        new DependencyPath(List.of(artifact("root"), artifact("b")))),
                paths);
    }

    @Test
    @DisplayName("A root with no children produces no paths")
    void flatten_rootWithNoChildrenProducesNoPaths() {
        DependencyNode root = node("root", "compile");

        assertTrue(MavenDependencyGraphResolver.flatten(root).isEmpty());
    }

    @Test
    @DisplayName("resolve builds the graph via the injected builder and flattens the result")
    void resolve_flattensTheBuiltDependencyGraph() throws DependencyGraphBuilderException {
        DependencyGraphBuilder dependencyGraphBuilder = mock(DependencyGraphBuilder.class);
        ProjectBuildingRequest buildingRequest = mock(ProjectBuildingRequest.class);
        DependencyNode root = node("root", "compile", node("a", "compile"));
        when(dependencyGraphBuilder.buildDependencyGraph(buildingRequest, null)).thenReturn(root);

        List<DependencyPath> paths = new MavenDependencyGraphResolver(dependencyGraphBuilder).resolve(buildingRequest);

        assertEquals(MavenDependencyGraphResolver.flatten(root), paths);
    }

    @ParameterizedTest(name = "\"{0}\" scope maps to {1}")
    @DisplayName("toArtifact preserves every declared scope")
    @CsvSource({
            "compile, COMPILE",
            "TEST, TEST",
            "provided, PROVIDED",
            "runtime, RUNTIME",
            "system, SYSTEM"
    })
    void toArtifact_preservesEveryDeclaredScope(String rawScope, Scope expectedScope) {
        assertEquals(expectedScope, scopeOf(rawScope));
    }

    @ParameterizedTest(name = "[{index}] scope \"{0}\" defaults to COMPILE")
    @DisplayName("toArtifact defaults a missing scope to COMPILE")
    @NullSource
    @ValueSource(strings = {"", "   "})
    void toArtifact_defaultsMissingScopeToCompile(String rawScope) {
        assertEquals(Scope.COMPILE, scopeOf(rawScope));
    }

    @Test
    @DisplayName("toArtifact maps an unrecognised scope to UNKNOWN rather than failing")
    void toArtifact_mapsUnrecognisedScopeToUnknownRatherThanFailing() {
        assertEquals(Scope.UNKNOWN, scopeOf("not-a-real-scope"));
    }

    @Test
    @DisplayName("toArtifact preserves the group, artifact and version")
    void toArtifact_preservesGroupArtifactAndVersion() {
        org.apache.maven.artifact.Artifact mvnArtifact = mock(org.apache.maven.artifact.Artifact.class);
        when(mvnArtifact.getGroupId()).thenReturn("com.example.group");
        when(mvnArtifact.getArtifactId()).thenReturn("some-lib");
        when(mvnArtifact.getVersion()).thenReturn("2.3.4");
        when(mvnArtifact.getScope()).thenReturn("compile");

        var artifact = MavenDependencyGraphResolver.toArtifact(mvnArtifact);

        assertEquals("com.example.group:some-lib:2.3.4", artifact.gav());
    }

    // --- fixtures ---------------------------------------------------------

    private static final String GROUP_ID = "org.example";
    private static final String VERSION = "1.0";

    private static DependencyNode node(String artifactId, String scope, DependencyNode... children) {
        org.apache.maven.artifact.Artifact mvnArtifact = mock(org.apache.maven.artifact.Artifact.class);
        when(mvnArtifact.getGroupId()).thenReturn(GROUP_ID);
        when(mvnArtifact.getArtifactId()).thenReturn(artifactId);
        when(mvnArtifact.getVersion()).thenReturn(VERSION);
        when(mvnArtifact.getScope()).thenReturn(scope);

        DependencyNode dependencyNode = mock(DependencyNode.class);
        when(dependencyNode.getArtifact()).thenReturn(mvnArtifact);
        when(dependencyNode.getChildren()).thenReturn(List.of(children));
        return dependencyNode;
    }

    /** The {@link Artifact} a {@code node(artifactId, "compile", ...)} maps to. */
    private static Artifact artifact(String artifactId) {
        return Artifact.create(GROUP_ID, artifactId, VERSION, Scope.COMPILE);
    }

    private static Scope scopeOf(String rawScope) {
        org.apache.maven.artifact.Artifact mvnArtifact = mock(org.apache.maven.artifact.Artifact.class);
        when(mvnArtifact.getGroupId()).thenReturn(GROUP_ID);
        when(mvnArtifact.getArtifactId()).thenReturn("a");
        when(mvnArtifact.getVersion()).thenReturn(VERSION);
        when(mvnArtifact.getScope()).thenReturn(rawScope);
        return MavenDependencyGraphResolver.toArtifact(mvnArtifact).scope();
    }
}
