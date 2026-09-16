package org.crbf.plugin;

import java.util.ArrayList;
import java.util.List;

import org.apache.maven.project.ProjectBuildingRequest;
import org.apache.maven.shared.dependency.graph.DependencyGraphBuilder;
import org.apache.maven.shared.dependency.graph.DependencyGraphBuilderException;
import org.apache.maven.shared.dependency.graph.DependencyNode;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.DependencyPath;
import org.crbf.domain.model.artifact.Scope;

/**
 * Resolves a Maven project's full transitive dependency graph (via the
 * injected {@link DependencyGraphBuilder}) and flattens it into root-to-node
 * {@link DependencyPath} entries.
 */
public class MavenDependencyGraphResolver {

    private final DependencyGraphBuilder dependencyGraphBuilder;

    public MavenDependencyGraphResolver(DependencyGraphBuilder dependencyGraphBuilder) {
        this.dependencyGraphBuilder = dependencyGraphBuilder;
    }

    /**
     * Builds the full dependency graph for the given project and flattens it
     * into one {@link DependencyPath} per non-root node, each listing the
     * complete lineage from the project root to that node.
     *
     * @throws DependencyGraphBuilderException if the graph cannot be built,
     *                                          e.g. due to unresolved
     *                                          dependencies.
     */
    public List<DependencyPath> resolve(ProjectBuildingRequest buildingRequest)
            throws DependencyGraphBuilderException {
        DependencyNode rootNode = dependencyGraphBuilder.buildDependencyGraph(buildingRequest, null);
        return flatten(rootNode);
    }

    /**
     * Flattens a Maven dependency tree into one {@link DependencyPath} per
     * non-root node, each listing the complete lineage from the project root
     * to that node. Public and self-contained — takes only a
     * {@link DependencyNode}, so it can be exercised directly against a
     * mocked tree without a real {@link DependencyGraphBuilder} or any other
     * infrastructure.
     */
    public static List<DependencyPath> flatten(DependencyNode root) {
        List<DependencyPath> paths = new ArrayList<>();
        traverseAllPaths(root, new ArrayList<>(), paths);
        return paths;
    }

    /**
     * Recursive Depth-First Search (DFS) worker behind {@link #flatten}.
     * Kept package-private: it exposes an accumulator-style shape (mutating
     * {@code allPaths} as it goes) that only makes sense as an implementation
     * detail — {@link #flatten} is the entry point callers and tests should
     * use.
     *
     * @param node        The current node of the Maven dependency tree being
     *                    processed.
     * @param currentPath The list of artifacts representing the path
     *                    traversed from the root project to this node.
     * @param allPaths    The global accumulator collection where valid paths
     *                    (with depth > 1, i.e. excluding the project root
     *                    itself) are registered.
     */
    static void traverseAllPaths(
            DependencyNode node,
            List<Artifact> currentPath,
            List<DependencyPath> allPaths) {
        if (node.getArtifact() != null) {
            currentPath = new ArrayList<>(currentPath);
            currentPath.add(toArtifact(node.getArtifact()));
        }

        if (currentPath.size() > 1) {
            allPaths.add(new DependencyPath(new ArrayList<>(currentPath)));
        }

        for (DependencyNode child : node.getChildren()) {
            traverseAllPaths(child, currentPath, allPaths);
        }
    }

    static Artifact toArtifact(org.apache.maven.artifact.Artifact mvnArtifact) {
        return Artifact.create(
                mvnArtifact.getGroupId(),
                mvnArtifact.getArtifactId(),
                mvnArtifact.getVersion(),
                Scope.fromString(mvnArtifact.getScope()));
    }
}
