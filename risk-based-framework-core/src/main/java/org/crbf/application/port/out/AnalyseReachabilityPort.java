package org.crbf.application.port.out;

import java.nio.file.Path;
import java.util.List;

import org.crbf.domain.model.artifact.LocatedArtifact;
import org.crbf.domain.model.reachability.ProjectCallGraph;
import org.crbf.domain.model.reachability.VulnerabilityReachability;
import org.crbf.domain.model.vulnerability.Vulnerability;

public interface AnalyseReachabilityPort {

    /**
     * Builds the project's call graph from compiled bytecode and all dependency JARs.
     * This is the expensive operation — call it once per analysis run, before the
     * per-artifact loop, and pass the result to {@link #analyseReachability}.
     *
     * Returns {@link ProjectCallGraph#empty()} if the analysis cannot be performed
     * (missing classes, SootUp failure, etc.).
     *
     * @param classesPath Path to the project's compiled bytecode ({@code target/classes/}).
     * @param allProjectJars All JAR paths in the dependency graph.
     */
    ProjectCallGraph buildCallGraph(Path classesPath, List<Path> allProjectJars);

    /**
     * Determines which vulnerabilities are reachable using a pre-built call graph.
     *
     * @param callGraph Pre-built project call graph from {@link #buildCallGraph}.
     * @param vulnerableArtifact The artifact whose vulnerabilities are being assessed.
     * @param vulnerabilities The list of vulnerabilities to assess.
     * @return One {@link VulnerabilityReachability} per vulnerability.
     */
    List<VulnerabilityReachability> analyseReachability(
            ProjectCallGraph callGraph,
            LocatedArtifact vulnerableArtifact,
            List<Vulnerability> vulnerabilities);
}
