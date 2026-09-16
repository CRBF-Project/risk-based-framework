package org.crbf.plugin;

import java.io.File;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.DefaultProjectBuildingRequest;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectBuildingRequest;
import org.apache.maven.shared.dependency.graph.DependencyGraphBuilder;
import org.apache.maven.shared.dependency.graph.DependencyGraphBuilderException;

import org.crbf.adapter.out.goblin.GoblinWeaverGraphAdapter;
import org.crbf.domain.model.optimisation.RiskWeights;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.RemoteRepository;
import org.crbf.adapter.out.epss.EpssAdapter;
import org.crbf.adapter.out.export.ReportGeneratorAdapter;
import org.crbf.adapter.out.goblin.GoblinWeaverStabilityAdapter;
import org.crbf.adapter.out.japicmp.JapicmpCompatibilityAdapter;
import org.crbf.adapter.out.osv.OsvVulnerabilityAdapter;
import org.crbf.adapter.out.wala.WalaReachabilityAdapter;
import org.crbf.adapter.out.z3.Z3RemediationAdapter;
import org.crbf.application.port.in.AnalyseDependencyRiskUseCase;
import org.crbf.application.service.AnalyseDependencyRiskService;
import org.crbf.application.service.RiskReportAssembler;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.DependencyPath;
import org.crbf.plugin.adapter.out.MavenRuntimeArtifactResolverAdapter;

/**
 * Maven Plugin Mojo for the Contextualised Risk-Based Framework.
 *
 * Executes within the Maven lifecycle (default: verify phase), receiving a
 * fully-resolved MavenProject from the Maven runtime.
 *
 * Usage in target project:
 * mvn org.contextframework:risk-based-framework-maven-plugin:1.0-SNAPSHOT:analyse
 */
@Mojo(name = "analyse", defaultPhase = LifecyclePhase.VERIFY, requiresDependencyResolution = ResolutionScope.COMPILE_PLUS_RUNTIME, threadSafe = false)
public class AnalyseMojo extends AbstractMojo {

    /**
     * The current Maven project — already fully resolved by the Maven runtime.
     */
    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject mavenProject;

    /**
     * The current Maven session — provides access to the local repository.
     */
    @Parameter(defaultValue = "${session}", readonly = true, required = true)
    private MavenSession mavenSession;

    /**
     * Maven Shared Dependency Graph Builder — provides the fully-resolved
     * DependencyNode tree, including all transitive dependencies, applying
     * Maven's conflict resolution (nearest-wins) and scope filtering.
     */
    @Component
    private DependencyGraphBuilder dependencyGraphBuilder;

    /**
     * Maximum total effort units available per sprint.
     * Effort costs: COMPATIBLE=1.0, SOURCE_INCOMPATIBLE=3.0,
     * BINARY_INCOMPATIBLE=4.0, UNKNOWN=2.0.
     */
    @Parameter(property = "contextframework.effortBudget", defaultValue = "10.0")
    private double effortBudget;

    /**
     * Maximum time (in seconds) allowed for WALA's 0-CFA call graph
     * construction. WALA's propagation-based analysis has no built-in time
     * bound, so a large or reflection-heavy dependency graph could otherwise
     * run indefinitely. On timeout, the analysis is abandoned and reachability
     * degrades gracefully to UNKNOWN for every vulnerability, never producing
     * false negatives.
     */
    @Parameter(property = "contextframework.callGraphTimeoutSeconds", defaultValue = "600")
    private int callGraphTimeoutSeconds;

    /**
     * Semicolon-separated regular expressions (JVM-internal slash notation,
     * e.g. {@code java/awt/.*}) identifying classes to exclude from WALA's
     * class-hierarchy construction entirely. Applies to every loader — JDK,
     * dependencies and application code alike — so it should only list
     * packages no real Maven dependency would ever occupy (JDK-internal/GUI
     * toolkit code). The default follows the same design as Eclipse Steady's
     * {@code vulas.reach.wala.callgraph.exclusions}, minus one entry
     * ({@code org/apache/xerces/.*}) that would otherwise make a real,
     * independently-distributed dependency (the standalone Xerces artifact)
     * invisible to reachability analysis.
     */
    @Parameter(property = "contextframework.callGraphExclusions", defaultValue = ""
            + "java/awt/.*;javax/swing/.*;sun/awt/.*;sun/swing/.*;com/sun/.*;sun/.*;"
            + "org/netbeans/.*;org/openide/.*;com/ibm/crypto/.*;com/ibm/security/.*;"
            + "dalvik/.*;java/io/ObjectStreamClass*;apple/.*;com/apple/.*;com/oracle/.*;jdk/.*;org/omg/.*;org/w3c/.*")
    private String callGraphExclusions;

    /**
     * OSV API endpoint for vulnerability lookups.
     */
    @Parameter(property = "contextframework.osvApiUrl", defaultValue = "https://api.osv.dev/v1/query")
    private String osvApiUrl;

    /**
     * Goblin Weaver API base URL for ecosystem stability metrics.
     */
    @Parameter(property = "contextframework.goblinUrl", defaultValue = "http://localhost:8080")
    private String goblinUrl;

    /**
     * The Aether Repository System entry point.
     * Used by the PluginArtifactResolverAdapter to physically download missing
     * artifact files (.jar) from remote repositories, which is strictly required
     * for WALA's bytecode analysis.
     */
    @Component
    private RepositorySystem repoSystem;

    /**
     * The current repository session context.
     * Provides the resolver with the local user environment settings.
     */
    @Parameter(defaultValue = "${repositorySystemSession}", readonly = true, required = true)
    private RepositorySystemSession repoSession;

    /**
     * The list of remote repositories configured for the current project.
     * Ensures that artifacts are resolved using the same repositories declared
     * by the user (e.g., Maven Central, corporate Nexus, or Artifactory).
     */
    @Parameter(defaultValue = "${project.remoteProjectRepositories}", readonly = true, required = true)
    private List<RemoteRepository> remoteRepositories;

    /**
     * Weight of the CVSS severity score in the contextual risk formula.
     * Must sum to 1.00 with epss and staleness weights (max 2 decimal places).
     * Range: [0.00, 1.00].
     */
    @Parameter(property = "contextframework.riskWeight.cvss", defaultValue = "0.5")
    private double riskWeightCvss;

    @Parameter(property = "contextframework.riskWeight.epss", defaultValue = "0.3")
    private double riskWeightEpss;

    @Parameter(property = "contextframework.riskWeight.staleness", defaultValue = "0.2")
    private double riskWeightStaleness;

    @Parameter(property = "contextframework.riskWeight.reachable", defaultValue = "1.0")
    private double riskWeightReachable;

    @Parameter(property = "contextframework.riskWeight.unknown", defaultValue = "0.5")
    private double riskWeightUnknown;

    @Parameter(property = "contextframework.riskWeight.unreachable", defaultValue = "0.1")
    private double riskWeightUnreachable;

    /**
     * The main entry point of the Contextualised Risk-Based Framework plugin.
     * <p>
     * This method acts as the primary orchestrator, executing the following
     * lifecycle:
     * <ol>
     * <li><b>Validation:</b> Verifies execution preconditions (e.g., compiled
     * bytecode presence, valid budget).</li>
     * <li><b>Extraction:</b> Resolves the project's dependency graph via Maven's
     * native API.</li>
     * <li><b>Execution:</b> Wires the Hexagonal Architecture adapters and delegates
     * risk analysis to the Core domain.</li>
     * </ol>
     *
     * @throws MojoExecutionException if a critical failure occurs during dependency
     *                                resolution or core analysis.
     * @throws MojoFailureException   if the execution environment fails validation.
     */
    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        getLog().info("=========================================================");
        getLog().info("  Contextualised Risk-Based Framework");
        getLog().info("=========================================================");
        getLog().info("Target Project : " + mavenProject.getArtifactId() + ":" + mavenProject.getVersion());
        getLog().info("Effort Budget  : " + effortBudget + " units");
        getLog().info("CG Timeout     : " + callGraphTimeoutSeconds + "s");
        getLog().info("---------------------------------------------------------");

        validatePreconditions();

        try {
            getLog().info("[Step 1] Resolving dependency graph via Maven...");
            List<DependencyPath> dependencyGraph = buildDependencyGraph();

            if (getLog().isDebugEnabled()) {
                getLog().debug("Extracted Dependency Paths:");
                for (DependencyPath dp : dependencyGraph) {
                    String fullPath = dp.path().stream()
                            .map(Artifact::gav)
                            .collect(Collectors.joining(" -> "));
                    getLog().debug("  " + fullPath);
                }
            }

            Path projectBase = mavenProject.getBasedir().toPath();
            Path classesPath = Path.of(mavenProject.getBuild().getOutputDirectory());
            AnalyseDependencyRiskUseCase service = wireService();

            service.analyse(projectBase, classesPath, dependencyGraph);

        } catch (Exception e) {
            getLog().error("Analysis failed: " + e.getMessage(), e);
            throw new MojoExecutionException("Contextualised Risk Framework execution failed.", e);
        }

        getLog().info("=======================================================");
        getLog().info("  Analysis complete. See target/risk-report.html");
        getLog().info("=======================================================");
    }

    /**
     * Validates the execution environment and configuration parameters before
     * starting the analysis.
     * <p>
     * <b>Compilation Check:</b> WALA requires compiled bytecode to build the call
     * graph.
     * If the project's output directory is missing, the plugin gracefully degrades
     * its behavior,
     * logging a warning and assuming an UNKNOWN reachability status for all
     * vulnerabilities.
     * <p>
     * <b>Budget Check:</b> Ensures that the configured effort budget for the
     * Z3Optimization
     * engine is strictly positive to prevent solver errors.
     * 
     * @throws MojoFailureException if the defined effort budget is zero or
     *                              negative.
     */
    private void validatePreconditions() throws MojoFailureException {
        File classesDir = new File(mavenProject.getBuild().getOutputDirectory());

        if (!classesDir.exists() || !classesDir.isDirectory()) {
            getLog().warn(
                    "[ContextFramework] Compiled classes not found at " + classesDir.getName() + ". "
                            + "Run 'mvn compile' first to enable reachability analysis. "
                            + "Proceeding with UNKNOWN reachability for all vulnerabilities.");
        }

        if (effortBudget <= 0) {
            throw new MojoFailureException(
                    "contextframework.effortBudget must be positive. Got: " + effortBudget);
        }

        if (riskWeightCvss < 0 || riskWeightEpss < 0 || riskWeightStaleness < 0) {
            throw new MojoFailureException(
                    "Risk weights (cvss, epss, staleness) must be non-negative.");
        }
        long cvssH = Math.round(riskWeightCvss * 100);
        long epssH = Math.round(riskWeightEpss * 100);
        long stalenessH = Math.round(riskWeightStaleness * 100);
        if (cvssH + epssH + stalenessH != 100) {
            throw new MojoFailureException(
                    "Risk weights must sum to 1.00 (max 2 decimal places). "
                            + String.format("cvss(%.2f) + epss(%.2f) + staleness(%.2f) = %.2f",
                                    riskWeightCvss, riskWeightEpss, riskWeightStaleness,
                                    riskWeightCvss + riskWeightEpss + riskWeightStaleness));
        }
        if (riskWeightReachable < 0 || riskWeightUnknown < 0 || riskWeightUnreachable < 0) {
            throw new MojoFailureException(
                    "Reachability weights (reachable, unknown, unreachable) must be non-negative.");
        }
    }

    /**
     * Acts as the Composition Root for the Hexagonal Architecture, wiring the
     * concrete infrastructure adapters to the core domain service.
     * <p>
     * <b>Dependency Injection:</b> Instantiates the required external adapters and
     * injects them into
     * the main {@link AnalyseDependencyRiskService}, ensuring the Core domain
     * remains completely
     * decoupled from specific technologies.
     *
     * @return the fully configured core use case instance, ready for execution.
     */
    private AnalyseDependencyRiskUseCase wireService() {
        MavenRuntimeArtifactResolverAdapter resolverAdapter = new MavenRuntimeArtifactResolverAdapter(
                repoSystem, repoSession, remoteRepositories);

        RiskWeights weights = new RiskWeights(
                riskWeightCvss,
                riskWeightEpss,
                riskWeightStaleness,
                riskWeightReachable,
                riskWeightUnknown,
                riskWeightUnreachable);

        return new AnalyseDependencyRiskService(
                resolverAdapter,
                new OsvVulnerabilityAdapter(osvApiUrl),
                new EpssAdapter(),
                new GoblinWeaverStabilityAdapter(goblinUrl),
                new WalaReachabilityAdapter(callGraphTimeoutSeconds, callGraphExclusions),
                new JapicmpCompatibilityAdapter(),
                new GoblinWeaverGraphAdapter(goblinUrl),
                new Z3RemediationAdapter(effortBudget, weights),
                new RiskReportAssembler(weights),
                new ReportGeneratorAdapter());
    }

    /**
     * Builds the full dependency graph using Maven's DependencyGraphBuilder,
     * delegating the actual graph resolution and flattening to
     * {@link MavenDependencyGraphResolver} (kept independently testable from
     * this Mojo — see {@code MavenDependencyGraphResolverTest}).
     *
     * @return the list of dependency paths extracted from the graph, where
     *         each path is a sequence of artifacts from the root project to a leaf
     *         dependency.
     * @throws MojoExecutionException if some of the dependencies could not be
     *                                resolved.
     */
    private List<DependencyPath> buildDependencyGraph() throws MojoExecutionException {
        try {
            ProjectBuildingRequest buildingRequest = new DefaultProjectBuildingRequest(
                    mavenSession.getProjectBuildingRequest());
            buildingRequest.setProject(mavenProject);

            return new MavenDependencyGraphResolver(dependencyGraphBuilder).resolve(buildingRequest);

        } catch (DependencyGraphBuilderException e) {
            throw new MojoExecutionException("Failed to build dependency graph", e);
        }
    }
}