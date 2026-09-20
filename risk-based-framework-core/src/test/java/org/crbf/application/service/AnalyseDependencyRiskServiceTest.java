package org.crbf.application.service;

import static org.crbf.fixture.VulnerabilityFixture.vulnerability;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import org.crbf.application.port.out.AnalyseReachabilityPort;
import org.crbf.application.port.out.DetectBreakingChangesPort;
import org.crbf.application.port.out.ExportRiskReportPort;
import org.crbf.application.port.out.ExportVexPort;
import org.crbf.application.port.out.LoadEpssScoresPort;
import org.crbf.application.port.out.LoadStabilityMetricsPort;
import org.crbf.application.port.out.LoadVulnerabilitiesPort;
import org.crbf.application.port.out.OptimiseRemediationPort;
import org.crbf.application.port.out.ResolveArtifactPort;
import org.crbf.application.port.out.ResolveTransitiveDependenciesPort;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.DependencyPath;
import org.crbf.domain.model.artifact.LocatedArtifact;
import org.crbf.domain.model.artifact.Scope;
import org.crbf.domain.model.optimisation.RemediationCandidate;
import org.crbf.domain.model.optimisation.RemediationPlan;
import org.crbf.domain.model.reachability.ProjectCallGraph;
import org.crbf.domain.model.reachability.ReachabilityStatus;
import org.crbf.domain.model.vulnerability.Vulnerability;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class AnalyseDependencyRiskServiceTest {

    // Arbitrary values: the behaviour under test does not depend on severity.
    private static final double ANY_CVSS = 8.0;
    private static final double ANY_EPSS = 0.1;

    private static final Path PROJECT_PATH = Path.of(".");
    private static final Path CLASSES_PATH = Path.of("target/classes");

    private static final Artifact ROOT = Artifact.create(
            "org.example", "application", "1.0.0", Scope.COMPILE);

    private ResolveArtifactPort resolveArtifactPort;
    private LoadVulnerabilitiesPort loadVulnerabilitiesPort;
    private LoadEpssScoresPort loadEpssScoresPort;
    private LoadStabilityMetricsPort loadStabilityMetricsPort;
    private AnalyseReachabilityPort analyseReachabilityPort;
    private OptimiseRemediationPort optimiseRemediationPort;

    private AnalyseDependencyRiskService service;

    @BeforeEach
    void setUp() {
        resolveArtifactPort = mock(ResolveArtifactPort.class);
        loadVulnerabilitiesPort = mock(LoadVulnerabilitiesPort.class);
        loadEpssScoresPort = mock(LoadEpssScoresPort.class);
        loadStabilityMetricsPort = mock(LoadStabilityMetricsPort.class);
        analyseReachabilityPort = mock(AnalyseReachabilityPort.class);
        optimiseRemediationPort = mock(OptimiseRemediationPort.class);

        when(analyseReachabilityPort.buildCallGraph(any(), anyList()))
                .thenReturn(ProjectCallGraph.empty());
        when(loadEpssScoresPort.enrich(anyList()))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(loadStabilityMetricsPort.loadMetrics(any()))
                .thenReturn(Optional.empty());
        when(optimiseRemediationPort.optimize(anyList()))
                .thenReturn(RemediationPlan.empty());

        service = new AnalyseDependencyRiskService(
                resolveArtifactPort,
                loadVulnerabilitiesPort,
                loadEpssScoresPort,
                loadStabilityMetricsPort,
                analyseReachabilityPort,
                mock(DetectBreakingChangesPort.class),
                mock(ResolveTransitiveDependenciesPort.class),
                optimiseRemediationPort,
                mock(RiskReportAssembler.class),
                mock(ExportRiskReportPort.class),
                mock(ExportVexPort.class));
    }

    @Test
    void shouldAssignUnknownReachabilityWhenArtifactJarCannotBeResolved() {
        Artifact unresolvedArtifact = Artifact.create(
                "org.example", "library", "1.0.0", Scope.COMPILE);

        Vulnerability detectedVulnerability = vulnerability("CVE-0000-0001", ANY_CVSS, ANY_EPSS);

        when(resolveArtifactPort.resolve(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Optional.empty());
        when(loadVulnerabilitiesPort.loadVulnerabilities(unresolvedArtifact))
                .thenReturn(List.of(detectedVulnerability));

        service.analyse(
                PROJECT_PATH,
                CLASSES_PATH,
                List.of(new DependencyPath(List.of(ROOT, unresolvedArtifact))));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<RemediationCandidate>> candidates = ArgumentCaptor.forClass(List.class);
        verify(optimiseRemediationPort).optimize(candidates.capture());

        RemediationCandidate candidate = candidates.getValue().get(0);
        assertEquals(ReachabilityStatus.UNKNOWN, candidate.reachabilityReports().get(0).status());
    }

    @Test
    void shouldExcludeTestScopeJarsFromTheCallGraphScope() {
        Artifact compileDependency = Artifact.create(
                "org.example", "library", "1.0.0", Scope.COMPILE);
        Artifact testDependency = Artifact.create(
                "org.example", "test-library", "1.0.0", Scope.TEST);

        Path compileJar = Path.of("/repo/library-1.0.0.jar");
        Path testJar = Path.of("/repo/test-library-1.0.0.jar");

        stubResolution(compileDependency, compileJar);
        stubResolution(testDependency, testJar);

        when(loadVulnerabilitiesPort.loadVulnerabilities(any()))
                .thenReturn(List.of());

        service.analyse(
                PROJECT_PATH,
                CLASSES_PATH,
                List.of(new DependencyPath(List.of(ROOT, compileDependency, testDependency))));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<Path>> scopeJars = ArgumentCaptor.forClass(List.class);
        verify(analyseReachabilityPort).buildCallGraph(any(), scopeJars.capture());

        assertEquals(List.of(compileJar), scopeJars.getValue());
    }

    private void stubResolution(Artifact artifact, Path jarPath) {
        when(resolveArtifactPort.resolve(
                artifact.groupId().value(),
                artifact.artifactId().value(),
                artifact.version().value(),
                artifact.scope().name()))
                .thenReturn(Optional.of(new LocatedArtifact(artifact, jarPath)));
    }
}
