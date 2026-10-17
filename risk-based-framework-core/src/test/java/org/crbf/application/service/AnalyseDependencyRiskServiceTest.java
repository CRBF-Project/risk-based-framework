package org.crbf.application.service;

import static org.crbf.fixture.VulnerabilityFixture.vulnerability;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.crbf.application.port.out.AnalyseReachabilityPort;
import org.crbf.application.model.vex.VexFinding;
import org.crbf.application.model.report.RiskReport;
import org.crbf.application.model.report.GraphValidationStatus;
import org.crbf.domain.model.optimisation.GlobalGraphValidation;
import org.crbf.domain.model.optimisation.OptimisationStatus;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.crbf.application.port.out.DetectBreakingChangesPort;
import org.crbf.application.port.out.ExportRiskReportPort;
import org.crbf.application.port.out.ExportVexPort;
import org.crbf.application.port.out.LoadEpssScoresPort;
import org.crbf.application.port.out.LoadStabilityMetricsPort;
import org.crbf.application.port.out.LoadVulnerabilitiesPort;
import org.crbf.application.port.out.OptimiseRemediationPort;
import org.crbf.application.port.out.ResolveArtifactPort;
import org.crbf.application.port.out.ResolveTransitiveDependenciesPort;
import org.crbf.application.port.out.VulnerabilityLookupException;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.DependencyPath;
import org.crbf.domain.model.artifact.LocatedArtifact;
import org.crbf.domain.model.artifact.Scope;
import org.crbf.domain.model.optimisation.RemediationCandidate;
import org.crbf.domain.model.optimisation.RemediationPlan;
import org.crbf.domain.model.reachability.ProjectCallGraph;
import org.crbf.domain.model.reachability.ReachabilityStatus;
import org.crbf.domain.model.reachability.VulnerabilityReachability;
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
    private ExportVexPort exportVexPort;
    private ResolveTransitiveDependenciesPort resolveTransitiveDependenciesPort;
    private ExportRiskReportPort exportRiskReportPort;
    private DetectBreakingChangesPort detectBreakingChangesPort;

    private AnalyseDependencyRiskService service;

    @BeforeEach
    void setUp() {
        resolveArtifactPort = mock(ResolveArtifactPort.class);
        loadVulnerabilitiesPort = mock(LoadVulnerabilitiesPort.class);
        loadEpssScoresPort = mock(LoadEpssScoresPort.class);
        loadStabilityMetricsPort = mock(LoadStabilityMetricsPort.class);
        analyseReachabilityPort = mock(AnalyseReachabilityPort.class);
        optimiseRemediationPort = mock(OptimiseRemediationPort.class);
        exportVexPort = mock(ExportVexPort.class);
        resolveTransitiveDependenciesPort = mock(ResolveTransitiveDependenciesPort.class);
        exportRiskReportPort = mock(ExportRiskReportPort.class);
        detectBreakingChangesPort = mock(DetectBreakingChangesPort.class);

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
                detectBreakingChangesPort,
                resolveTransitiveDependenciesPort,
                optimiseRemediationPort,
                new RiskReportAssembler(),
                exportRiskReportPort,
                exportVexPort);
    }

    @ParameterizedTest
    @EnumSource(OptimisationStatus.class)
    void shouldReportGlobalValidationAsNotRunWhenNoUpgradesAreSelected(OptimisationStatus status) {
        Artifact dependency = Artifact.create("org.example", "library", "1.0.0", Scope.COMPILE);
        stubResolution(dependency, Path.of("/repo/library-1.0.0.jar"));
        when(loadVulnerabilitiesPort.loadVulnerabilities(dependency)).thenReturn(List.of());
        when(optimiseRemediationPort.optimize(anyList())).thenReturn(
                new RemediationPlan(List.of(), 0, 0, 0, status, GlobalGraphValidation.notRun()));

        service.analyse(PROJECT_PATH, CLASSES_PATH,
                List.of(new DependencyPath(List.of(ROOT, dependency))));

        ArgumentCaptor<RiskReport> report = ArgumentCaptor.forClass(RiskReport.class);
        verify(exportRiskReportPort).exportReport(report.capture(), eq(PROJECT_PATH.resolve("target")));
        assertEquals(GraphValidationStatus.NOT_RUN, report.getValue().globalGraphValidation().status());
        verify(resolveTransitiveDependenciesPort, never()).resolveGlobalGraph(anyList());
    }

    @Test
    void shouldPreserveCompleteVulnerabilitySetsForEachResolvedDependencyVersion() {
        Artifact first = Artifact.create("org.example", "library", "1.0.0", Scope.COMPILE);
        Artifact second = Artifact.create("org.example", "library", "2.0.0", Scope.COMPILE);
        Artifact clean = Artifact.create("org.example", "clean-library", "1.0.0", Scope.COMPILE);
        List<Vulnerability> firstSource = List.of(
                vulnerability("CVE-2026-1001", ANY_CVSS, ANY_EPSS),
                vulnerability("CVE-2026-1002", ANY_CVSS, ANY_EPSS),
                vulnerability("GHSA-AAAA-BBBB-CCCC", ANY_CVSS, ANY_EPSS));
        List<Vulnerability> secondSource = List.of(vulnerability("CVE-2026-2001", ANY_CVSS, ANY_EPSS));
        stubResolution(first, Path.of("/repo/library-1.0.0.jar"));
        stubResolution(second, Path.of("/repo/library-2.0.0.jar"));
        stubResolution(clean, Path.of("/repo/clean-library-1.0.0.jar"));
        when(loadVulnerabilitiesPort.loadVulnerabilities(first)).thenReturn(firstSource);
        when(loadVulnerabilitiesPort.loadVulnerabilities(second)).thenReturn(secondSource);
        when(loadVulnerabilitiesPort.loadVulnerabilities(clean)).thenReturn(List.of());
        when(analyseReachabilityPort.analyseReachability(any(), any(), anyList()))
                .thenAnswer(invocation -> invocation.<List<Vulnerability>>getArgument(2).stream()
                        .map(VulnerabilityReachability::unknown).toList());

        service.analyse(PROJECT_PATH, CLASSES_PATH,
                List.of(new DependencyPath(List.of(ROOT, first, second, clean))));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<RemediationCandidate>> candidates = ArgumentCaptor.forClass(List.class);
        verify(optimiseRemediationPort).optimize(candidates.capture());
        Map<Artifact, Set<Vulnerability>> results = candidates.getValue().stream().collect(Collectors.toMap(
                RemediationCandidate::artifact, c -> Set.copyOf(c.vulnerabilities())));
        assertEquals(Map.of(first, Set.copyOf(firstSource), second, Set.copyOf(secondSource)), results);
        verify(loadVulnerabilitiesPort).loadVulnerabilities(clean);
    }

    @Test
    void shouldReportFailedLookupsWhilePreservingSuccessfulDependencyResults() {
        Artifact failed = Artifact.create("org.example", "unavailable", "1.0.0", Scope.COMPILE);
        Artifact successful = Artifact.create("org.example", "available", "1.0.0", Scope.COMPILE);
        Vulnerability source = vulnerability("CVE-2026-1001", ANY_CVSS, ANY_EPSS);
        stubResolution(failed, Path.of("/repo/unavailable-1.0.0.jar"));
        stubResolution(successful, Path.of("/repo/available-1.0.0.jar"));
        when(loadVulnerabilitiesPort.loadVulnerabilities(failed))
                .thenThrow(new VulnerabilityLookupException(failed.gav(), 503));
        when(loadVulnerabilitiesPort.loadVulnerabilities(successful)).thenReturn(List.of(source));
        when(analyseReachabilityPort.analyseReachability(any(), any(), anyList()))
                .thenReturn(List.of(VulnerabilityReachability.unknown(source)));

        service.analyse(PROJECT_PATH, CLASSES_PATH,
                List.of(new DependencyPath(List.of(ROOT, failed, successful))));

        ArgumentCaptor<RiskReport> report = ArgumentCaptor.forClass(RiskReport.class);
        verify(exportRiskReportPort).exportReport(report.capture(), eq(PROJECT_PATH.resolve("target")));
        assertEquals(List.of(failed.gav()), report.getValue().vulnerabilityLookupFailures());
        assertEquals(List.of(successful.gav()), report.getValue().findings().stream().map(f -> f.artifact()).toList());
        assertEquals(List.of(source.id().value()), report.getValue().findings().get(0).vulnerabilities().stream()
                .map(v -> v.id()).toList());
    }

    @Test
    void shouldExportEveryVulnerabilityAsUnknownWhenArtifactJarCannotBeResolved() {
        Artifact unresolved = Artifact.create("org.example", "library", "1.0.0", Scope.COMPILE);
        Vulnerability first = vulnerability("CVE-2026-0001", ANY_CVSS, ANY_EPSS);
        Vulnerability second = vulnerability("CVE-2026-0002", ANY_CVSS, ANY_EPSS);
        when(resolveArtifactPort.resolve(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Optional.empty());
        when(loadVulnerabilitiesPort.loadVulnerabilities(unresolved)).thenReturn(List.of(first, second));

        service.analyse(PROJECT_PATH, CLASSES_PATH, List.of(new DependencyPath(List.of(ROOT, unresolved))));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<VexFinding>> findings = ArgumentCaptor.forClass(List.class);
        verify(exportVexPort).exportVex(findings.capture(), eq(PROJECT_PATH.resolve("target")));
        assertEquals(List.of(
                new VexFinding(unresolved, VulnerabilityReachability.unknown(first)),
                new VexFinding(unresolved, VulnerabilityReachability.unknown(second))),
                findings.getValue());
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

    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {
            "[BINARY] Method fixture.Api#removed() — METHOD_REMOVED",
            "[BINARY] Class fixture.Api — CLASS_REMOVED",
            "[BINARY] Field fixture.Api#removed — FIELD_REMOVED" })
    void shouldPreserveJapicmpIncompatibilityWhenAffectedUsageIsAbsentFromCallGraph(String change) {
        RemediationCandidate candidate = analyseIncompatibleUpgrade(change);
        assertEquals(org.crbf.domain.model.compatibility.CompatibilityStatus.BINARY_INCOMPATIBLE,
                candidate.compatibilityReport().orElseThrow().status());
    }

    @Test
    void shouldRetainOriginalEffortWhenContextualHeuristicCannotEvaluateChanges() {
        RemediationCandidate candidate = analyseIncompatibleUpgrade(
                "[BINARY] Class fixture.Api — CLASS_REMOVED");
        assertEquals(4.0, candidate.upgradeCost());
    }

    @Test
    void shouldUseReducedEffortWhenMappedAffectedMethodsAreNotObserved() {
        RemediationCandidate candidate = analyseIncompatibleUpgrade(
                "[BINARY] Method fixture.Api#removed() — METHOD_REMOVED");
        assertEquals(1.0, candidate.upgradeCost());
    }

    @SuppressWarnings("unchecked")
    private RemediationCandidate analyseIncompatibleUpgrade(String change) {
        Artifact current = Artifact.create("org.example", "library", "1.0.0", Scope.COMPILE);
        Artifact target = Artifact.create("org.example", "library", "2.0.0", Scope.COMPILE);
        LocatedArtifact locatedCurrent = new LocatedArtifact(current, Path.of("/repo/library-1.jar"));
        LocatedArtifact locatedTarget = new LocatedArtifact(target, Path.of("/repo/library-2.jar"));
        stubResolution(current, locatedCurrent.physicalJarPath());
        stubResolution(target, locatedTarget.physicalJarPath());
        Vulnerability v = Vulnerability.create("CVE-2026-1001", 8, "TEST_VECTOR", Optional.of("2.0.0"),
                Optional.empty(), List.of(), "", "", List.of(), Optional.empty(), Optional.empty(), "", "");
        when(loadVulnerabilitiesPort.loadVulnerabilities(current)).thenReturn(List.of(v));
        when(loadVulnerabilitiesPort.loadVulnerabilities(target)).thenReturn(List.of());
        when(resolveTransitiveDependenciesPort.getNewerVersionsWithCves(current)).thenReturn(List.of());
        when(resolveTransitiveDependenciesPort.resolveTransitiveDepsWithCves(current))
                .thenReturn(org.crbf.domain.model.artifact.TransitiveDepsResult.of(Set.of(), List.of()));
        when(resolveTransitiveDependenciesPort.resolveTransitiveDepsWithCves(target))
                .thenReturn(org.crbf.domain.model.artifact.TransitiveDepsResult.of(Set.of(), List.of()));
        when(analyseReachabilityPort.buildCallGraph(any(), anyList())).thenReturn(new ProjectCallGraph(
                Set.of(org.crbf.domain.model.reachability.ReachableMethod.of("fixture.Api", "used"))));
        when(analyseReachabilityPort.analyseReachability(any(), eq(locatedCurrent), anyList()))
                .thenReturn(List.of(VulnerabilityReachability.reachableProbable(v, Set.of())));
        when(detectBreakingChangesPort.detect(locatedCurrent, locatedTarget)).thenReturn(
                new org.crbf.domain.model.compatibility.CompatibilityReport(current, target,
                        org.crbf.domain.model.compatibility.CompatibilityStatus.BINARY_INCOMPATIBLE, List.of(change)));
        service.analyse(PROJECT_PATH, CLASSES_PATH, List.of(new DependencyPath(List.of(ROOT, current))));
        ArgumentCaptor<List<RemediationCandidate>> candidates = ArgumentCaptor.forClass(List.class);
        verify(optimiseRemediationPort).optimize(candidates.capture());
        return candidates.getValue().get(0);
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
