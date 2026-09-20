package org.crbf.application.service;

import static org.crbf.fixture.VulnerabilityFixture.vulnerability;
import static org.junit.jupiter.api.Assertions.assertEquals;
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
import org.crbf.domain.model.artifact.Scope;
import org.crbf.domain.model.optimisation.RemediationCandidate;
import org.crbf.domain.model.optimisation.RemediationPlan;
import org.crbf.domain.model.reachability.ProjectCallGraph;
import org.crbf.domain.model.reachability.ReachabilityStatus;
import org.crbf.domain.model.vulnerability.Vulnerability;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import static org.mockito.ArgumentMatchers.any;

class AnalyseDependencyRiskServiceTest {

    // Arbitrary values: the behaviour under test does not depend on severity.
    private static final double ANY_CVSS = 8.0;
    private static final double ANY_EPSS = 0.1;

    @Test
    void shouldAssignUnknownReachabilityWhenArtifactJarCannotBeResolved() {
        ResolveArtifactPort resolveArtifactPort = mock(ResolveArtifactPort.class);
        LoadVulnerabilitiesPort loadVulnerabilitiesPort = mock(LoadVulnerabilitiesPort.class);
        LoadEpssScoresPort loadEpssScoresPort = mock(LoadEpssScoresPort.class);
        LoadStabilityMetricsPort loadStabilityMetricsPort = mock(LoadStabilityMetricsPort.class);
        AnalyseReachabilityPort analyseReachabilityPort = mock(AnalyseReachabilityPort.class);
        DetectBreakingChangesPort detectBreakingChangesPort = mock(DetectBreakingChangesPort.class);
        ResolveTransitiveDependenciesPort resolveTransitiveDependenciesPort = mock(ResolveTransitiveDependenciesPort.class);
        OptimiseRemediationPort optimiseRemediationPort = mock(OptimiseRemediationPort.class);
        RiskReportAssembler reportAssembler = mock(RiskReportAssembler.class);
        ExportRiskReportPort exportRiskReportPort = mock(ExportRiskReportPort.class);
        ExportVexPort exportVexPort = mock(ExportVexPort.class);

        Artifact root = Artifact.create(
                "org.example",
                "application",
                "1.0.0",
                Scope.COMPILE);

        Artifact unresolvedArtifact = Artifact.create(
                "org.example",
                "library",
                "1.0.0",
                Scope.COMPILE);

        Vulnerability detectedVulnerability = vulnerability("CVE-0000-0001", ANY_CVSS, ANY_EPSS);

        when(resolveArtifactPort.resolve(
                anyString(),
                anyString(),
                anyString(),
                anyString()))
                .thenReturn(Optional.empty());

        when(loadVulnerabilitiesPort.loadVulnerabilities(unresolvedArtifact))
                .thenReturn(List.of(detectedVulnerability));

        when(loadEpssScoresPort.enrich(anyList()))
                .thenReturn(List.of(detectedVulnerability));

        when(loadStabilityMetricsPort.loadMetrics(unresolvedArtifact))
                .thenReturn(Optional.empty());

        when(analyseReachabilityPort.buildCallGraph(
                any(),
                anyList()))
                .thenReturn(ProjectCallGraph.empty());

        when(optimiseRemediationPort.optimize(anyList()))
                .thenReturn(RemediationPlan.empty());

        AnalyseDependencyRiskService service = new AnalyseDependencyRiskService(
                resolveArtifactPort,
                loadVulnerabilitiesPort,
                loadEpssScoresPort,
                loadStabilityMetricsPort,
                analyseReachabilityPort,
                detectBreakingChangesPort,
                resolveTransitiveDependenciesPort,
                optimiseRemediationPort,
                reportAssembler,
                exportRiskReportPort,
                exportVexPort);

        service.analyse(
                Path.of("."),
                Path.of("target/classes"),
                List.of(new DependencyPath(
                        List.of(root, unresolvedArtifact))));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<RemediationCandidate>> candidates = ArgumentCaptor.forClass(List.class);
        verify(optimiseRemediationPort).optimize(candidates.capture());

        RemediationCandidate candidate = candidates.getValue().get(0);
        assertEquals(ReachabilityStatus.UNKNOWN, candidate.reachabilityReports().get(0).status());
    }
}