package org.crbf.application.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Set;

import org.crbf.application.port.out.DetectBreakingChangesPort;
import org.crbf.application.port.out.LoadVulnerabilitiesPort;
import org.crbf.application.port.out.ResolveArtifactPort;
import org.crbf.application.port.out.ResolveTransitiveDependenciesPort;
import org.crbf.application.port.out.VulnerabilityLookupException;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.Scope;
import org.crbf.domain.model.artifact.TransitiveDepsResult;
import org.crbf.domain.model.optimisation.UpgradePathStatus;
import org.crbf.domain.model.optimisation.UpgradePathValidation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class UpgradePathAnalyserTest {

    private LoadVulnerabilitiesPort loadVulnerabilitiesPort;
    private ResolveTransitiveDependenciesPort resolveTransitiveDependenciesPort;
    private ResolveArtifactPort resolveArtifactPort;
    private DetectBreakingChangesPort detectBreakingChangesPort;
    private AnalysisProgressLogger logger;

    private UpgradePathAnalyser analyser;

    private static final Artifact CURRENT_ARTIFACT = Artifact.create(
            "org.example",
            "library",
            "1.0.0",
            Scope.COMPILE);

    private static final Artifact FIX_ARTIFACT = Artifact.create(
            "org.example",
            "library",
            "2.0.0",
            Scope.COMPILE);

    private static final String FIX_VERSION = "2.0.0";
    private static final double DELTA = 0.000001;

    @BeforeEach
    void setUp() {
        loadVulnerabilitiesPort = mock(LoadVulnerabilitiesPort.class);
        resolveTransitiveDependenciesPort = mock(ResolveTransitiveDependenciesPort.class);
        resolveArtifactPort = mock(ResolveArtifactPort.class);
        detectBreakingChangesPort = mock(DetectBreakingChangesPort.class);
        logger = mock(AnalysisProgressLogger.class);

        analyser = new UpgradePathAnalyser(
                loadVulnerabilitiesPort,
                resolveTransitiveDependenciesPort,
                resolveArtifactPort,
                detectBreakingChangesPort,
                logger);
    }

    @Test
    void shouldMarkUpgradePathUnknownWhenFixVersionVulnerabilityLookupFails() {
        when(resolveTransitiveDependenciesPort
                .getNewerVersionsWithCves(CURRENT_ARTIFACT))
                .thenReturn(List.of());

        when(loadVulnerabilitiesPort.loadVulnerabilities(FIX_ARTIFACT))
                .thenThrow(new VulnerabilityLookupException(
                        FIX_ARTIFACT.gav(),
                        503));

        when(resolveTransitiveDependenciesPort
                .resolveTransitiveDepsWithCves(CURRENT_ARTIFACT))
                .thenReturn(TransitiveDepsResult.of(
                        Set.of(),
                        List.of()));

        when(resolveTransitiveDependenciesPort
                .resolveTransitiveDepsWithCves(FIX_ARTIFACT))
                .thenReturn(TransitiveDepsResult.of(
                        Set.of(),
                        List.of()));

        UpgradePathValidation result = analyser.validateUpgradePathWithoutJar(
                CURRENT_ARTIFACT,
                FIX_VERSION);

        assertEquals(
                UpgradePathStatus.UNKNOWN,
                result.upgradePathStatus());
    }

    @Test
    void shouldMarkUpgradePathUnknownWhenTransitiveGraphDataIsUnavailable() {
        when(resolveTransitiveDependenciesPort
                .getNewerVersionsWithCves(CURRENT_ARTIFACT))
                .thenReturn(List.of());

        when(loadVulnerabilitiesPort
                .loadVulnerabilities(FIX_ARTIFACT))
                .thenReturn(List.of());

        when(resolveTransitiveDependenciesPort
                .resolveTransitiveDepsWithCves(CURRENT_ARTIFACT))
                .thenReturn(TransitiveDepsResult.unavailable());

        when(resolveTransitiveDependenciesPort
                .resolveTransitiveDepsWithCves(FIX_ARTIFACT))
                .thenReturn(TransitiveDepsResult.of(
                        Set.of(),
                        List.of()));

        UpgradePathValidation result = analyser.validateUpgradePathWithoutJar(
                CURRENT_ARTIFACT,
                FIX_VERSION);

        assertEquals(UpgradePathStatus.UNKNOWN, result.upgradePathStatus());
    }

    @Test
    void shouldMarkUpgradePathCleanWhenNoVulnerabilitiesAreIntroduced() {
        when(resolveTransitiveDependenciesPort
                .getNewerVersionsWithCves(CURRENT_ARTIFACT))
                .thenReturn(List.of());

        when(loadVulnerabilitiesPort
                .loadVulnerabilities(FIX_ARTIFACT))
                .thenReturn(List.of());

        when(resolveTransitiveDependenciesPort
                .resolveTransitiveDepsWithCves(CURRENT_ARTIFACT))
                .thenReturn(TransitiveDepsResult.of(
                        Set.of(),
                        List.of()));

        when(resolveTransitiveDependenciesPort
                .resolveTransitiveDepsWithCves(FIX_ARTIFACT))
                .thenReturn(TransitiveDepsResult.of(
                        Set.of(),
                        List.of()));

        UpgradePathValidation result = analyser.validateUpgradePathWithoutJar(
                CURRENT_ARTIFACT,
                FIX_VERSION);

        assertEquals(UpgradePathStatus.CLEAN, result.upgradePathStatus());
    }

    @Test
    void shouldCalculateUpgradePathSecuritySignalFromIntroducedVulnerabilities() {
        Artifact safeDependency = Artifact.create(
                "org.example",
                "safe-dependency",
                "1.0.0",
                Scope.COMPILE);

        Artifact vulnerableDependency = Artifact.create(
                "org.example",
                "vulnerable-dependency",
                "1.0.0",
                Scope.COMPILE);

        when(resolveTransitiveDependenciesPort
                .getNewerVersionsWithCves(CURRENT_ARTIFACT))
                .thenReturn(List.of());

        when(loadVulnerabilitiesPort
                .loadVulnerabilities(FIX_ARTIFACT))
                .thenReturn(List.of());

        when(resolveTransitiveDependenciesPort
                .resolveTransitiveDepsWithCves(CURRENT_ARTIFACT))
                .thenReturn(TransitiveDepsResult.of(
                        Set.of(),
                        List.of()));

        when(resolveTransitiveDependenciesPort
                .resolveTransitiveDepsWithCves(FIX_ARTIFACT))
                .thenReturn(TransitiveDepsResult.of(
                        Set.of(safeDependency, vulnerableDependency),
                        List.of(vulnerableDependency)));

        UpgradePathValidation result = analyser.validateUpgradePathWithoutJar(
                CURRENT_ARTIFACT,
                FIX_VERSION);

        double fixSafety = 1.0;
        double introducedVulnerabilityRatio = 1.0 / 2.0;
        double expectedSignal = fixSafety - introducedVulnerabilityRatio;

        assertEquals(expectedSignal, result.upgradePathSecuritySignal().orElseThrow(), DELTA);
    }

}