package org.crbf.fixture;

import java.util.List;
import java.util.Optional;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.Scope;
import org.crbf.domain.model.optimisation.RemediationCandidate;
import org.crbf.domain.model.reachability.VulnerabilityReachability;
import org.crbf.domain.model.vulnerability.Vulnerability;

public final class RemediationCandidateFixture {

    private static final Artifact ARTIFACT =
            Artifact.create(
                    "org.example",
                    "test-library",
                    "1.0.0",
                    Scope.COMPILE);

    private static final String FIX_VERSION = "2.0.0";

    private RemediationCandidateFixture() {
    }

    public static RemediationCandidate withFix(
            List<VulnerabilityReachability> reachabilityReports) {

        List<Vulnerability> vulnerabilities = reachabilityReports.stream()
                .map(VulnerabilityReachability::vulnerability)
                .toList();

        return new RemediationCandidate(
                ARTIFACT,
                vulnerabilities,
                reachabilityReports,
                Optional.empty(),
                Optional.of(FIX_VERSION),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty());
    }
}