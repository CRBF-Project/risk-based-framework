package org.crbf.adapter.out.export;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.crbf.fixture.RemediationCandidateFixture.withFix;
import static org.crbf.fixture.VulnerabilityFixture.vulnerability;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Files;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.crbf.application.model.report.RiskReport;
import org.crbf.application.service.RiskReportAssembler;
import org.crbf.domain.model.optimisation.GlobalGraphValidation;
import org.crbf.domain.model.optimisation.InfeasibilityDetails;
import org.crbf.domain.model.optimisation.OptimisationStatus;
import org.crbf.domain.model.optimisation.RemediationPlan;
import org.crbf.domain.model.optimisation.RemediationCandidate;
import org.crbf.domain.model.optimisation.RemediationDecision;
import org.crbf.domain.model.reachability.VulnerabilityReachability;
import org.crbf.domain.model.vulnerability.Vulnerability;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class ReportGeneratorAdapterTest {

    @TempDir
    Path outputDirectory;

    @Test
    void shouldExportRecommendedUpdatesWithContextualRiskAndSupportingFactors() throws IOException {
        double cvssScore = 8.0;
        double epssProbability = 0.2;
        double expectedNormalisedCvss = 0.8;
        double neutralStaleness = 0.5;
        double expectedCvssWeight = 0.5;
        double expectedEpssWeight = 0.3;
        double expectedStalenessWeight = 0.2;
        double expectedReachabilityFactor = 1.0;
        double expectedPathQualityFactor = 1.0;
        double expectedBaseRisk = expectedNormalisedCvss * expectedCvssWeight
                + epssProbability * expectedEpssWeight
                + neutralStaleness * expectedStalenessWeight;
        double expectedContextualRisk = expectedBaseRisk * expectedReachabilityFactor * expectedPathQualityFactor;
        int expectedFindingCount = 1;
        int expectedAdvisoryCount = 1;
        double selectedEffort = 2.0;
        double effortBudget = 2.0;
        double fullyRemediatedResidualRisk = 0.0;
        double tolerance = 1e-9;
        String recommendedVersion = "2.0.0";
        String rationale = "Selected within the effort budget.";
        Vulnerability vulnerability = vulnerability("CVE-2026-1001", cvssScore, epssProbability);
        RemediationCandidate candidate = withFix(List.of(
                VulnerabilityReachability.reachableConfirmed(vulnerability, Set.of(), Set.of())));
        RemediationDecision decision = RemediationDecision.upgrade(
                candidate.artifact(), recommendedVersion, expectedContextualRisk, selectedEffort, rationale);
        RemediationPlan plan = new RemediationPlan(List.of(decision), expectedContextualRisk, fullyRemediatedResidualRisk,
                selectedEffort, OptimisationStatus.OPTIMAL, GlobalGraphValidation.notRun()).withEffortBudget(effortBudget);
        RiskReport report = new RiskReportAssembler().assemble(Path.of("test-project"), List.of(),
                Set.of(candidate.artifact()), List.of(candidate), plan, List.of());

        new ReportGeneratorAdapter().exportReport(report, outputDirectory);

        JsonNode exported = new ObjectMapper().readTree(outputDirectory.resolve("risk-report.json").toFile());
        JsonNode embedded = embeddedData(Files.readString(outputDirectory.resolve("risk-report.html")));
        assertEquals(exported, embedded, "HTML must embed the complete exported JSON report");
        assertEquals(expectedFindingCount, exported.path("findings").size(), "The recommended dependency must be exported once");
        JsonNode finding = exported.path("findings").get(0);
        assertEquals("org.example:test-library:1.0.0", finding.path("artifact").asText(), "Current Maven coordinates");
        assertEquals(expectedContextualRisk, finding.path("contextualRisk").asDouble(), tolerance, "Dependency contextual risk");
        JsonNode remediation = finding.path("remediation");
        assertEquals("RECOMMENDED", remediation.path("decision").asText(), "Selected update classification");
        assertEquals(recommendedVersion, remediation.path("recommendedVersion").asText(), "Recommended target version");
        assertEquals(rationale, remediation.path("rationale").asText(), "Recommendation rationale");
        assertEquals(expectedContextualRisk, remediation.path("riskReduction").asDouble(), tolerance, "Selected risk reduction");
        assertEquals(expectedAdvisoryCount, finding.path("vulnerabilities").size(), "The supporting advisory must be exported once");
        JsonNode advisory = finding.path("vulnerabilities").get(0);
        assertEquals("CVE-2026-1001", advisory.path("id").asText(), "Supporting vulnerability identifier");
        JsonNode risk = advisory.path("contextualRisk");
        assertEquals("REACHABLE_CONFIRMED", risk.path("reachabilityStatus").asText(), "Vulnerability reachability classification");
        assertEquals(expectedNormalisedCvss, risk.path("cvssNormalized").asDouble(), tolerance, "Normalised CVSS");
        assertEquals(epssProbability, risk.path("epss").asDouble(), tolerance, "EPSS probability");
        assertEquals(neutralStaleness, risk.path("stalenessUrgency").asDouble(), tolerance, "Neutral staleness for unavailable metrics");
        assertEquals(expectedCvssWeight, risk.path("effectiveCvssWeight").asDouble(), tolerance, "Effective CVSS weight");
        assertEquals(expectedEpssWeight, risk.path("effectiveEpssWeight").asDouble(), tolerance, "Effective EPSS weight");
        assertEquals(expectedStalenessWeight, risk.path("effectiveStalenessWeight").asDouble(), tolerance, "Effective staleness weight");
        assertEquals(expectedBaseRisk, risk.path("baseRisk").asDouble(), tolerance, "Weighted base risk");
        assertEquals(expectedReachabilityFactor, risk.path("reachabilityFactor").asDouble(), tolerance, "Confirmed reachability factor");
        assertEquals(expectedPathQualityFactor, risk.path("pathQualityFactor").asDouble(), tolerance, "Risk-preserving factor for unavailable path quality");
        assertEquals(expectedContextualRisk, risk.path("value").asDouble(), tolerance, "Vulnerability contextual risk");
    }

    @Test
    void shouldEmbedHostileTextAsDataWithoutChangingTheJsonReport() throws IOException {
        RiskReport base = new RiskReportAssembler().assemble(Path.of("test-project"), List.of(), Set.of(),
                List.of(), RemediationPlan.empty(), List.of());
        String name = "</script><script>window.injected=true</script><img src=x onerror=alert(1)>";
        RiskReport report = new RiskReport(name, base.totalDependenciesScanned(), base.totalDependencyPaths(),
                base.scannedArtifacts(), base.findings(), base.optimisationStatus(), base.infeasibility(),
                base.residualRisk(), base.globalGraphValidation(), base.vulnerabilityLookupFailures(), base.availableEffortBudget());

        new ReportGeneratorAdapter().exportReport(report, outputDirectory);

        String html = Files.readString(outputDirectory.resolve("risk-report.html"));
        JsonNode exported = new ObjectMapper().readTree(outputDirectory.resolve("risk-report.json").toFile());
        assertEquals(name, exported.path("projectName").asText());
        assertEquals(exported, embeddedData(html));
        assertFalse(html.contains(name), "Untrusted HTML delimiters must not appear in the data block");
    }

    @Test
    void shouldExportInfeasibilityDetailsAndPendingMandatoryVersions() throws IOException {
        InfeasibilityDetails details = InfeasibilityDetails.of(
                InfeasibilityDetails.Reason.MANDATORY_EFFORT_EXCEEDS_BUDGET, 3,
                List.of(new InfeasibilityDetails.MandatoryUpgrade("org.example:library:1.0.0", "2.0.0", 4)));
        RemediationPlan plan = new RemediationPlan(List.of(), 0, 1, 0,
                OptimisationStatus.INFEASIBLE, GlobalGraphValidation.notRun(), Optional.of(details));
        RiskReport report = new RiskReportAssembler().assemble(
                Path.of("test-project"), List.of(), Set.of(), List.of(), plan, List.of());

        new ReportGeneratorAdapter().exportReport(report, outputDirectory);

        JsonNode exported = new ObjectMapper().readTree(outputDirectory.resolve("risk-report.json").toFile());
        JsonNode infeasibility = exported.path("infeasibility");
        assertEquals(3, infeasibility.path("availableEffortBudget").asDouble());
        assertEquals(4, infeasibility.path("requiredMandatoryEffort").asDouble());
        assertEquals(1, infeasibility.path("budgetShortfall").asDouble());
        assertEquals("2.0.0", infeasibility.path("mandatoryUpgrades").get(0).path("targetVersion").asText());
    }

    @ParameterizedTest
    @EnumSource(OptimisationStatus.class)
    void shouldExportExplicitOptimisationOutcome(OptimisationStatus status) throws IOException {
        RemediationPlan plan = new RemediationPlan(List.of(), 0, 0, 0,
                status, GlobalGraphValidation.notRun()).withEffortBudget(10);
        RiskReport report = new RiskReportAssembler().assemble(
                Path.of("test-project"), List.of(), Set.of(), List.of(), plan, List.of());

        new ReportGeneratorAdapter().exportReport(report, outputDirectory);

        JsonNode exported = new ObjectMapper().readTree(outputDirectory.resolve("risk-report.json").toFile());
        assertEquals(status.name(), exported.path("optimisationStatus").asText());
        assertEquals(10, exported.path("availableEffortBudget").asDouble());
        assertEquals(exported, embeddedData(Files.readString(outputDirectory.resolve("risk-report.html"))));
    }

    private JsonNode embeddedData(String html) throws IOException {
        String marker = "<script id=\"report-data\" type=\"application/json\">";
        int start = html.indexOf(marker) + marker.length();
        int end = html.indexOf("</script>", start);
        return new ObjectMapper().readTree(html.substring(start, end));
    }
}
