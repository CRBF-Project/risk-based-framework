package org.crbf.adapter.out.export;

import static org.crbf.fixture.VulnerabilityFixture.vulnerability;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.crbf.application.model.vex.VexFinding;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.Scope;
import org.crbf.domain.model.reachability.ReachabilityStatus;
import org.crbf.domain.model.reachability.VulnerabilityReachability;
import org.cyclonedx.Version;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class CycloneDxVexAdapterTest {

    private static final Artifact COMMONS = Artifact.create(
            "org.apache.commons", "commons-lang3", "3.12.0", Scope.COMPILE);
    private static final Artifact JACKSON = Artifact.create(
            "com.fasterxml.jackson.core", "jackson-databind", "2.15.0", Scope.RUNTIME);
    private static final Artifact OTHER_COMMONS_VERSION = Artifact.create(
            "org.apache.commons", "commons-lang3", "3.13.0", Scope.COMPILE);

    @TempDir
    Path outputDirectory;

    @Test
    void shouldGenerateJsonValidAgainstTheOfficialCycloneDx17Schema() throws IOException {
        JsonNode document = export(representativeFindings());

        var errors = new JsonParser().validate(document, Version.VERSION_17);

        assertTrue(errors.isEmpty(), () -> "CycloneDX 1.7 schema violations: " + errors);
        assertEquals("CycloneDX", document.path("bomFormat").asText());
        assertEquals("1.7", document.path("specVersion").asText());
    }

    @Test
    void shouldRejectAnInvalidExploitabilityStateDuringSchemaValidation() throws IOException {
        JsonNode document = export(representativeFindings());
        ((ObjectNode) document.path("vulnerabilities").get(0).path("analysis"))
                .put("state", "invalid-state");

        assertFalse(new JsonParser().validate(document, Version.VERSION_17).isEmpty());
    }

    @Test
    void shouldRepresentEveryIdentifiedVulnerabilityIncludingOneSharedByComponents() throws IOException {
        JsonNode document = export(representativeFindings());

        List<String> ids = StreamSupport.stream(document.path("vulnerabilities").spliterator(), false)
                .map(v -> v.path("id").asText()).sorted().toList();

        assertEquals(List.of("CVE-2026-0001", "CVE-2026-0001", "CVE-2026-0002",
                "CVE-2026-0003", "CVE-2026-0004"), ids);
    }

    @ParameterizedTest
    @CsvSource({
            "REACHABLE_CONFIRMED, exploitable",
            "REACHABLE_PROBABLE, in_triage",
            "UNREACHABLE, not_affected",
            "UNKNOWN, in_triage"
    })
    void shouldMapReachabilityToVexExploitabilityState(ReachabilityStatus status, String state) throws IOException {
        JsonNode document = export(List.of(finding(COMMONS, "CVE-2026-0001", status)));

        assertEquals(state, document.path("vulnerabilities").get(0).path("analysis").path("state").asText());
    }

    @Test
    void shouldJustifyNotAffectedWithCodeNotReachable() throws IOException {
        JsonNode document = export(List.of(finding(COMMONS, "CVE-2026-0001", ReachabilityStatus.UNREACHABLE)));

        assertEquals("code_not_reachable",
                document.path("vulnerabilities").get(0).path("analysis").path("justification").asText());
    }

    @ParameterizedTest
    @CsvSource({"REACHABLE_PROBABLE", "UNKNOWN"})
    void shouldNotAssertNonExploitabilityWhenReachabilityIsUncertain(ReachabilityStatus status) throws IOException {
        JsonNode document = export(List.of(finding(COMMONS, "CVE-2026-0001", status)));
        JsonNode analysis = document.path("vulnerabilities").get(0).path("analysis");

        assertFalse(analysis.has("justification"));
        assertFalse(analysis.path("detail").asText().isBlank());
    }

    @Test
    void shouldAssociateEachVulnerabilityWithTheCorrectMavenComponentAndVersion() throws IOException {
        JsonNode document = export(representativeFindings());
        Set<String> associations = new HashSet<>();

        for (JsonNode vulnerability : document.path("vulnerabilities")) {
            assertEquals(1, vulnerability.path("affects").size());
            String ref = vulnerability.path("affects").get(0).path("ref").asText();
            associations.add(vulnerability.path("id").asText() + "|" + ref);
            List<JsonNode> matchingComponents = StreamSupport.stream(document.path("components").spliterator(), false)
                    .filter(component -> component.path("bom-ref").asText().equals(ref)).toList();
            assertEquals(1, matchingComponents.size(), "Each affected ref must resolve to exactly one component");
            assertEquals(ref, matchingComponents.get(0).path("purl").asText());
        }

        assertEquals(Set.of(
                "CVE-2026-0001|pkg:maven/org.apache.commons/commons-lang3@3.12.0",
                "CVE-2026-0002|pkg:maven/org.apache.commons/commons-lang3@3.12.0",
                "CVE-2026-0003|pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.0",
                "CVE-2026-0004|pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.0",
                "CVE-2026-0001|pkg:maven/org.apache.commons/commons-lang3@3.13.0"), associations);
    }

    @Test
    void shouldEmitOneComponentForMultipleVulnerabilitiesInTheSameArtifact() throws IOException {
        JsonNode document = export(List.of(
                finding(COMMONS, "CVE-2026-0001", ReachabilityStatus.REACHABLE_CONFIRMED),
                finding(COMMONS, "CVE-2026-0002", ReachabilityStatus.UNREACHABLE)));

        assertEquals(1, document.path("components").size());
        JsonNode component = document.path("components").get(0);
        assertEquals("library", component.path("type").asText());
        assertEquals("org.apache.commons", component.path("group").asText());
        assertEquals("commons-lang3", component.path("name").asText());
        assertEquals("3.12.0", component.path("version").asText());
    }

    @Test
    void shouldKeepSharedVulnerabilityAssessmentsSpecificToEachComponent() throws IOException {
        JsonNode document = export(List.of(
                finding(COMMONS, "CVE-2026-0001", ReachabilityStatus.REACHABLE_CONFIRMED),
                finding(JACKSON, "CVE-2026-0001", ReachabilityStatus.UNREACHABLE)));

        Set<String> assessments = StreamSupport.stream(document.path("vulnerabilities").spliterator(), false)
                .map(v -> v.path("affects").get(0).path("ref").asText() + "|" + v.path("analysis").path("state").asText())
                .collect(Collectors.toSet());
        assertEquals(Set.of("pkg:maven/org.apache.commons/commons-lang3@3.12.0|exploitable",
                "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.0|not_affected"), assessments);
    }

    @Test
    void shouldExportMissingAnalysisRepresentedAsUnknownWithoutInferringSafety() throws IOException {
        VexFinding missingAnalysis = new VexFinding(COMMONS,
                VulnerabilityReachability.unknown(vulnerability("CVE-2026-0001", 8, 0.1)));

        JsonNode document = export(List.of(missingAnalysis));
        JsonNode analysis = document.path("vulnerabilities").get(0).path("analysis");

        assertEquals("in_triage", analysis.path("state").asText());
        assertEquals("Reachability could not be determined.", analysis.path("detail").asText());
    }

    @Test
    void shouldFailExplicitlyWhenAReachabilityResultIsAbsentInsteadOfUnknown() {
        IllegalStateException error = assertThrows(IllegalStateException.class,
                () -> new CycloneDxVexAdapter().exportVex(List.of(new VexFinding(COMMONS, null)), outputDirectory));

        assertEquals("Failed to export CycloneDX VEX document", error.getMessage());
        assertTrue(error.getCause() instanceof NullPointerException);
    }

    @Test
    void shouldGenerateSchemaValidJsonWhenNoVulnerabilitiesAreIdentified() throws IOException {
        JsonNode document = export(List.of());

        var errors = new JsonParser().validate(document, Version.VERSION_17);
        assertTrue(errors.isEmpty(), () -> "CycloneDX 1.7 schema violations: " + errors);
        assertEquals(0, document.path("vulnerabilities").size());
        assertEquals(0, document.path("components").size());
    }

    private JsonNode export(List<VexFinding> findings) throws IOException {
        new CycloneDxVexAdapter().exportVex(findings, outputDirectory);
        return new ObjectMapper().readTree(outputDirectory.resolve("vex.json").toFile());
    }

    private static List<VexFinding> representativeFindings() {
        // Synthetic CVEs, multiple CVEs per artifact, repeated CVE across versions,
        // and all four reachability classifications.
        return List.of(
                finding(COMMONS, "CVE-2026-0001", ReachabilityStatus.REACHABLE_CONFIRMED),
                finding(COMMONS, "CVE-2026-0002", ReachabilityStatus.REACHABLE_PROBABLE),
                finding(JACKSON, "CVE-2026-0003", ReachabilityStatus.UNKNOWN),
                finding(JACKSON, "CVE-2026-0004", ReachabilityStatus.UNREACHABLE),
                finding(OTHER_COMMONS_VERSION, "CVE-2026-0001", ReachabilityStatus.REACHABLE_CONFIRMED));
    }

    private static VexFinding finding(Artifact artifact, String id, ReachabilityStatus status) {
        return new VexFinding(artifact, new VulnerabilityReachability(
                vulnerability(id, 8, 0.1), status, Set.of(), Set.of()));
    }
}
