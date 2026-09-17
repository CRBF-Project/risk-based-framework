package org.crbf.adapter.out.export;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.crbf.application.model.vex.VexFinding;
import org.crbf.application.port.out.ExportVexPort;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.reachability.ReachabilityStatus;
import org.cyclonedx.Version;
import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.vulnerability.Vulnerability;

public class CycloneDxVexAdapter implements ExportVexPort {

    @Override
    public void exportVex(
            List<VexFinding> findings,
            Path outputDirectory) {

        try {
          Files.createDirectories(outputDirectory);

            Bom bom = new Bom();

            List<Component> components = findings.stream()
                    .map(VexFinding::artifact)
                    .distinct()
                    .map(this::toComponent)
                    .toList();

            List<Vulnerability> vulnerabilities = findings.stream()
                    .map(this::toVulnerability)
                    .toList();

            bom.setComponents(components);
            bom.setVulnerabilities(vulnerabilities);

            BomJsonGenerator generator =
                    new BomJsonGenerator(bom, Version.VERSION_17);

            String json = generator.toJsonString(true);

            Files.writeString(
                    outputDirectory.resolve("vex.json"),
                    json,
                    StandardCharsets.UTF_8);

        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to export CycloneDX VEX document",
                    e);
        }
    }

      private Component toComponent(Artifact artifact) {
        String purl = toPurl(artifact);

        Component component = new Component();
        component.setType(Component.Type.LIBRARY);
        component.setGroup(artifact.groupId().value());
        component.setName(artifact.artifactId().value());
        component.setVersion(artifact.version().value());
        component.setPurl(purl);
        component.setBomRef(purl);

        return component;
    }

    private Vulnerability toVulnerability(VexFinding finding) {
        var reachability = finding.reachability();
        var domainVulnerability = reachability.vulnerability();

        Vulnerability vulnerability = new Vulnerability();

        vulnerability.setId(domainVulnerability.id().value());

        Vulnerability.Affect affect = new Vulnerability.Affect();
        affect.setRef(toPurl(finding.artifact()));

        vulnerability.setAffects(List.of(affect));
        vulnerability.setAnalysis(
                toAnalysis(reachability.status()));

        return vulnerability;
    }

    private Vulnerability.Analysis toAnalysis(
            ReachabilityStatus status) {

        Vulnerability.Analysis analysis =
                new Vulnerability.Analysis();

        switch (status) {
            case REACHABLE_CONFIRMED -> {
                analysis.setState(
                        Vulnerability.Analysis.State.EXPLOITABLE);
                analysis.setDetail(
                        "The vulnerable code is reachable from the analysed project.");
            }

            case REACHABLE_PROBABLE -> {
                analysis.setState(
                        Vulnerability.Analysis.State.EXPLOITABLE);
                analysis.setDetail(
                        "The vulnerable artifact is reachable, but the specific vulnerable code could not be confirmed.");
            }

            case UNREACHABLE -> {
                analysis.setState(
                        Vulnerability.Analysis.State.NOT_AFFECTED);
                analysis.setJustification(
                        Vulnerability.Analysis.Justification.CODE_NOT_REACHABLE);
                analysis.setDetail(
                        "No call-graph path to the vulnerable artifact was identified.");
            }

            case UNKNOWN -> {
                analysis.setState(
                        Vulnerability.Analysis.State.IN_TRIAGE);
                analysis.setDetail(
                        "Reachability could not be determined.");
            }
        }

        return analysis;
    }

    private String toPurl(Artifact artifact) {
        return "pkg:maven/"
                + artifact.groupId().value()
                + "/"
                + artifact.artifactId().value()
                + "@"
                + artifact.version().value();
    }
}