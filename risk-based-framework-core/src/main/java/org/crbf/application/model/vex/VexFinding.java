package org.crbf.application.model.vex;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.reachability.VulnerabilityReachability;

public record VexFinding(
        Artifact artifact,
        VulnerabilityReachability reachability
) {
}