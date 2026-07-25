package org.crbf.application.port.out;

import java.util.List;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.vulnerability.Vulnerability;

public interface LoadVulnerabilitiesPort {
        List<Vulnerability> loadVulnerabilities(Artifact artifact);
}
