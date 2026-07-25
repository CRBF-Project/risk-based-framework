package org.crbf.application.port.out;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.stability.EcosystemStability;

public interface LoadStabilityMetricsPort {
    EcosystemStability loadMetrics(Artifact artifact);
}
