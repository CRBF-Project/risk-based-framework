package org.crbf.application.port.out;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.stability.EcosystemStability;

import java.util.Optional;

public interface LoadStabilityMetricsPort {

    /**
     * Loads ecosystem stability metrics for an artifact.
     *
     * @return the metrics, or {@link Optional#empty()} when the ecosystem data
     *         source has no data for this artifact or could not be reached.
     *         Unavailability is represented explicitly so that callers can apply
     *         a neutral fallback instead of reading absent data as zero adoption.
     */
    Optional<EcosystemStability> loadMetrics(Artifact artifact);
}
