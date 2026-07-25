package org.crbf.application.port.out;

import org.crbf.domain.model.artifact.LocatedArtifact;
import org.crbf.domain.model.compatibility.CompatibilityReport;

/**
 * Output port for binary compatibility analysis between two versions of
 * the same artifact.
 *
 * Given the currently used version of a dependency and a candidate upgrade
 * version (typically the fix version from a CVE remediation), this port
 * determines whether the upgrade introduces binary or source-level breaking
 * changes.
 */
public interface DetectBreakingChangesPort {

    /**
     * @param currentArtifact   The located version of the artifact currently in use.
     * @param candidateArtifact The located candidate version to upgrade to.
     * @return A {@link CompatibilityReport} describing the compatibility status
     *         and the list of individual breaking changes detected.
     */
    CompatibilityReport detect(LocatedArtifact currentArtifact, LocatedArtifact candidateArtifact);
}
