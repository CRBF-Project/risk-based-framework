package org.crbf.application.model.report;

import java.util.List;
import java.util.Optional;

import org.crbf.domain.model.risk.ContextualRisk;

/**
 * @param contextualRisk the score for this vulnerability together with every
 *                       factor used to derive it, so that a reader of the
 *                       report can retrace the calculation.
 */
public record CveSummary(
        String id,
        String severity,
        CvssSummary cvss,
        Optional<EpssSummary> epss,
        List<String> cwes,
        List<String> aliases,
        String summary,
        String advisoryUrl,
        String fixCommitUrl,
        String published,
        String modified,
        ContextualRisk contextualRisk) {
    public CveSummary {
        cwes = cwes == null ? List.of() : List.copyOf(cwes);
        aliases = aliases == null ? List.of() : List.copyOf(aliases);
        epss = epss == null ? Optional.empty() : epss;
    }
}
