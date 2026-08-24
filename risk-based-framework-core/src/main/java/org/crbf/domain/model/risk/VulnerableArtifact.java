package org.crbf.domain.model.risk;

import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.Version;
import org.crbf.domain.model.vulnerability.AlternativeFix;
import org.crbf.domain.model.vulnerability.Severity;
import org.crbf.domain.model.vulnerability.Vulnerability;

import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Domain aggregate representing an artifact that has been assessed against
 * a vulnerability database and found to have one or more known CVEs.
 */
public record VulnerableArtifact(
        Artifact artifact,
        List<Vulnerability> vulnerabilities) {

    public VulnerableArtifact {
        Objects.requireNonNull(artifact, "Artifact cannot be null");
        vulnerabilities = vulnerabilities == null ? List.of() : List.copyOf(vulnerabilities);
        if (vulnerabilities.isEmpty()) {
            throw new IllegalArgumentException("VulnerableArtifact must have at least one vulnerability");
        }
    }

    /**
     * The minimum version that fixes ALL known CVEs for this artifact.
     *
     * Each CVE carries its own minimum fix version; to eliminate every CVE
     * with a single upgrade, the target must be at least the maximum of all
     * those individual minimums.
     *
     * Returns empty if no CVE provides a fix version.
     */
    public Optional<Version> requiredFixVersion() {
        return vulnerabilities.stream()
                .flatMap(v -> v.minimumFixVersion().stream())
                .max(Comparator.naturalOrder());
    }

    /**
     * When no CVE affecting this artifact carries a fix version of its own,
     * looks for a fix that exists under a different Maven coordinate — e.g.
     * the library was renamed/forked. Only meaningful alongside
     * {@code !hasFixAvailable()}: if a direct fix exists, that is always the
     * simpler and preferred remediation path.
     */
    public Optional<AlternativeFix> requiredAlternativeFix() {
        if (hasFixAvailable()) {
            return Optional.empty();
        }
        return vulnerabilities.stream()
                .flatMap(v -> v.alternativeFix().stream())
                .findFirst();
    }

    /**
     * The highest severity across all CVEs affecting this artifact.
     */
    public Severity worstSeverity() {
        return vulnerabilities.stream()
                .map(Vulnerability::severity)
                .min(Comparator.comparingInt(Severity::ordinal))
                .orElse(Severity.UNKNOWN);
    }

    /**
     * The highest CVSS score across all CVEs affecting this artifact.
     */
    public double maxCvssScore() {
        return vulnerabilities.stream()
                .mapToDouble(v -> v.cvss().value())
                .max()
                .orElse(0.0);
    }

    public boolean hasCritical() {
        return worstSeverity() == Severity.CRITICAL;
    }

    public boolean hasFixAvailable() {
        return requiredFixVersion().isPresent();
    }

    public String gav() {
        return artifact.gav();
    }
}
