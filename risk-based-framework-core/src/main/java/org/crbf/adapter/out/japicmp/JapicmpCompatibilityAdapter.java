package org.crbf.adapter.out.japicmp;

import japicmp.cmp.JarArchiveComparator;
import japicmp.cmp.JarArchiveComparatorOptions;
import japicmp.model.JApiClass;
import org.crbf.application.port.out.DetectBreakingChangesPort;
import org.crbf.domain.model.artifact.LocatedArtifact;
import org.crbf.domain.model.compatibility.CompatibilityReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.List;

/**
 * Outbound adapter that detects binary and source-level API breaking changes
 * between two versions of the same artifact using the japicmp library
 * (https://github.com/siom79/japicmp).
 *
 * The adapter requires both JARs to be physically located — use
 * {@link LocatedArtifact#isResolvable()} before calling this port.
 */
public class JapicmpCompatibilityAdapter implements DetectBreakingChangesPort {

    private static final Logger LOG = LoggerFactory.getLogger(JapicmpCompatibilityAdapter.class);

    private final JapicmpCompatibilityMapper mapper;

    public JapicmpCompatibilityAdapter() {
        this.mapper = new JapicmpCompatibilityMapper();
    }

    @Override
    public CompatibilityReport detect(LocatedArtifact currentArtifact, LocatedArtifact candidateArtifact) {
        Path currentJar = currentArtifact.physicalJarPath();
        Path candidateJar = candidateArtifact.physicalJarPath();

        if (currentJar == null || !currentJar.toFile().exists() ||
            candidateJar == null || !candidateJar.toFile().exists()) {

            LOG.warn("Cannot compare {} → {}: one or both physical JARs are unavailable.",
                    currentArtifact.version().value(), candidateArtifact.version().value());
            return CompatibilityReport.unknown(currentArtifact.artifact(), candidateArtifact.artifact());
        }

        try {
            List<JApiClass> jApiClasses = compareJars(currentJar, candidateJar);
            CompatibilityReport report = mapper.toDomain(
                    currentArtifact.artifact(), candidateArtifact.artifact(), jApiClasses);

            LOG.info("{} → {}: {} ({} breaking changes)",
                    currentArtifact.version().value(),
                    candidateArtifact.version().value(),
                    report.status(),
                    report.breakingChangeCount());

            return report;

        } catch (Exception e) {
            LOG.error("Comparison failed for {} → {}: {}", currentArtifact.gav(), candidateArtifact.gav(), e.getMessage());
            return CompatibilityReport.unknown(currentArtifact.artifact(), candidateArtifact.artifact());
        }
    }

    private List<JApiClass> compareJars(Path oldJar, Path newJar) {
        JarArchiveComparatorOptions options = new JarArchiveComparatorOptions();

        options.setAccessModifier(japicmp.model.AccessModifier.PUBLIC);

        options.getIgnoreMissingClasses().setIgnoreAllMissingClasses(true);

        JarArchiveComparator comparator = new JarArchiveComparator(options);

        return comparator.compare(
                new japicmp.cmp.JApiCmpArchive(oldJar.toFile(),
                        oldJar.getFileName().toString()),
                new japicmp.cmp.JApiCmpArchive(newJar.toFile(),
                        newJar.getFileName().toString()));
    }
}