package org.crbf.application.port.in;

import java.nio.file.Path;
import java.util.List;

import org.crbf.domain.model.artifact.DependencyPath;

public interface AnalyseDependencyRiskUseCase {

    /**
     * @param projectPath Root directory of the project being analysed.
     * @param classesPath Path to the compiled bytecode output directory
     *                    (e.g. {@code target/classes} for Maven,
     *                    {@code build/classes/java/main} for Gradle).
     *                    Provided by the caller so the service remains
     *                    agnostic of the build tool.
     * @param prebuiltGraph Dependency paths resolved by the build tool.
     */
    void analyse(Path projectPath, Path classesPath, List<DependencyPath> prebuiltGraph);

}
