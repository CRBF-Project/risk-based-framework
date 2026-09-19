package org.crbf.architecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import com.tngtech.archunit.core.importer.ImportOption;


class ModularityArchitectureTest {

    private static final String ROOT_PACKAGE = "org.crbf";

    private static final String DOMAIN_PACKAGE = "org.crbf.domain..";
    private static final String APPLICATION_PACKAGE = "org.crbf.application..";
    private static final String ADAPTER_PACKAGE = "org.crbf.adapter..";

    private static final String WALA_PACKAGE = "com.ibm.wala..";
    private static final String JAPICMP_PACKAGE = "japicmp..";
    private static final String Z3_PACKAGE = "com.microsoft.z3..";

    private static final JavaClasses PROJECT_CLASSES =
        new ClassFileImporter()
                .withImportOption(
                        ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages(ROOT_PACKAGE);

    @Test
    void domainShouldNotDependOnApplicationOrAdapters() {
        noClasses()
                .that().resideInAPackage(DOMAIN_PACKAGE)
                .should().dependOnClassesThat()
                .resideInAnyPackage(
                        APPLICATION_PACKAGE,
                        ADAPTER_PACKAGE)
                .check(PROJECT_CLASSES);
    }

    @Test
    void applicationShouldNotDependOnAdapters() {
        noClasses()
                .that().resideInAPackage(APPLICATION_PACKAGE)
                .should().dependOnClassesThat()
                .resideInAPackage(ADAPTER_PACKAGE)
                .check(PROJECT_CLASSES);
    }

    @Test
    void applicationShouldNotDependOnConcreteAnalysisLibraries() {
        noClasses()
                .that().resideInAPackage(APPLICATION_PACKAGE)
                .should().dependOnClassesThat()
                .resideInAnyPackage(
                        WALA_PACKAGE,
                        JAPICMP_PACKAGE,
                        Z3_PACKAGE)
                .check(PROJECT_CLASSES);
    }

    @Test
    void domainShouldNotDependOnConcreteAnalysisLibraries() {
        noClasses()
                .that().resideInAPackage(DOMAIN_PACKAGE)
                .should().dependOnClassesThat()
                .resideInAnyPackage(
                        WALA_PACKAGE,
                        JAPICMP_PACKAGE,
                        Z3_PACKAGE)
                .check(PROJECT_CLASSES);
    }
}