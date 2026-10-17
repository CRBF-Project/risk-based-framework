package org.crbf.domain.model.compatibility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.artifact.Scope;
import org.crbf.domain.model.reachability.ProjectCallGraph;
import org.crbf.domain.model.reachability.ReachableMethod;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class CompatibilityReportTest {
    private final Artifact from = Artifact.create("test", "library", "1", Scope.COMPILE);
    private final Artifact to = Artifact.create("test", "library", "2", Scope.COMPILE);
    private final ProjectCallGraph graph = new ProjectCallGraph(Set.of(
            ReachableMethod.of("fixture.Api", "used", Optional.of("()"))));
    private static final String REMOVED = "[BINARY] Method fixture.Api#removed() — METHOD_REMOVED";

    @Test
    void shouldPreserveOriginalJapicmpClassificationAfterContextualisation() {
        assertEquals(CompatibilityStatus.BINARY_INCOMPATIBLE, report(REMOVED).contextualise(graph).status());
    }

    @Test
    void shouldClassifyUnobservedMappedChangesAsContextuallyCompatible() {
        assertEquals(CompatibilityStatus.COMPATIBLE, report(REMOVED).contextualise(graph).contextualStatus());
    }

    @Test
    void shouldUseCompatibleEffortCategoryForUnobservedMappedChanges() {
        assertEquals(CompatibilityStatus.COMPATIBLE, report(REMOVED).contextualise(graph).effortStatus());
    }

    @Test
    void shouldPreserveBreakingChangeDescriptionsAfterContextualisation() {
        assertEquals(List.of(REMOVED), report(REMOVED).contextualise(graph).breakingChanges());
    }

    @Test
    void shouldKeepContextualIncompatibilityWhenAffectedMethodIsObserved() {
        assertEquals(CompatibilityStatus.BINARY_INCOMPATIBLE,
                report("[BINARY] Method fixture.Api#used() — METHOD_REMOVED").contextualise(graph).contextualStatus());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "[BINARY] Class fixture.Api — CLASS_REMOVED",
            "[BINARY] Field fixture.Api#used — FIELD_REMOVED",
            "Method fixture.Api#removed()",
            "[BINARY] Method fixture.Api#removed — METHOD_REMOVED" })
    void shouldKeepUnknownContextForChangesTheHeuristicCannotMap(String change) {
        assertEquals(CompatibilityStatus.UNKNOWN, report(change).contextualise(graph).contextualStatus());
    }

    @Test
    void shouldNotDiscountMixedMethodAndUnmappedChanges() {
        assertEquals(CompatibilityStatus.BINARY_INCOMPATIBLE,
                report(REMOVED, "[BINARY] Field fixture.Api#value — FIELD_REMOVED").contextualise(graph).effortStatus());
    }

    @Test
    void shouldKeepUnknownContextWithoutCallGraphEvidence() {
        assertEquals(CompatibilityStatus.UNKNOWN, report(REMOVED).contextualise(ProjectCallGraph.empty()).contextualStatus());
    }

    @Test
    void shouldRetainOriginalEffortWithoutCallGraphEvidence() {
        assertEquals(CompatibilityStatus.BINARY_INCOMPATIBLE,
                report(REMOVED).contextualise(ProjectCallGraph.empty()).effortStatus());
    }

    @Test
    void shouldKeepUnknownContextWithoutBreakingChangeDetails() {
        assertEquals(CompatibilityStatus.UNKNOWN, report().contextualise(graph).contextualStatus());
    }

    @Test
    void shouldEvaluateMultipleChangesToTheSameMethodWithoutTreatingThemAsUnmapped() {
        assertEquals(CompatibilityStatus.COMPATIBLE,
                report(REMOVED, "[SOURCE] Method fixture.Api#removed() — METHOD_NOW_THROWS_CHECKED_EXCEPTION")
                        .contextualise(graph).contextualStatus());
    }

    @Test
    void shouldConservativelyMatchConstructorWithoutReportedSignature() {
        var constructors = new ProjectCallGraph(Set.of(ReachableMethod.of("fixture.Api", "<init>", Optional.of("(String)"))));
        assertEquals(CompatibilityStatus.BINARY_INCOMPATIBLE,
                report("[BINARY] Constructor fixture.Api#<init> — CONSTRUCTOR_REMOVED")
                        .contextualise(constructors).contextualStatus());
    }

    @Test
    void shouldLeaveSourceOnlyCompatibilityUnchanged() {
        var source = new CompatibilityReport(from, to, CompatibilityStatus.SOURCE_INCOMPATIBLE, List.of(REMOVED));
        assertEquals(CompatibilityStatus.SOURCE_INCOMPATIBLE, source.contextualise(graph).effortStatus());
    }

    @Test
    void shouldLeaveOriginallyCompatibleEffortUnchanged() {
        assertEquals(CompatibilityStatus.COMPATIBLE, CompatibilityReport.compatible(from, to).contextualise(graph).effortStatus());
    }

    private CompatibilityReport report(String... changes) {
        return new CompatibilityReport(from, to, CompatibilityStatus.BINARY_INCOMPATIBLE, List.of(changes));
    }
}
