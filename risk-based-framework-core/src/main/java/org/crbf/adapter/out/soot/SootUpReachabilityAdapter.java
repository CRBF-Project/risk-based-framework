package org.crbf.adapter.out.soot;

import org.crbf.application.port.out.AnalyseReachabilityPort;
import org.crbf.domain.model.artifact.LocatedArtifact;
import org.crbf.domain.model.reachability.ProjectCallGraph;
import org.crbf.domain.model.reachability.ReachableMethod;
import org.crbf.domain.model.reachability.ReachabilityStatus;
import org.crbf.domain.model.reachability.VulnerabilityReachability;
import org.crbf.domain.model.vulnerability.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sootup.callgraph.CallGraph;
import sootup.callgraph.RapidTypeAnalysisAlgorithm;
import sootup.core.model.SourceType;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.signatures.MethodSignature;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.JrtFileSystemAnalysisInputLocation;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;
import sootup.java.core.views.JavaView;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Outbound adapter that performs Static Reachability Analysis (SRA) using
 * the SootUp 2.0.0 framework (https://soot-oss.github.io/SootUp/latest/).
 *
 * Two-phase design:
 * 1. {@link #buildCallGraph} — builds the full RTA call graph once per analysis
 * run, excluding JDK/standard-library packages from the reachable set.
 * 2. {@link #analyseReachability} — class/method matching against the
 * pre-built graph. Safe to call for every vulnerable artifact.
 *
 * Fallback: if analysis fails for any reason (missing classes, JVM mismatch,
 * etc.), the result is UNKNOWN, which the service layer treats conservatively
 * as potentially REACHABLE — never producing false negatives.
 */
public class SootUpReachabilityAdapter implements AnalyseReachabilityPort {

        private static final Logger LOG = LoggerFactory.getLogger(SootUpReachabilityAdapter.class);

        // Matches CamelCase Java class name tokens in CVE text, e.g. "JndiLookup",
        // "StringSubstitutor", "XStream".
        private static final Pattern CLASS_TOKEN_PATTERN = Pattern.compile(
                        "\\b([A-Z][A-Za-z0-9]{2,})\\b");

        // Matches method-like references: "foo(", "Class.foo(", "#foo", "foo()".
        private static final Pattern METHOD_TOKEN_PATTERN = Pattern.compile(
                        "(?:#|\\b)([A-Za-z_][A-Za-z0-9_]*)\\s*(?:\\(|\\))");

        // JDK/standard-library packages excluded from the reachable set: they are
        // never the target of application-level vulnerability assessment and would
        // otherwise expand the call graph without informing the analysis.
        private static final List<String> EXCLUDED_PACKAGE_PREFIXES = List.of(
                        "java.", "javax.", "sun.", "com.oracle.");

        @Override
        public ProjectCallGraph buildCallGraph(Path classesPath, List<Path> allProjectJars) {
                if (!classesPath.toFile().exists()) {
                        LOG.error("Project classes not found at: {}. Tip: run 'mvn compile' on the target project first.", classesPath);
                        return ProjectCallGraph.empty();
                }

                try {
                        return new ProjectCallGraph(buildReachableMethodSet(classesPath, allProjectJars));
                } catch (Exception e) {
                        LOG.error("Call graph construction failed: {}", e.getMessage());
                        return ProjectCallGraph.empty();
                }
        }

        @Override
        public List<VulnerabilityReachability> analyseReachability(
                        ProjectCallGraph callGraph,
                        LocatedArtifact vulnerableArtifact,
                        List<Vulnerability> vulnerabilities) {

                if (vulnerabilities.isEmpty()) {
                        return List.of();
                }

                if (callGraph.isEmpty()) {
                        return markAllUnknown(vulnerabilities);
                }

                if (vulnerableArtifact.physicalJarPath() == null) {
                        LOG.warn("No physical JAR path for {} - cannot analyse reachability", vulnerableArtifact.gav());
                        return markAllUnknown(vulnerabilities);
                }

                try {
                        Set<String> jarClasses = extractClassNamesFromJar(vulnerableArtifact.physicalJarPath());

                        if (jarClasses.isEmpty()) {
                                LOG.warn("Could not extract classes from {} - using groupId fallback", vulnerableArtifact.gav());
                        }

                        Set<ReachableMethod> reachableFromJar = jarClasses.isEmpty()
                                        ? reachableByGroupIdFallback(callGraph, vulnerableArtifact)
                                        : reachableByClassMatch(callGraph, jarClasses);

                        boolean anyReachable = !reachableFromJar.isEmpty();

                        LOG.info("{} → {} ({} reachable methods from {} classes)",
                                        vulnerableArtifact.gav(),
                                        anyReachable ? "REACHABLE" : ReachabilityStatus.UNREACHABLE,
                                        reachableFromJar.size(),
                                        jarClasses.size());

                        if (!anyReachable) {
                                return markAllUnreachable(vulnerabilities);
                        }

                        return vulnerabilities.stream()
                                        .map(v -> classifyVulnerability(v, reachableFromJar, jarClasses))
                                        .toList();

                } catch (Exception e) {
                        LOG.error("Reachability matching failed for {}: {}", vulnerableArtifact.gav(), e.getMessage());
                        return markAllUnknown(vulnerabilities);
                }
        }

        /**
         * Classifies a single vulnerability as CONFIRMED or PROBABLE.
         *
         * CONFIRMED: CVE text yields class name candidates that can be matched to
         * a specific FQCN in the JAR, and that class is reachable in the call graph.
         *
         * PROBABLE: The JAR is reachable (some class from it is called) but no
         * specific vulnerable class could be extracted from CVE text.
         */
        private VulnerabilityReachability classifyVulnerability(
                        Vulnerability vulnerability,
                        Set<ReachableMethod> reachableFromJar,
                        Set<String> jarClasses) {

                Set<String> classNameCandidates = extractClassNameCandidates(vulnerability);

                if (!classNameCandidates.isEmpty()) {
                        Set<String> confirmedClasses = jarClasses.stream()
                                        .filter(fqcn -> classNameCandidates.contains(simpleClassName(fqcn)))
                                        .collect(Collectors.toUnmodifiableSet());

                        Set<ReachableMethod> confirmedMethods = reachableFromJar.stream()
                                        .filter(m -> confirmedClasses.contains(m.container()))
                                        .collect(Collectors.toUnmodifiableSet());

                        if (!confirmedMethods.isEmpty()) {
                                Set<ReachableMethod> vulnerableMethods = inferVulnerableMethods(
                                                vulnerability, confirmedMethods);
                                LOG.debug("{} → REACHABLE_CONFIRMED (class: {})", vulnerability.id().value(), confirmedClasses);
                                return VulnerabilityReachability.reachableConfirmed(
                                                vulnerability, confirmedMethods, vulnerableMethods);
                        }
                }

                LOG.debug("{} → REACHABLE_PROBABLE (no specific class in CVE text)", vulnerability.id().value());
                return VulnerabilityReachability.reachableProbable(vulnerability, reachableFromJar);
        }

        private Set<ReachableMethod> buildReachableMethodSet(Path projectClassesPath, List<Path> allProjectJars) {

                List<AnalysisInputLocation> inputLocations = new ArrayList<>();

                inputLocations.add(new JrtFileSystemAnalysisInputLocation());

                inputLocations.add(new JavaClassPathAnalysisInputLocation(
                                projectClassesPath.toAbsolutePath().toString(),
                                SourceType.Application));

                for (Path jarPath : allProjectJars) {
                        if (jarPath != null && jarPath.toFile().exists()) {
                                inputLocations.add(new JavaClassPathAnalysisInputLocation(
                                                jarPath.toAbsolutePath().toString(),
                                                SourceType.Library));
                        }
                }

                JavaView view = new JavaView(inputLocations);
                List<MethodSignature> entryPoints = collectEntryPoints(view);

                if (entryPoints.isEmpty()) {
                        LOG.warn("No entry points found. Ensure the project is compiled and contains public methods.");
                        return Set.of();
                }

                CallGraph callGraph = new RapidTypeAnalysisAlgorithm(view)
                                .initialize(entryPoints);

                return collectReachableMethods(callGraph);
        }

        /**
         * Collects all public/protected, non-abstract methods of Application
         * classes as RTA entry points.
         */
        private List<MethodSignature> collectEntryPoints(JavaView view) {
                return view.getClasses()
                                .filter(JavaSootClass::isApplicationClass)
                                .flatMap(cls -> cls.getMethods().stream())
                                .filter(m -> !m.isAbstract())
                                .filter(m -> m.isPublic() || m.isProtected())
                                .map(JavaSootMethod::getSignature)
                                .toList();
        }

        /**
         * Extracts all transitively reachable methods from the call graph,
         * excluding methods declared in JDK/standard-library packages.
         */
        private Set<ReachableMethod> collectReachableMethods(CallGraph callGraph) {
                return callGraph.getMethodSignatures()
                                .stream()
                                .filter(sig -> !isExcludedPackage(sig.getDeclClassType().getFullyQualifiedName()))
                                .map(sig -> ReachableMethod.of(
                                                sig.getDeclClassType().getFullyQualifiedName(),
                                                sig.getName(),
                                                extractSignature(sig)))
                                .collect(Collectors.toUnmodifiableSet());
        }

        private boolean isExcludedPackage(String fullyQualifiedClassName) {
                return EXCLUDED_PACKAGE_PREFIXES.stream()
                                .anyMatch(fullyQualifiedClassName::startsWith);
        }

        private Optional<String> extractSignature(MethodSignature signature) {
                try {
                        @SuppressWarnings("unchecked")
                        List<Object> parameterTypes = (List<Object>) signature.getClass()
                                        .getMethod("getParameterTypes")
                                        .invoke(signature);

                        String formatted = parameterTypes.stream()
                                        .map(Object::toString)
                                        .map(this::simplifyTypeName)
                                        .collect(Collectors.joining(", ", "(", ")"));

                        return Optional.of(formatted);
                } catch (Exception ignored) {
                        return Optional.empty();
                }
        }

        private String simplifyTypeName(String rawType) {
                if (rawType == null || rawType.isBlank()) {
                        return "?";
                }

                String normalized = rawType.trim().replace('$', '.');
                int lastDot = normalized.lastIndexOf('.');
                return lastDot >= 0 ? normalized.substring(lastDot + 1) : normalized;
        }

        /**
         * Returns the subset of call graph methods whose declaring class is one of
         * the FQCNs extracted from the vulnerable JAR.
         */
        private Set<ReachableMethod> reachableByClassMatch(
                        ProjectCallGraph callGraph, Set<String> jarClasses) {
                return callGraph.reachableMethods().stream()
                                .filter(m -> jarClasses.contains(m.container()))
                                .collect(Collectors.toUnmodifiableSet());
        }

        /**
         * Fallback when the JAR could not be opened: matches by groupId prefix,
         * identical to the previous package-level behaviour.
         */
        private Set<ReachableMethod> reachableByGroupIdFallback(
                        ProjectCallGraph callGraph, LocatedArtifact artifact) {
                String groupIdPrefix = artifact.groupId().value();
                return callGraph.reachableMethods().stream()
                                .filter(m -> m.belongsToNamespace(groupIdPrefix))
                                .collect(Collectors.toUnmodifiableSet());
        }

        /**
         * Extracts the fully-qualified class names of all top-level classes in the
         * JAR. Inner classes (containing '$') are excluded — they are accessed
         * through their enclosing class.
         */
        private Set<String> extractClassNamesFromJar(Path jarPath) {
                Set<String> classes = new HashSet<>();

                try (JarFile jar = new JarFile(jarPath.toFile())) {
                        jar.stream()
                                        .filter(entry -> entry.getName().endsWith(".class"))
                                        .filter(entry -> !entry.getName().contains("$"))
                                        .map(entry -> entry.getName()
                                                        .replace('/', '.')
                                                        .replace(".class", ""))
                                        .forEach(classes::add);

                } catch (Exception e) {
                        LOG.warn("Failed to extract classes from JAR {}: {}", jarPath, e.getMessage());
                }

                return classes;
        }

        /**
         * Extracts CamelCase Java class name candidates from CVE summary and
         * description. The simple class name is used for matching so that
         * "JndiLookup" matches
         * "org.apache.logging.log4j.core.lookup.JndiLookup" in the JAR.
         */
        private Set<String> extractClassNameCandidates(Vulnerability vulnerability) {
                Set<String> candidates = new HashSet<>();
                addClassCandidates(candidates, vulnerability.summary());
                addClassCandidates(candidates, vulnerability.description());
                return Set.copyOf(candidates);
        }

        private void addClassCandidates(Set<String> candidates, String text) {
                if (text == null || text.isBlank()) {
                        return;
                }

                Matcher matcher = CLASS_TOKEN_PATTERN.matcher(text);
                while (matcher.find()) {
                        String token = matcher.group(1);
                        if (token != null && token.chars().anyMatch(Character::isLowerCase)) {
                                candidates.add(token);
                        }
                }
        }

        private Set<ReachableMethod> inferVulnerableMethods(
                        Vulnerability vulnerability,
                        Set<ReachableMethod> reachableMethods) {

                if (reachableMethods == null || reachableMethods.isEmpty()) {
                        return Set.of();
                }

                Set<String> methodNameCandidates = extractMethodNameCandidates(vulnerability);
                if (methodNameCandidates.isEmpty()) {
                        return Set.of();
                }

                return reachableMethods.stream()
                                .filter(method -> methodNameCandidates.contains(method.name().toLowerCase()))
                                .collect(Collectors.toUnmodifiableSet());
        }

        private Set<String> extractMethodNameCandidates(Vulnerability vulnerability) {
                Set<String> candidates = new HashSet<>();
                addMethodCandidates(candidates, vulnerability.summary());
                addMethodCandidates(candidates, vulnerability.description());
                return Set.copyOf(candidates);
        }

        private void addMethodCandidates(Set<String> candidates, String text) {
                if (text == null || text.isBlank()) {
                        return;
                }

                Matcher matcher = METHOD_TOKEN_PATTERN.matcher(text);
                while (matcher.find()) {
                        String token = matcher.group(1);
                        if (token != null && !token.isBlank()) {
                                candidates.add(token.toLowerCase());
                        }
                }
        }

        private String simpleClassName(String fqcn) {
                int lastDot = fqcn.lastIndexOf('.');
                return lastDot >= 0 ? fqcn.substring(lastDot + 1) : fqcn;
        }

        private List<VulnerabilityReachability> markAllUnreachable(List<Vulnerability> vulnerabilities) {
                return vulnerabilities.stream()
                                .map(VulnerabilityReachability::unreachable)
                                .toList();
        }

        private List<VulnerabilityReachability> markAllUnknown(List<Vulnerability> vulnerabilities) {
                return vulnerabilities.stream()
                                .map(VulnerabilityReachability::unknown)
                                .toList();
        }
}
