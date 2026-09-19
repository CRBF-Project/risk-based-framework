package org.crbf.adapter.out.wala;

import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.classLoader.Language;
import com.ibm.wala.core.util.config.AnalysisScopeReader;
import com.ibm.wala.ipa.callgraph.AnalysisCacheImpl;
import com.ibm.wala.ipa.callgraph.AnalysisOptions;
import com.ibm.wala.ipa.callgraph.AnalysisScope;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.CallGraphBuilder;
import com.ibm.wala.ipa.callgraph.Entrypoint;
import com.ibm.wala.ipa.callgraph.IAnalysisCacheView;
import com.ibm.wala.ipa.callgraph.impl.ArgumentTypeEntrypoint;
import com.ibm.wala.ipa.callgraph.impl.Util;
import com.ibm.wala.ipa.callgraph.propagation.InstanceKey;
import com.ibm.wala.ipa.cha.ClassHierarchyFactory;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.types.TypeName;
import org.crbf.application.port.out.AnalyseReachabilityPort;
import org.crbf.domain.model.artifact.LocatedArtifact;
import org.crbf.domain.model.reachability.ProjectCallGraph;
import org.crbf.domain.model.reachability.ReachableMethod;
import org.crbf.domain.model.reachability.ReachabilityStatus;
import org.crbf.domain.model.reachability.VulnerabilityReachability;
import org.crbf.domain.model.vulnerability.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Outbound adapter that performs Static Reachability Analysis (SRA) using
 * WALA's 0-CFA points-to-based call graph construction
 * (https://github.com/wala/WALA).
 *
 * Two-phase design:
 * 1. {@link #buildCallGraph} — builds the full 0-CFA call graph once per
 * analysis run, excluding the JDK (Primordial loader) and synthetic
 * (fake-root) nodes from the reachable set.
 * 2. {@link #analyseReachability} — class/method matching against the
 * pre-built graph. Safe to call for every vulnerable artifact.
 *
 * Fallback: if analysis fails for any reason (missing classes, JVM mismatch,
 * timeout, etc.), the result is UNKNOWN, which the service layer treats
 * conservatively as potentially REACHABLE — never producing false negatives.
 */
public class WalaReachabilityAdapter implements AnalyseReachabilityPort {

        private static final Logger LOG = LoggerFactory.getLogger(WalaReachabilityAdapter.class);

        // Matches CamelCase Java class name tokens in CVE text, e.g. "JndiLookup",
        // "StringSubstitutor", "XStream".
        private static final Pattern CLASS_TOKEN_PATTERN = Pattern.compile(
                        "\\b([A-Z][A-Za-z0-9]{2,})\\b");

        // Matches method-like references: "foo(", "Class.foo(", "#foo", "foo()".
        private static final Pattern METHOD_TOKEN_PATTERN = Pattern.compile(
                        "(?:#|\\b)([A-Za-z_][A-Za-z0-9_]*)\\s*(?:\\(|\\))");

        // Class hierarchy exclusions applied scope-wide (Primordial, Extension and
        // Application loaders alike — see AnalysisScope#exclusions) to avoid known
        // CHA-construction trouble spots: JDK GUI toolkits, vendor-internal/native
        // packages sealed since Java 9, and legacy CORBA/Dalvik/Apple bits. Adapted
        // from the exclusions bundled in WALA's own com.ibm.wala.core jar
        // (Java60RegressionExclusions.txt)
        private static final String DEFAULT_CALL_GRAPH_EXCLUSIONS = String.join(";",
                        "java/awt/.*",
                        "javax/swing/.*",
                        "sun/awt/.*",
                        "sun/swing/.*",
                        "com/sun/.*",
                        "sun/.*",
                        "org/netbeans/.*",
                        "org/openide/.*",
                        "com/ibm/crypto/.*",
                        "com/ibm/security/.*",
                        "dalvik/.*",
                        "java/io/ObjectStreamClass*",
                        "apple/.*",
                        "com/apple/.*",
                        "com/oracle/.*",
                        "jdk/.*",
                        "org/omg/.*",
                        "org/w3c/.*");

        // WALA's propagation-based call graph construction has no built-in time
        // bound: a large or reflection-heavy dependency graph can run for a very
        // long time. This default keeps a single analysis run within a practical
        // CI/local-build budget; callers can override it via the constructor.
        private static final int DEFAULT_CALL_GRAPH_TIMEOUT_SECONDS = 120;

        private final int callGraphTimeoutSeconds;
        private final String callGraphExclusions;

        public WalaReachabilityAdapter() {
                this(DEFAULT_CALL_GRAPH_TIMEOUT_SECONDS, DEFAULT_CALL_GRAPH_EXCLUSIONS);
        }

        public WalaReachabilityAdapter(int callGraphTimeoutSeconds) {
                this(callGraphTimeoutSeconds, DEFAULT_CALL_GRAPH_EXCLUSIONS);
        }

        /**
         * @param callGraphTimeoutSeconds Maximum time allowed for 0-CFA call graph
         *                                construction.
         * @param callGraphExclusions     Semicolon-separated regular expressions
         *                                (JVM-internal slash notation, e.g.
         *                                {@code java/awt/.*}) identifying classes
         *                                to exclude from class-hierarchy
         *                                construction entirely. Applies to every
         *                                loader (JDK, dependencies, application
         *                                code) — see {@link #DEFAULT_CALL_GRAPH_EXCLUSIONS}.
         */
        public WalaReachabilityAdapter(int callGraphTimeoutSeconds, String callGraphExclusions) {
                if (callGraphTimeoutSeconds <= 0) {
                        throw new IllegalArgumentException(
                                        "callGraphTimeoutSeconds must be positive, was: " + callGraphTimeoutSeconds);
                }
                this.callGraphTimeoutSeconds = callGraphTimeoutSeconds;
                this.callGraphExclusions = callGraphExclusions == null || callGraphExclusions.isBlank()
                                ? DEFAULT_CALL_GRAPH_EXCLUSIONS
                                : callGraphExclusions;
        }

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

        private Set<ReachableMethod> buildReachableMethodSet(Path projectClassesPath, List<Path> allProjectJars)
                        throws Exception {

                java.io.File exclusionsFile = writeExclusionsFile();
                AnalysisScope scope = AnalysisScopeReader.instance.makePrimordialScope(exclusionsFile);

                AnalysisScopeReader.instance.addClassPathToScope(
                                projectClassesPath.toAbsolutePath().toString(),
                                scope,
                                scope.getApplicationLoader());

                List<String> skippedJars = new ArrayList<>();

                for (Path jarPath : allProjectJars) {
                        if (jarPath == null || !jarPath.toFile().exists()) {
                                continue;
                        }

                        try {
                                AnalysisScopeReader.instance.addClassPathToScope(
                                                jarPath.toAbsolutePath().toString(),
                                                scope,
                                                scope.getExtensionLoader());
                        } catch (Throwable t) {
                                // WALA follows Class-Path manifest entries and fails hard
                                // (UnimplementedError, an Error) when a referenced sibling JAR is
                                // absent, which is common in the Maven repository layout. A single
                                // malformed manifest must not abort the whole analysis.
                                skippedJars.add(jarPath.getFileName().toString());
                                LOG.warn("Skipping {} in call graph scope: {}",
                                                jarPath.getFileName(), t.getMessage());
                        }
                }

                if (!skippedJars.isEmpty()) {
                        LOG.warn("{} JAR(s) excluded from the call graph scope; reachability for classes "
                                        + "they contain may be under-approximated: {}",
                                        skippedJars.size(), skippedJars);
                }

                IClassHierarchy cha = ClassHierarchyFactory.make(scope);
                Set<Entrypoint> entryPoints = collectEntryPoints(scope, cha);

                if (entryPoints.isEmpty()) {
                        LOG.warn("No entry points found. Ensure the project is compiled and contains public methods.");
                        return Set.of();
                }

                AnalysisOptions options = new AnalysisOptions(scope, entryPoints);
                IAnalysisCacheView cache = new AnalysisCacheImpl();
                CallGraphBuilder<InstanceKey> builder = Util.makeZeroCFABuilder(
                                Language.JAVA, options, cache, cha);
                CallGraph callGraph = makeCallGraphWithTimeout(builder, options);

                return collectReachableMethods(callGraph, scope);
        }

        /**
         * Materialises {@link #callGraphExclusions} as the newline-separated regex
         * file WALA's {@code AnalysisScopeReader} expects. Written fresh per run
         * (not cached) since the exclusions can differ between adapter instances.
         */
        private java.io.File writeExclusionsFile() throws java.io.IOException {
                String content = String.join(
                                System.lineSeparator(),
                                callGraphExclusions.split(";"));
                java.nio.file.Path tempFile = java.nio.file.Files.createTempFile("wala-cha-exclusions", ".txt");
                java.nio.file.Files.writeString(tempFile, content);
                tempFile.toFile().deleteOnExit();
                return tempFile.toFile();
        }

        /**
         * Runs WALA's (otherwise unbounded) call graph construction on a daemon
         * worker thread, bounded by {@link #callGraphTimeoutSeconds}. On timeout,
         * the worker is interrupted (best-effort — WALA does not guarantee prompt
         * cancellation) and an exception is thrown, which {@link #buildCallGraph}
         * already treats as a hard failure, falling back to an empty call graph.
         */
        private CallGraph makeCallGraphWithTimeout(
                        CallGraphBuilder<InstanceKey> builder, AnalysisOptions options) throws Exception {
                FutureTask<CallGraph> task = new FutureTask<>(() -> builder.makeCallGraph(options, null));
                Thread worker = new Thread(task, "wala-callgraph-construction");
                worker.setDaemon(true);
                worker.start();

                try {
                        return task.get(callGraphTimeoutSeconds, TimeUnit.SECONDS);
                } catch (TimeoutException e) {
                        task.cancel(true);
                        throw new IllegalStateException(
                                        "Call graph construction exceeded " + callGraphTimeoutSeconds
                                                        + "s timeout", e);
                } catch (ExecutionException e) {
                        Throwable cause = e.getCause();
                        if (cause instanceof Exception exception) {
                                throw exception;
                        }
                        throw new IllegalStateException("Call graph construction failed: " + cause, cause);
                }
        }

        /**
         * Collects all public/protected, non-abstract methods of Application
         * classes as 0-CFA entry points.
         */
        private Set<Entrypoint> collectEntryPoints(AnalysisScope scope, IClassHierarchy cha) {
                Set<Entrypoint> entryPoints = new HashSet<>();

                for (IClass klass : cha) {
                        if (klass.isInterface()) {
                                continue;
                        }
                        if (!scope.getApplicationLoader().equals(klass.getClassLoader().getReference())) {
                                continue;
                        }
                        for (IMethod method : klass.getDeclaredMethods()) {
                                if (!method.isAbstract() && (method.isPublic() || method.isProtected())) {
                                        entryPoints.add(new ArgumentTypeEntrypoint(method, cha));
                                }
                        }
                }

                return entryPoints;
        }

        /**
         * Extracts all transitively reachable methods from the call graph,
         * excluding methods declared in the JDK (Primordial loader) and
         * synthetic (fake-root) nodes.
         */
        private Set<ReachableMethod> collectReachableMethods(CallGraph callGraph, AnalysisScope scope) {
                Set<ReachableMethod> result = new HashSet<>();

                for (CGNode node : callGraph) {
                        IMethod method = node.getMethod();
                        ClassLoaderReference loader = method.getDeclaringClass().getClassLoader().getReference();

                        if (loader.equals(scope.getPrimordialLoader()) || loader.equals(scope.getSyntheticLoader())) {
                                continue;
                        }

                        result.add(ReachableMethod.of(
                                        fullyQualifiedClassName(method),
                                        method.getName().toString(),
                                        Optional.of(extractSignature(method))));
                }

                return Set.copyOf(result);
        }

        private String fullyQualifiedClassName(IMethod method) {
                TypeName typeName = method.getDeclaringClass().getName();
                String packageName = typeName.getPackage() == null
                                ? ""
                                : typeName.getPackage().toString().replace('/', '.');
                String simpleName = typeName.getClassName().toString();
                return packageName.isEmpty() ? simpleName : packageName + "." + simpleName;
        }

        /**
         * Builds a "(Param1, Param2)" style signature from WALA's parameter
         * types — the format {@link ReachableMethod#signature()} is expected to
         * carry, since it is compared verbatim against japicmp-derived method
         * ids in {@link ProjectCallGraph#containsMethodId}. {@code IMethod}'s
         * own {@link IMethod#getSignature()} returns a full
         * "declaringClass.methodName(descriptor)returnDescriptor" string, which
         * is a different format and must not be used here directly.
         *
         * WALA includes an implicit "this" as parameter 0 for instance methods
         * (see e.g. AllApplicationEntrypoints/ArgumentTypeEntrypoint usage
         * upstream), so it is skipped for non-static methods.
         */
        private String extractSignature(IMethod method) {
                int start = method.isStatic() ? 0 : 1;
                int count = method.getNumberOfParameters();
                StringBuilder sb = new StringBuilder("(");
                for (int i = start; i < count; i++) {
                        if (i > start) {
                                sb.append(", ");
                        }
                        sb.append(simpleTypeName(method.getParameterType(i)));
                }
                return sb.append(")").toString();
        }

        private String simpleTypeName(com.ibm.wala.types.TypeReference type) {
                if (type.isArrayType()) {
                        return simpleTypeName(type.getArrayElementType()) + "[]";
                }
                if (type.isPrimitiveType()) {
                        return switch (type.getName().getClassName().toString()) {
                                case "Z" -> "boolean";
                                case "B" -> "byte";
                                case "C" -> "char";
                                case "D" -> "double";
                                case "F" -> "float";
                                case "I" -> "int";
                                case "J" -> "long";
                                case "S" -> "short";
                                case "V" -> "void";
                                default -> type.getName().getClassName().toString();
                        };
                }
                return type.getName().getClassName().toString();
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
