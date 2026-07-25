# Contextualised Risk-Based Framework for Maven Dependency Updates

A Maven plugin that analyses transitive dependencies for known vulnerabilities (CVEs), contextualises risk via static reachability analysis, and produces an optimised remediation plan using a Z3 SMT solver. Output is an HTML report at `target/risk-report.html`.

## Architecture

The project follows a **Hexagonal (Ports & Adapters)** architecture split across two Maven modules:

```
risk-based-framework/
├── risk-based-framework-core/          # Pure library — domain model, ports, adapters
│   ├── domain/model/                   # Entities and Value objects (Artifact, Vulnerability, RiskWeights, ...)
│   ├── application/port/in|out/        # Inbound use case + outbound port interfaces
│   ├── application/service/            # AnalyseDependencyRiskService — pipeline orchestrator
│   └── adapter/out/                    # Concrete implementations (OSV, EPSS, SootUp, Z3, ...)
└── risk-based-framework-maven-plugin/  # Composition root
    └── AnalyseMojo.java                # Wires all adapters; exposes @Parameter config
```

## Prerequisites

| Requirement | Version |
|---|---|
| Java | 17+ |
| Maven | 3.8+ |
| Z3 native library | 4.12+ (must be on `java.library.path`) |
| Goblin Weaver | Optional — skipped when unavailable |

> **Reachability analysis** requires the target project to be compiled first (`mvn compile`). Without compiled bytecode, all vulnerabilities are reported with `UNKNOWN` reachability.

## Build

All commands run from the `risk-based-framework/` directory.

```bash
# Build and install to local Maven repository
mvn clean install

# Build without tests
mvn clean install -DskipTests

# Run all tests
mvn clean test
```

## Usage

Run the plugin on any Maven project:

```bash
# From the target project's root directory
mvn org.crbf:risk-based-framework-maven-plugin:1.0-SNAPSHOT:analyse
```

Or add to the target project's `pom.xml`:

```xml
<plugin>
    <groupId>org.crbf</groupId>
    <artifactId>risk-based-framework-maven-plugin</artifactId>
    <version>1.0-SNAPSHOT</version>
    <executions>
        <execution>
            <goals><goal>analyse</goal></goals>
        </execution>
    </executions>
</plugin>
```

## Configuration

All parameters are optional. Defaults are designed to work out of the box.

```xml
<configuration>

    <effortBudget>10.0</effortBudget>

    <!-- OSV vulnerability API endpoint -->
    <osvApiUrl>https://api.osv.dev/v1/query</osvApiUrl>

    <!-- Goblin Weaver base URL (set to skip if unavailable) -->
    <goblinUrl>http://localhost:8080</goblinUrl>

    <!-- Set to false to enable Goblin stability metrics -->
    <skipStabilityAnalysis>true</skipStabilityAnalysis>

    <!-- Risk signal weights — must sum to 1.00 (max 2 decimal places) -->
    <riskWeightCvss>0.50</riskWeightCvss>
    <riskWeightEpss>0.30</riskWeightEpss>
    <riskWeightStaleness>0.20</riskWeightStaleness>

    <!-- Reachability multipliers -->
    <riskWeightReachable>1.0</riskWeightReachable>
    <riskWeightUnknown>0.5</riskWeightUnknown>
    <riskWeightUnreachable>0.1</riskWeightUnreachable>
</configuration>
```
