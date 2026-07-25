package org.crbf.adapter.out.goblin;

import org.crbf.domain.model.optimisation.UpgradeCandidate;

import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;

// Candidates are sorted ascending by semantic version so findBestFixVersion()
// selects the minimum qualifying version — smallest upgrade, least risk of breakage.

public class GoblinWeaverUpgradeCandidateMapper {

    private static final Pattern PRE_RELEASE_PATTERN =
            Pattern.compile("(?i)(alpha|beta|rc|snapshot|m\\d+)");

    List<UpgradeCandidate> toDomain(GoblinWeaverReleaseResponse response) {
        if (response == null || response.nodes() == null) return List.of();

        return response.nodes().stream()
                .filter(node -> "RELEASE".equals(node.nodeType()))
                .filter(node -> node.version() != null && !node.version().isBlank())
                .filter(node -> !isPreRelease(node.version()))
                .map(this::toDomain)
                .sorted(Comparator.comparing(UpgradeCandidate::version))
                .toList();
    }

    private UpgradeCandidate toDomain(GoblinWeaverReleaseResponse.GoblinNodeDto dto) {
        List<String> cveIds = dto.cveAggregated() == null ? List.of() :
                dto.cveAggregated().stream()
                .map(GoblinWeaverReleaseResponse.GoblinCveDto::name)
                .filter(name -> name != null && !name.isBlank())
                .toList();

        return UpgradeCandidate.create(dto.version(), cveIds);
    }

    private boolean isPreRelease(String version) {
        return PRE_RELEASE_PATTERN.matcher(version).find();
    }

}
