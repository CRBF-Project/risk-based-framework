package org.crbf.application.port.out;

import org.crbf.domain.model.vulnerability.Vulnerability;
import java.util.List;

public interface LoadEpssScoresPort {
    List<Vulnerability> enrich(List<Vulnerability> vulnerabilities);
}