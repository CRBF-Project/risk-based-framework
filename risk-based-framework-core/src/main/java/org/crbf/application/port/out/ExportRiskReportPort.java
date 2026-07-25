package org.crbf.application.port.out;

import java.nio.file.Path;
import org.crbf.application.model.report.RiskReport;

public interface ExportRiskReportPort {
    public void exportReport(RiskReport report, Path outputDirectory);
}
