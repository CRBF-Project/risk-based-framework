package org.crbf.adapter.out.export;

import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.json.JsonWriteFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.crbf.application.model.report.RiskReport;
import org.crbf.application.port.out.ExportRiskReportPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ReportGeneratorAdapter implements ExportRiskReportPort {

    private static final Logger LOG = LoggerFactory.getLogger(ReportGeneratorAdapter.class);

    private final ObjectMapper mapper;

    public ReportGeneratorAdapter() {
        this.mapper = new ObjectMapper();
        this.mapper.registerModule(new Jdk8Module());
        this.mapper.enable(SerializationFeature.INDENT_OUTPUT);
        this.mapper.configure(JsonWriteFeature.ESCAPE_NON_ASCII.mappedFeature(), true);
        this.mapper.setVisibility(PropertyAccessor.GETTER, Visibility.PUBLIC_ONLY);
    }

    @Override
    public void exportReport(RiskReport report, Path outputDirectory) {
        try {
            File targetDir = outputDirectory.toFile();
            if (!targetDir.exists())
                targetDir.mkdirs();

            String jsonString = mapper.writeValueAsString(report);

            File jsonFile = new File(targetDir, "risk-report.json");
            mapper.writeValue(jsonFile, report);
            LOG.info("JSON Report generated at: {}", jsonFile.getAbsolutePath());

            File htmlFile = new File(targetDir, "risk-report.html");
            generateHtmlDashboard(htmlFile, jsonString);
            LOG.info("HTML Dashboard generated at: {}", htmlFile.getAbsolutePath());

        } catch (IOException e) {
            LOG.error("Error exporting report: {}", e.getMessage());
        }
    }

    private void generateHtmlDashboard(File htmlFile, String jsonString) throws IOException {
        try (InputStream is = getClass().getResourceAsStream("/report-template.html")) {
            if (is == null) {
                throw new IOException("Report template not found on classpath: /report-template.html");
            }
            String html = new String(is.readAllBytes(), StandardCharsets.UTF_8)
                    .replace("REPORT_DATA_PLACEHOLDER", jsonString);
            Files.writeString(htmlFile.toPath(), html, StandardCharsets.UTF_8);
        }
    }
}
