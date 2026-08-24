package org.crbf.adapter.out.osv;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
record OsvQueryResponse(List<OsvVulnerabilityDto> vulns) {

        @JsonIgnoreProperties(ignoreUnknown = true)
        record OsvVulnerabilityDto(
                        String id,
                        String summary,
                        String details,
                        List<String> aliases,
                        String published,
                        String modified,
                        List<OsvSeverityDto> severity,
                        List<OsvAffectedDto> affected,
                        List<OsvReferenceDto> references,
                        @JsonProperty("database_specific") OsvDatabaseSpecificDto databaseSpecific) {
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        record OsvSeverityDto(String type, String score) {
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        record OsvAffectedDto(
                        @JsonProperty("package") OsvPackageDto pkg,
                        List<OsvRangeDto> ranges) {
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        record OsvPackageDto(
                        String ecosystem,
                        String name) {
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        record OsvRangeDto(List<OsvEventDto> events) {
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        record OsvEventDto(String fixed) {
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        record OsvReferenceDto(
                        String type,
                        String url) {
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        record OsvDatabaseSpecificDto(
                        @JsonProperty("cwe_ids") List<String> cweIds) {
        }
}