package org.crbf.adapter.out.japicmp;

import japicmp.model.JApiChangeStatus;
import japicmp.model.JApiClass;
import japicmp.model.JApiCompatibilityChange;
import japicmp.model.JApiConstructor;
import japicmp.model.JApiMethod;
import japicmp.model.JApiField;
import org.crbf.domain.model.artifact.Artifact;
import org.crbf.domain.model.compatibility.CompatibilityReport;
import org.crbf.domain.model.compatibility.CompatibilityStatus;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Maps the raw japicmp output ({@link JApiClass} list) to the domain
 * object {@link CompatibilityReport}.
 */
class JapicmpCompatibilityMapper {

    CompatibilityReport toDomain(
            Artifact from, Artifact to, List<JApiClass> jApiClasses) {

        List<String> breakingChanges = new ArrayList<>();
        boolean hasBinaryBreak = false;
        boolean hasSourceBreak = false;

        for (JApiClass jApiClass : jApiClasses) {
            if (jApiClass.getChangeStatus() == JApiChangeStatus.UNCHANGED) {
                continue;
            }

            for (JApiCompatibilityChange change : jApiClass.getCompatibilityChanges()) {
                if (!change.isBinaryCompatible()) {
                    hasBinaryBreak = true;
                    breakingChanges.add(formatClassChange(jApiClass, change, "BINARY"));
                } else if (!change.isSourceCompatible()) {
                    hasSourceBreak = true;
                    breakingChanges.add(formatClassChange(jApiClass, change, "SOURCE"));
                }
            }

            // Report individual method-level breaking changes.
            for (JApiMethod method : jApiClass.getMethods()) {
                for (JApiCompatibilityChange change : method.getCompatibilityChanges()) {
                    if (!change.isBinaryCompatible()) {
                        hasBinaryBreak = true;
                        breakingChanges.add(formatMethodChange(
                                jApiClass.getFullyQualifiedName(), method, change, "BINARY"));
                    } else if (!change.isSourceCompatible()) {
                        hasSourceBreak = true;
                        breakingChanges.add(formatMethodChange(
                                jApiClass.getFullyQualifiedName(), method, change, "SOURCE"));
                    }
                }
            }

            for (JApiConstructor constructor : jApiClass.getConstructors()) {
                for (JApiCompatibilityChange change : constructor.getCompatibilityChanges()) {
                    if (!change.isBinaryCompatible()) {
                        hasBinaryBreak = true;
                        breakingChanges.add(formatMemberChange(
                                jApiClass.getFullyQualifiedName(),
                                "constructor", "<init>", change, "BINARY"));
                    } else if (!change.isSourceCompatible()) {
                        hasSourceBreak = true;
                        breakingChanges.add(formatMemberChange(
                                jApiClass.getFullyQualifiedName(),
                                "constructor", "<init>", change, "SOURCE"));
                    }
                }
            }

            for (JApiField field : jApiClass.getFields()) {
                for (JApiCompatibilityChange change : field.getCompatibilityChanges()) {
                    if (!change.isBinaryCompatible()) {
                        hasBinaryBreak = true;
                        breakingChanges.add(formatMemberChange(
                                jApiClass.getFullyQualifiedName(),
                                "field", field.getName(), change, "BINARY"));
                    } else if (!change.isSourceCompatible()) {
                        hasSourceBreak = true;
                        breakingChanges.add(formatMemberChange(
                                jApiClass.getFullyQualifiedName(),
                                "field", field.getName(), change, "SOURCE"));
                    }
                }
            }
        }

        CompatibilityStatus status;
        if (hasBinaryBreak) {
            status = CompatibilityStatus.BINARY_INCOMPATIBLE;
        } else if (hasSourceBreak) {
            status = CompatibilityStatus.SOURCE_INCOMPATIBLE;
        } else {
            status = CompatibilityStatus.COMPATIBLE;
        }

        return new CompatibilityReport(from, to, status, breakingChanges);
    }

    private String formatClassChange(
            JApiClass cls, JApiCompatibilityChange change, String level) {
        return String.format("[%s] Class %s — %s (%s)",
                level,
                cls.getFullyQualifiedName(),
                change.getType().name(),
                cls.getChangeStatus().name());
    }

    private String formatMethodChange(
            String className, JApiMethod method,
            JApiCompatibilityChange change, String level) {
        String params = method.getParameters().stream()
                .map(p -> simplifyType(p.getType()))
                .collect(Collectors.joining(", ", "(", ")"));
        return String.format("[%s] Method %s#%s%s — %s",
                level, className, method.getName(), params, change.getType().name());
    }

    private String formatMemberChange(
            String className, String memberType, String memberName,
            JApiCompatibilityChange change, String level) {
        return String.format("[%s] %s %s#%s — %s",
                level,
                Character.toUpperCase(memberType.charAt(0)) + memberType.substring(1),
                className,
                memberName,
                change.getType().name());
    }

    private String simplifyType(String fqType) {
        if (fqType == null || fqType.isBlank())
            return "?";
        int lastDot = fqType.lastIndexOf('.');
        return lastDot >= 0 ? fqType.substring(lastDot + 1) : fqType;
    }
}