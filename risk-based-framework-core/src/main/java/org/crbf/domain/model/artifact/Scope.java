package org.crbf.domain.model.artifact;

public enum Scope {
    COMPILE,
    PROVIDED,
    RUNTIME,
    TEST,
    SYSTEM,
    IMPORT,
    UNKNOWN;

    public static Scope fromString(String scopeStr) {
        if (scopeStr == null || scopeStr.isBlank()) {
            return COMPILE;
        }
        
        try {
            return Scope.valueOf(scopeStr.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return UNKNOWN;
        }
    }

    public boolean isAnalysable() {
        return this != SYSTEM && this != IMPORT;
    }
}