package org.crbf.domain.model.compatibility;

/**
 * Classifies the binary and source compatibility between two versions of
 * the same artifact.
 *
 * COMPATIBLE — No API changes that would break compilation or
 *              runtime behaviour. Safe to upgrade.
 *
 * SOURCE_INCOMPATIBLE — Changes break source compilation (e.g. a method
 *                       signature changed) but may still run if the
 *                       project was compiled against the old version.
 *
 * BINARY_INCOMPATIBLE — Changes break the binary contract (e.g. a method
 *                       as removed, or its return type changed). Any
 *                       project compiled against the old version will
 *                       throw a LinkageError or NoSuchMethodError at
 *                       runtime. This is the most dangerous category.
 *
 * UNKNOWN — The comparison could not be performed (e.g. JARs
 *           unavailable, download failed, or timeout).
 */
public enum CompatibilityStatus {
    COMPATIBLE,
    SOURCE_INCOMPATIBLE,
    BINARY_INCOMPATIBLE,
    UNKNOWN
}