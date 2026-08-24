package org.crbf.application.model.report;

/**
 * Splits total residual risk (deferred candidates' contextual risk, summed)
 * by whether a remediation path is actually known, so the two are never
 * conflated into a single number:
 *
 * @param actionable Risk that remains only because it wasn't selected this
 *                    round — either deferred for budget reasons with a real
 *                    fix available, or a migration path is known
 *                    ({@code MIGRATION_AVAILABLE}). The optimiser (or a
 *                    human, for migrations) could act on this.
 * @param blocked     Risk with no known remediation path at all — no fix
 *                     version, no alternative artifact. Nothing short of a
 *                     new upstream release changes this.
 */
public record ResidualRiskSummary(double actionable, double blocked) {}
