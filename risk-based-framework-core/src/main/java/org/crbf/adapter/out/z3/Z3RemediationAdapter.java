package org.crbf.adapter.out.z3;

import com.microsoft.z3.ArithExpr;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Context;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Model;
import com.microsoft.z3.Optimize;
import com.microsoft.z3.RealExpr;
import com.microsoft.z3.RealSort;
import com.microsoft.z3.Status;
import org.crbf.application.port.out.OptimiseRemediationPort;
import org.crbf.domain.model.compatibility.CompatibilityStatus;
import org.crbf.domain.model.optimisation.GlobalGraphValidation;
import org.crbf.domain.model.optimisation.InfeasibilityDetails;
import org.crbf.domain.model.optimisation.OptimisationStatus;
import org.crbf.domain.model.optimisation.RemediationCandidate;
import org.crbf.domain.model.optimisation.RemediationDecision;
import org.crbf.domain.model.optimisation.RemediationPlan;
import org.crbf.domain.model.optimisation.RiskWeights;
import org.crbf.domain.model.stability.StabilityScore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Outbound adapter that solves the remediation selection problem using the
 * Z3 SMT Optimise API (https://github.com/Z3Prover/z3).
 *
 * Subject to:
 * (C1) budget capacity
 * (C2) no fix = no upgrade
 * (C3) mandatory upgrades
 */
public class Z3RemediationAdapter implements OptimiseRemediationPort {

    private static final Logger LOG = LoggerFactory.getLogger(Z3RemediationAdapter.class);

    private final double effortBudget;
    private final RiskWeights riskWeights;
    private final Supplier<Context> contextFactory;

    /**
     * @param effortBudget Maximum total effort units available for upgrades.
     *                     Typical values: 10–20 units.
     *                     See {@link RemediationCandidate#upgradeCost()} for the
     *                     effort cost definitions per compatibility category.
     */
    public Z3RemediationAdapter(double effortBudget) {
        this(effortBudget, RiskWeights.defaults());
    }

    public Z3RemediationAdapter(double effortBudget, RiskWeights riskWeights) {
        this(effortBudget, riskWeights, Context::new);
    }

    // Allows deterministic testing of failure at the external solver boundary.
    Z3RemediationAdapter(double effortBudget, RiskWeights riskWeights, Supplier<Context> contextFactory) {
        if (effortBudget <= 0) {
            throw new IllegalArgumentException("Effort budget must be positive. Received: " + effortBudget);
        }
        this.effortBudget = effortBudget;
        this.riskWeights = riskWeights;
        this.contextFactory = contextFactory;
    }

    @Override
    public RemediationPlan optimize(List<RemediationCandidate> candidates) {
        List<RemediationCandidate> vulnerable = candidates.stream()
                .filter(c -> !c.vulnerabilities().isEmpty())
                .toList();

        if (vulnerable.isEmpty()) {
            return RemediationPlan.empty().withEffortBudget(effortBudget);
        }

        LOG.info("Starting optimisation — {} candidates, effort budget: {} units", vulnerable.size(), effortBudget);


        double mandatoryEffort = vulnerable.stream()
                .filter(RemediationCandidate::isMandatoryUpgrade)
                .mapToDouble(RemediationCandidate::upgradeCost)
                .sum();
        if (mandatoryEffort > effortBudget) {
            return infeasiblePlan(vulnerable, InfeasibilityDetails.Reason.MANDATORY_EFFORT_EXCEEDS_BUDGET)
                    .withEffortBudget(effortBudget);
        }

        try (Context ctx = contextFactory.get()) {
            return solveWithZ3(ctx, vulnerable).withEffortBudget(effortBudget);
        } catch (Exception | LinkageError e) {
            LOG.error("Z3 optimisation failed ({}). Falling back to greedy selection.", e.getMessage());
            return greedyFallback(vulnerable).withEffortBudget(effortBudget);
        }
    }

    @SuppressWarnings("unchecked")
    private RemediationPlan solveWithZ3(Context ctx, List<RemediationCandidate> candidates) {
        Optimize optimizer = ctx.mkOptimize();
        int n = candidates.size();

        BoolExpr[] upgradeVars = declareDecisionVariables(ctx, n);

        applyHardConstraints(ctx, optimizer, candidates, upgradeVars);

        ArithExpr<RealSort> totalRiskReduction = buildRiskObjective(ctx, candidates, upgradeVars);
        ArithExpr<RealSort> totalEffort = buildEffortSum(ctx, candidates, upgradeVars);

        optimizer.MkMaximize(totalRiskReduction);
        BoolExpr budgetConstraint = ctx.mkLe(totalEffort, ctx.mkReal(Double.toString(effortBudget)));
        optimizer.Add(budgetConstraint);

        Status status = optimizer.Check();

        if (status == Status.SATISFIABLE) {
            LOG.info("Optimal solution found.");
            return extractPlan(optimizer.getModel(), candidates, upgradeVars);
        }

        if (status == Status.UNSATISFIABLE) {
            return infeasiblePlan(candidates, InfeasibilityDetails.Reason.UNSATISFIABLE_CONSTRAINTS);
        }

        LOG.warn("Z3 could not determine a solution ({}). Falling back to greedy selection.", optimizer.getReasonUnknown());
        return greedyFallback(candidates);
    }

    private RemediationPlan infeasiblePlan(List<RemediationCandidate> candidates, InfeasibilityDetails.Reason cause) {
        String reason = cause == InfeasibilityDetails.Reason.MANDATORY_EFFORT_EXCEEDS_BUDGET
                ? "No feasible remediation solution: mandatory upgrades exceed the effort budget."
                : "No feasible remediation solution: the update constraints cannot all be satisfied.";
        LOG.warn(reason);
        List<RemediationDecision> decisions = candidates.stream()
                .map(c -> RemediationDecision.defer(c.artifact(),
                        (!c.hasFixAvailable() ? "No fix version available. "
                                : c.isMandatoryUpgrade() ? "Mandatory upgrade pending. " : "Optional upgrade not selected. ") + reason))
                .toList();
        double residualRisk = candidates.stream()
                .mapToDouble(c -> c.contextualRisk(riskWeights)).sum();
        List<InfeasibilityDetails.MandatoryUpgrade> pending = candidates.stream()
                .filter(RemediationCandidate::isMandatoryUpgrade)
                .map(c -> new InfeasibilityDetails.MandatoryUpgrade(
                        c.artifact().gav(), c.fixVersion().orElseThrow(), c.upgradeCost()))
                .toList();
        return new RemediationPlan(decisions, 0.0, residualRisk, 0.0,
                OptimisationStatus.INFEASIBLE, GlobalGraphValidation.notRun(),
                Optional.of(InfeasibilityDetails.of(cause, effortBudget, pending)));
    }

    private BoolExpr[] declareDecisionVariables(Context ctx, int n) {
        BoolExpr[] vars = new BoolExpr[n];
        for (int i = 0; i < n; i++) {
            vars[i] = ctx.mkBoolConst("upgrade_" + i);
        }
        return vars;
    }

    @SuppressWarnings("unchecked")
    private void applyHardConstraints(
            Context ctx, Optimize optimizer,
            List<RemediationCandidate> candidates, BoolExpr[] upgradeVars) {

        for (int i = 0; i < candidates.size(); i++) {
            RemediationCandidate c = candidates.get(i);

            if (!c.hasFixAvailable()) {
                BoolExpr noFixAvailableConstraint = ctx.mkNot(upgradeVars[i]);
                optimizer.Add(noFixAvailableConstraint);
            } else if (c.isMandatoryUpgrade()) {
                optimizer.Add(upgradeVars[i]);
                LOG.info("Hard constraint: {} is CRITICAL+REACHABLE (mandatory upgrade).", c.artifact().gav());
            }
        }
    }

    private ArithExpr<RealSort> buildRiskObjective(
            Context ctx, List<RemediationCandidate> candidates, BoolExpr[] upgradeVars) {

        RealExpr[] terms = new RealExpr[candidates.size()];
        for (int i = 0; i < candidates.size(); i++) {
            double risk = candidates.get(i).contextualRisk(riskWeights);
            terms[i] = (RealExpr) ctx.mkITE(
                    upgradeVars[i],
                    ctx.mkReal(Double.toString(risk)),
                    ctx.mkReal("0"));
        }
        return ctx.mkAdd(terms);
    }

    private ArithExpr<RealSort> buildEffortSum(
            Context ctx, List<RemediationCandidate> candidates, BoolExpr[] upgradeVars) {

        RealExpr[] terms = new RealExpr[candidates.size()];
        for (int i = 0; i < candidates.size(); i++) {
            RemediationCandidate c = candidates.get(i);
            double cost = c.hasFixAvailable() ? c.upgradeCost() : 0.0;
            terms[i] = (RealExpr) ctx.mkITE(
                    upgradeVars[i],
                    ctx.mkReal(Double.toString(cost)),
                    ctx.mkReal("0"));
        }
        return ctx.mkAdd(terms);
    }

    // -------------------------------------------------------------------------
    // Plan Extraction
    // -------------------------------------------------------------------------

    private RemediationPlan extractPlan(
            Model model,
            List<RemediationCandidate> candidates,
            BoolExpr[] upgradeVars) {

        List<RemediationDecision> decisions = new ArrayList<>();
        double totalRiskReduction = 0.0;
        double totalResidualRisk = 0.0;
        double totalEffort = 0.0;

        for (int i = 0; i < candidates.size(); i++) {
            RemediationCandidate c = candidates.get(i);

            Expr<?> evaluated = model.evaluate(upgradeVars[i], true);
            boolean shouldUpgrade = evaluated != null && evaluated.isTrue();

            RemediationDecision decision;
            if (shouldUpgrade) {
                double risk = c.contextualRisk(riskWeights);
                double effort = c.upgradeCost();
                totalRiskReduction += risk;
                totalEffort += effort;
                decision = RemediationDecision.upgrade(
                        c.artifact(), c.fixVersion().orElseThrow(), risk, effort,
                        buildUpgradeRationale(c));
            } else {
                totalResidualRisk += c.contextualRisk(riskWeights);
                decision = RemediationDecision.defer(
                        c.artifact(),
                        buildDeferRationale(c));
            }
            decisions.add(decision);
        }

        return new RemediationPlan(decisions, totalRiskReduction, totalResidualRisk, totalEffort,
                OptimisationStatus.OPTIMAL, GlobalGraphValidation.notRun());
    }

    // -------------------------------------------------------------------------
    // Greedy Fallback
    // -------------------------------------------------------------------------

    /**
     * Greedy fallback for technical solver failures, after feasibility is checked.
     * Reserves effort for mandatory upgrades before spending on optional upgrades
     * in descending order of risk/effort ratio. It does not guarantee optimality.
     */
    private RemediationPlan greedyFallback(List<RemediationCandidate> candidates) {
        LOG.info("Running greedy fallback selection.");

        List<RemediationCandidate> sorted = candidates.stream()
                .filter(RemediationCandidate::hasFixAvailable)
                .sorted((a, b) -> Double.compare(
                        b.contextualRisk(riskWeights) / b.upgradeCost(),
                        a.contextualRisk(riskWeights) / a.upgradeCost()))
                .toList();

        double remainingBudget = effortBudget - sorted.stream()
                .filter(RemediationCandidate::isMandatoryUpgrade)
                .mapToDouble(RemediationCandidate::upgradeCost).sum();
        List<RemediationDecision> decisions = new ArrayList<>();
        double totalRiskReduction = 0.0;
        double totalResidualRisk = 0.0;
        double totalEffort = 0.0;

        for (RemediationCandidate c : sorted) {
            boolean fits = c.upgradeCost() <= remainingBudget;
            boolean forced = c.isMandatoryUpgrade();

            if (fits || forced) {
                double risk = c.contextualRisk(riskWeights);
                double effort = c.upgradeCost();
                if (!forced)
                    remainingBudget -= effort;
                totalRiskReduction += risk;
                totalEffort += effort;
                decisions.add(RemediationDecision.upgrade(
                        c.artifact(), c.fixVersion().orElseThrow(), risk, effort,
                        forced ? "Greedy fallback (mandatory: CRITICAL+REACHABLE)."
                                : "Greedy fallback: highest risk/effort ratio within budget."));
            } else {
                totalResidualRisk += c.contextualRisk(riskWeights);
                decisions.add(RemediationDecision.defer(
                        c.artifact(), "Greedy fallback: insufficient budget remaining."));
            }
        }

        for (RemediationCandidate c : candidates) {
            if (!c.hasFixAvailable()) {
                decisions.add(RemediationDecision.defer(c.artifact(), "No fix version available."));
                totalResidualRisk += c.contextualRisk(riskWeights);
            }
        }

        return new RemediationPlan(decisions, totalRiskReduction, totalResidualRisk, totalEffort,
                OptimisationStatus.GREEDY_FALLBACK, GlobalGraphValidation.notRun());
    }

    private String buildUpgradeRationale(RemediationCandidate c) {
        String prefix = c.isMandatoryUpgrade()
                ? "Mandatory (CRITICAL + REACHABLE). "
                : "Optimal: maximises risk reduction within effort budget. ";

        String compatStr = c.compatibilityReport()
                .map(r -> r.status().name())
                .orElse(CompatibilityStatus.UNKNOWN.name());

        String stabilityStr = c.fixVersionStability()
                .flatMap(StabilityScore::ofFixVersion)
                .map(s -> String.format(Locale.ROOT, "StabilityScore=%.2f", s.value()))
                .orElse("StabilityScore=N/A");

        return String.format(Locale.ROOT, "%sRisk=%.2f | Effort=%.1f units (%s) | %s.",
                prefix, c.contextualRisk(riskWeights), c.upgradeCost(), compatStr, stabilityStr);
    }

    /**
     * A deferral is not a statement that the risk is small. The optimiser
     * maximises total risk reduction under the effort budget, so an artifact is
     * deferred because its upgrade cost bought less reduction than the upgrades
     * that were selected. Reporting it as "risk within an acceptable threshold"
     * contradicts the plan whenever a deferred artifact outranks a selected one
     * on risk alone, so the rationale names the cost that drove the decision.
     */
    private String buildDeferRationale(RemediationCandidate c) {
        if (!c.hasFixAvailable()) {
            return "No fix version available — upgrade not possible.";
        }

        String compatStr = c.compatibilityReport()
                .map(r -> r.status().name())
                .orElse(CompatibilityStatus.UNKNOWN.name());

        return String.format(
                Locale.ROOT,
                "Not selected under the effort budget: upgrading costs %.1f units (%s), "
                        + "and the budget bought more risk reduction elsewhere. "
                        + "Residual risk %.2f remains unmitigated.",
                c.upgradeCost(), compatStr, c.contextualRisk(riskWeights));
    }
}