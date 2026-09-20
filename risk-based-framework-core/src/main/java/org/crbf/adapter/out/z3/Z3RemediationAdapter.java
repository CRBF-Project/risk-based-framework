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
        if (effortBudget <= 0) {
            throw new IllegalArgumentException("Effort budget must be positive. Received: " + effortBudget);
        }
        this.effortBudget = effortBudget;
        this.riskWeights = riskWeights;
    }

    @Override
    public RemediationPlan optimize(List<RemediationCandidate> candidates) {
        List<RemediationCandidate> vulnerable = candidates.stream()
                .filter(c -> !c.vulnerabilities().isEmpty())
                .toList();

        if (vulnerable.isEmpty()) {
            return RemediationPlan.empty();
        }

        LOG.info("Starting optimisation — {} candidates, effort budget: {} units", vulnerable.size(), effortBudget);

        try (Context ctx = new Context()) {
            return solveWithZ3(ctx, vulnerable);
        } catch (Exception e) {
            LOG.error("Z3 optimisation failed ({}). Falling back to greedy selection.", e.getMessage());
            return greedyFallback(vulnerable);
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
            return extractPlan(optimizer.getModel(), candidates, upgradeVars, true);
        }

        LOG.warn("No feasible solution found (status: {}). Budget may be insufficient to cover mandatory upgrades. Falling back to greedy selection.", status);
        return greedyFallback(candidates);
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
            BoolExpr[] upgradeVars,
            boolean solvedByZ3) {

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

        return new RemediationPlan(decisions, totalRiskReduction, totalResidualRisk, totalEffort, solvedByZ3, GlobalGraphValidation.notRun());
    }

    // -------------------------------------------------------------------------
    // Greedy Fallback
    // -------------------------------------------------------------------------

    /**
     * Greedy fallback used when Z3 fails or reports UNSATISFIABLE.
     * Selects upgrades in descending order of risk/effort ratio until
     * the budget is exhausted, then forces mandatory upgrades regardless.
     */
    private RemediationPlan greedyFallback(List<RemediationCandidate> candidates) {
        LOG.info("Running greedy fallback selection.");

        List<RemediationCandidate> sorted = candidates.stream()
                .filter(RemediationCandidate::hasFixAvailable)
                .sorted((a, b) -> Double.compare(
                        b.contextualRisk(riskWeights) / b.upgradeCost(),
                        a.contextualRisk(riskWeights) / a.upgradeCost()))
                .toList();

        double remainingBudget = effortBudget;
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
                if (fits)
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

        candidates.stream()
                .filter(c -> !c.hasFixAvailable())
                .forEach(c -> {
                    decisions.add(RemediationDecision.defer(c.artifact(), "No fix version available."));
                });

        return new RemediationPlan(decisions, totalRiskReduction, totalResidualRisk, totalEffort, false, GlobalGraphValidation.notRun());
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

    private String buildDeferRationale(RemediationCandidate c) {
        if (!c.hasFixAvailable()) {
            return "No fix version available — upgrade not possible.";
        }
        return String.format(
                Locale.ROOT,
                "Deferred by optimiser: residual risk %.2f within acceptable threshold given sprint budget.",
                c.contextualRisk(riskWeights));
    }
}