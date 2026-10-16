import fs from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';

// Code-only renderer tests: no browser, network, screenshots or recording.
const template = fs.readFileSync(new URL('../../main/resources/report-template.html', import.meta.url), 'utf8');
const script = template.split('<script>')[1].split('</script>')[0];
const real = JSON.parse(fs.readFileSync(new URL('../../../../evaluation/data/raw/my-blog/c3.json', import.meta.url), 'utf8'));
const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function render(data) {
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, {
      value: id === 'finding-filter' ? 'all' : id === 'finding-sort' ? 'risk' : '',
      innerHTML: '', textContent: '', events: {},
      addEventListener(type, handler) { this.events[type] = handler; }
    });
    return elements.get(id);
  };
  element('report-data').textContent = JSON.stringify(data);
  const document = { getElementById: element, querySelectorAll: () => [], addEventListener() {}, title: '' };
  const context = vm.createContext({ document, window: {}, navigator: {}, URL, console, setTimeout });
  vm.runInContext(script, context, { timeout: 5000 });
  return {
    element, context,
    output: () => [...elements.values()].map(e => e.innerHTML + ' ' + e.textContent).join('\n')
  };
}

function infeasible(reason = 'MANDATORY_EFFORT_EXCEEDS_BUDGET') {
  const data = structuredClone(real);
  data.optimisationStatus = 'INFEASIBLE';
  data.infeasibility = {
    reason, availableEffortBudget: 3, requiredMandatoryEffort: 4,
    budgetShortfall: reason === 'MANDATORY_EFFORT_EXCEEDS_BUDGET' ? 1 : null,
    mandatoryUpgrades: data.findings.slice(0, 2).map(f => ({
      artifact: f.artifact, targetVersion: f.remediation.recommendedVersion, effortCost: 2
    }))
  };
  data.findings.forEach((finding, i) => Object.assign(finding.remediation, {
    decision: i < 2 ? 'MANDATORY_PENDING' : 'OPTIONAL_NOT_SELECTED', riskReduction: 0, effortCost: 0
  }));
  return data;
}

test('preserves real C3 advisory, evidence, ecosystem and inventory information', () => {
  const report = render(real);
  const output = report.output();
  for (const finding of real.findings) {
    assert(output.includes(escape(finding.artifact)));
    assert(output.includes(escape(finding.stabilitySummary)));
    assert(output.includes(escape(finding.remediation.rationale)));
    for (const vulnerability of finding.vulnerabilities) {
      assert(output.includes(escape(vulnerability.id)));
      assert(output.includes(escape(vulnerability.summary)));
      assert(output.includes(escape(vulnerability.cvss.vector)));
      for (const alias of vulnerability.aliases) assert(output.includes(escape(alias)));
      for (const cwe of vulnerability.cwes) assert(output.includes(escape(cwe)));
    }
    for (const method of finding.reachability.reachableMethods) assert(output.includes(escape(method)));
    for (const change of finding.compatibility.topBreakingChanges) {
      const description = change.replace(/^\[(BINARY|SOURCE)\]\s+(Method|Constructor|Field|Class)\s+/, '').trim();
      assert(output.includes(escape(description)));
    }
  }
  for (const gav of real.scannedArtifacts) assert(output.includes(escape(gav)));
});

test('does not infer optimisation success for legacy reports', () => {
  assert(render(real).element('optimisation-outcome').innerHTML.includes('Optimisation outcome not reported'));
});

for (const [status, expected] of [
  ['OPTIMAL', 'Optimal selection'], ['FEASIBLE', 'Feasible selection'],
  ['GREEDY_FALLBACK', 'Feasible · greedy fallback'], ['NOT_RUN', 'Optimisation not run']
]) {
  test(`explains ${status} without changing the source classifications`, () => {
    const data = { ...real, optimisationStatus: status };
    assert(render(data).element('optimisation-outcome').innerHTML.includes(expected));
  });
}

test('keeps mandatory pending effort separate from selected effort and reduction', () => {
  const data = infeasible();
  const report = render(data);
  const outcome = report.element('optimisation-outcome').innerHTML;
  assert(report.element('plan-count').textContent.startsWith('0 selected'));
  assert(outcome.includes('>3.0<') && outcome.includes('>4.0<') && outcome.includes('>1.0<'));
  assert(outcome.includes('>0.0<') && outcome.includes('>0.00<'));
  assert(report.element('plan-content').innerHTML.includes('Pending · not selected'));
  assert(!report.element('plan-content').innerHTML.includes('pom.xml update:'));
  for (const finding of data.findings) assert(report.output().includes(escape(finding.remediation.rationale)));
});

test('does not attribute general infeasibility to an unconfirmed budget shortfall', () => {
  const report = render(infeasible('UNSATISFIABLE_CONSTRAINTS'));
  assert(report.element('optimisation-outcome').innerHTML.includes('Not established'));
});

test('preserves a pending requirement even when its finding is absent', () => {
  const data = infeasible();
  data.infeasibility.mandatoryUpgrades.push({ artifact: 'org.example:pending-only:1.0.0', targetVersion: '2.0.0', effortCost: 2 });
  const report = render(data);
  assert(report.element('plan-count').textContent.includes('3 mandatory pending'));
  assert(report.element('plan-content').innerHTML.includes('pending-only'));
});

test('filters and resets findings without changing project-wide overview totals', () => {
  const report = render(real);
  const overview = report.element('summary-cards').innerHTML;
  report.element('finding-search').value = 'no-such-dependency-123';
  report.element('finding-search').events.input();
  assert(report.element('filter-result').textContent.startsWith('Showing 0 of'));
  report.element('reset-filters').events.click();
  assert(report.element('filter-result').textContent.startsWith(`Showing ${real.findings.length} of`));
  report.element('finding-filter').value = 'selected';
  report.element('finding-filter').events.change();
  const selected = real.findings.filter(f => ['MANDATORY', 'RECOMMENDED'].includes(f.remediation.decision));
  assert(report.element('filter-result').textContent.startsWith(`Showing ${selected.length} of`));
  assert.equal(report.element('summary-cards').innerHTML, overview);
  report.element('finding-sort').value = 'name';
  report.element('finding-sort').events.change();
  assert.equal(report.element('summary-cards').innerHTML, overview);
});

test('renders unavailable information and failed lookups without representing it as zero', () => {
  const report = render({ projectName: 'incomplete', findings: [{
    artifact: 'org.example:unknown:1.0.0', vulnerabilities: [{ id: 'CVE-2026-0001', severity: 'UNKNOWN' }],
    reachability: { status: 'UNKNOWN' }, remediation: { decision: 'DEFER', effortCost: 0, riskReduction: 0 }
  }], vulnerabilityLookupFailures: ['org.example:failed:1.0.0'] });
  assert(report.output().includes('Unavailable'));
  assert(report.element('limitations-content').innerHTML.includes('org.example:failed:1.0.0'));
  assert(report.element('limitations-content').innerHTML.includes('unknown vulnerability status, not zero vulnerabilities'));
});

test('escapes untrusted text and excludes executable URL schemes', () => {
  const data = structuredClone(real);
  data.projectName = '</script><script>window.CRBF_INJECTED=true</script>';
  data.findings[0].vulnerabilities[0].summary = '<img src=x onerror="window.CRBF_INJECTED=true">';
  data.findings[0].vulnerabilities[0].advisoryUrl = 'javascript:alert(1)';
  data.findings[0].vulnerabilities[0].fixCommitUrl = 'data:text/html,<script>alert(1)</script>';
  const report = render(data);
  assert(!report.element('vulnerability-content').innerHTML.includes('<img src=x'));
  assert(!report.output().includes('href="javascript:') && !report.output().includes('href="data:'));
  assert.equal(report.context.CRBF_INJECTED, undefined);
});

test('renders an empty report without claiming a completed vulnerability scan', () => {
  const report = render({ projectName: 'empty', optimisationStatus: 'NOT_RUN', findings: [], scannedArtifacts: [] });
  assert(report.element('optimisation-outcome').innerHTML.includes('Optimisation not run'));
  assert(report.element('project-meta').textContent.startsWith('Unknown dependencies'));
});


test('shows the reported budget independently of selected effort', () => {
  const report = render({ ...real, availableEffortBudget: 12.5 });
  const outcome = report.element('optimisation-outcome').innerHTML;
  assert(outcome.includes('Available effort budget'));
  assert(outcome.includes('>12.5<'));
});

test('does not invent a budget for reports that omit it', () => {
  const outcome = render(real).element('optimisation-outcome').innerHTML;
  assert(outcome.includes('unavailable">Unavailable</span><span class="metric-label">Available effort budget'));
});

test('qualifies the latest version as graph information', () => {
  assert(render(real).element('compatibility-content').innerHTML.includes('Latest known to graph'));
});
