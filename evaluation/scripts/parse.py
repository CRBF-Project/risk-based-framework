"""Normalise saved C1/C2/C3 reports.

Usage: python3 evaluation/scripts/parse.py --data evaluation/results/<run>
"""

import argparse
import csv
import hashlib
import json
import re
import shutil
from collections import Counter
from pathlib import Path


def identifier(value):
    value = value.strip()
    return value.upper() if value.upper().startswith(('CVE-', 'GHSA-')) else value


class Identities:
    """Join identifiers only through explicit aliases in the supplied reports."""

    def __init__(self):
        self.parent = {}

    def root(self, value):
        self.parent.setdefault(value, value)
        if self.parent[value] != value:
            self.parent[value] = self.root(self.parent[value])
        return self.parent[value]

    def add(self, values):
        values = sorted({identifier(v) for v in values if v})
        for value in values[1:]:
            self.parent[self.root(value)] = self.root(values[0])

    def aliases(self, value):
        root = self.root(identifier(value))
        return sorted(v for v in self.parent if self.root(v) == root)

    def canonical(self, value):
        aliases = self.aliases(value)
        return next((v for v in aliases if v.startswith('CVE-')), aliases[0])


def osv_packages(document):
    return [p for result in document['results'] for p in result.get('packages', [])]


def collect_identities(documents):
    identities = Identities()
    for (project, config), document in documents.items():
        containers = document['findings'] if config == 'c3' else osv_packages(document)
        for container in containers:
            for vuln in container.get('vulnerabilities', []):
                identities.add([vuln['id'], *vuln.get('aliases', [])])
            for group in container.get('groups', []):
                identities.add([*group['ids'], *group.get('aliases', [])])
    return identities


def osv_called(package, vuln, identities):
    values = set()
    canonical = identities.canonical(vuln['id'])
    for group in package.get('groups', []):
        for vid, analysis in group.get('experimental_analysis', {}).items():
            if identities.canonical(vid) == canonical and isinstance(analysis.get('called'), bool):
                values.add(analysis['called'])
    if len(values) > 1:
        raise ValueError(f'Conflicting called values for {canonical}')
    return next(iter(values)) if values else None


def cvss_data(container, vuln, identities, config):
    if config == 'c3':
        raw = vuln.get('cvss') or {}
        score = raw.get('score') if raw.get('vector') not in (None, '', 'UNKNOWN') else None
        return dict(cvss_score=score, cvss_basis='CRBF_REPORTED', cvss_original=json.dumps(raw, sort_keys=True))
    canonical = identities.canonical(vuln['id'])
    severities = [g.get('max_severity') for g in container.get('groups', [])
                  if any(identities.canonical(vid) == canonical for vid in g['ids'])]
    numeric = []
    for value in severities:
        try:
            score = float(value)
        except (TypeError, ValueError):
            continue
        if 0 <= score <= 10:
            numeric.append(score)
    return dict(cvss_score=max(numeric) if numeric else None, cvss_basis='OSV_GROUP_MAX_SEVERITY',
                cvss_original=json.dumps({'group_max_severity': severities, 'severity': vuln.get('severity')}, sort_keys=True))


def ranks(rows, field):
    """Competition ranks: equal scores have equal ranks; missing scores stay absent."""
    scores = sorted((r[field] for r in rows if r.get(field) is not None), reverse=True)
    return {score: scores.index(score) + 1 for score in set(scores)}


def add_ranks(rows):
    for field, target in [('cvss_score', 'cvss_rank'), ('contextual_risk', 'contextual_rank')]:
        mapping = ranks(rows, field)
        for row in rows:
            row[target] = mapping.get(row.get(field))


FINDING_FIELDS = [
    'project_id', 'config', 'dependency', 'version', 'vulnerability_id',
    'reported_ids', 'identity_aliases', 'osv_called', 'crbf_reachability',
    'contextual_risk', 'epss', 'cvss_score', 'cvss_basis', 'cvss_original',
    'contextual_risk_original', 'cvss_rank', 'contextual_rank',
    'group_id', 'artifact_id', 'source_path', 'source_refs',
]


def normalise(project, config, document, identities, source):
    findings, inventory, remediation = {}, set(), []
    containers = document['findings'] if config == 'c3' else osv_packages(document)
    if config == 'c3':
        for artifact in document['scannedArtifacts']:
            inventory.add(tuple(artifact.rsplit(':', 1)))
    for index, container in enumerate(containers):
        if config == 'c3':
            dependency, version = container['artifact'].rsplit(':', 1)
            inventory.add((dependency, version))
            decision = container.get('remediation', {})
            remediation.append(dict(
                project_id=project, dependency=dependency, version=version,
                decision=decision.get('decision'), recommended_version=decision.get('recommendedVersion'),
                potential_risk_addressed=decision.get('potentialRiskAddressed', decision.get('riskReduction')), effort_cost=decision.get('effortCost'),
                compatibility=container.get('compatibility', {}).get('status'),
                contextual_compatibility=container.get('compatibility', {}).get('contextualStatus'),
                contextual_risk=container.get('contextualRisk'),
                rationale=decision.get('rationale'), stability_summary=container.get('stabilitySummary'),
                source_path=source, source_ref=f'findings[{index}]',
            ))
        else:
            dependency, version = container['package']['name'], container['package']['version']
            inventory.add((dependency, version))
        for vi, vuln in enumerate(container.get('vulnerabilities', [])):
            canonical = identities.canonical(vuln['id'])
            risk = vuln.get('contextualRisk', {}) if config == 'c3' else {}
            row = dict(project_id=project, config=config, dependency=dependency, version=version,
                       vulnerability_id=canonical, reported_ids=vuln['id'],
                       identity_aliases=';'.join(identities.aliases(vuln['id'])),
                       osv_called=osv_called(container, vuln, identities) if config == 'c2' else None,
                       crbf_reachability=risk.get('reachabilityStatus'),
                       contextual_risk=risk.get('value'), epss=(vuln.get('epss') or {}).get('score'),
                       source_path=source,
                       source_refs=f'{"findings" if config == "c3" else "flattened_packages"}[{index}].vulnerabilities[{vi}]')
            row.update(cvss_data(container, vuln, identities, config))
            row['contextual_risk_original'] = json.dumps(vuln.get('contextualRisk'), sort_keys=True) if config == 'c3' else None
            row['group_id'], row['artifact_id'] = dependency.rsplit(':', 1)
            key = dependency, version, canonical
            if key in findings:
                previous = findings[key]
                for field in ('osv_called', 'crbf_reachability', 'contextual_risk', 'epss', 'cvss_score'):
                    if previous[field] != row[field]:
                        raise ValueError(f'Conflicting duplicate occurrence: {project}/{config}/{key}/{field}')
                previous['reported_ids'] = ';'.join(sorted(set(previous['reported_ids'].split(';') + [row['reported_ids']])))
                previous['source_refs'] += ';' + row['source_refs']
            else:
                findings[key] = row
    add_ranks(list(findings.values()))
    for row in remediation:
        known = [r['cvss_score'] for r in findings.values() if r['dependency'] == row['dependency'] and r['version'] == row['version'] and r['cvss_score'] is not None]
        row['max_cvss_score'] = max(known) if known else None
    return findings, inventory, remediation


def write_csv(path, rows, fields):
    with path.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator='\n')
        writer.writeheader()
        for row in rows:
            writer.writerow({k: ('true' if v is True else 'false' if v is False else v) for k, v in row.items()})


def compare(left, right, left_inventory, right_inventory, project, pair):
    rows = []
    for key in sorted(left.keys() | right.keys()):
        a, b = left.get(key), right.get(key)
        rows.append(dict(project_id=project, comparison=pair, dependency=key[0], version=key[1],
                         vulnerability_id=key[2], presence='BOTH' if a and b else 'LEFT_ONLY' if a else 'RIGHT_ONLY',
                         dependency_in_left_inventory=key[:2] in left_inventory,
                         dependency_in_right_inventory=key[:2] in right_inventory,
                         left_osv_called=a['osv_called'] if a else None,
                         right_osv_called=b['osv_called'] if b else None,
                         right_crbf_reachability=b['crbf_reachability'] if b else None))
    return rows


COMPARISON_FIELDS = ['project_id', 'comparison', 'dependency', 'version', 'vulnerability_id',
                     'presence', 'dependency_in_left_inventory', 'dependency_in_right_inventory',
                     'left_osv_called', 'right_osv_called', 'right_crbf_reachability']


def inventory_difference(left, right):
    return dict(common=len(left & right), left_only=[list(k) for k in sorted(left - right)],
                right_only=[list(k) for k in sorted(right - left)])


def comparison_rows(project, pair, left, right, li, ri):
    rows = compare(left, right, li, ri, project, pair)
    shared = sorted(left.keys() & right.keys())
    eligible = [k for k in shared if left[k].get('cvss_score') is not None
                and right[k].get('cvss_score') is not None
                and (not pair.endswith('_c3') or right[k].get('contextual_risk') is not None)]
    lcvss = ranks([left[k] for k in eligible], 'cvss_score')
    rcvss = ranks([right[k] for k in eligible], 'cvss_score')
    contextual = ranks([right[k] for k in eligible], 'contextual_risk')
    for row in rows:
        key = row['dependency'], row['version'], row['vulnerability_id']
        a, b = left.get(key), right.get(key)
        common = key in eligible
        row.update(left_cvss_score=a.get('cvss_score') if a else None,
                   right_cvss_score=b.get('cvss_score') if b else None,
                   right_contextual_risk=b.get('contextual_risk') if b else None,
                   left_cvss_rank_shared=lcvss.get(a.get('cvss_score')) if common else None,
                   right_cvss_rank_shared=rcvss.get(b.get('cvss_score')) if common else None,
                   right_contextual_rank_shared=contextual.get(b.get('contextual_risk')) if common else None)
    return rows


COMPARISON_FIELDS += ['left_cvss_score', 'right_cvss_score', 'right_contextual_risk',
                      'left_cvss_rank_shared', 'right_cvss_rank_shared', 'right_contextual_rank_shared']
REMEDIATION_FIELDS = ['project_id', 'dependency', 'version', 'decision', 'recommended_version',
                      'potential_risk_addressed', 'effort_cost', 'compatibility', 'contextual_compatibility', 'contextual_risk',
                      'max_cvss_score', 'rationale', 'stability_summary', 'source_path', 'source_ref']


def execution_evidence(data):
    warnings, hashes = [], []
    diagnostic = re.compile(r'failed to|^failed |unavailable|not present in|timed? out|timeout', re.I)
    for path in sorted((data / 'raw').rglob('*')):
        if not path.is_file():
            continue
        name = path.relative_to(data).as_posix()
        hashes.append(dict(path=name, sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
        if path.suffix == '.log':
            for number, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
                if line.startswith('$ '):
                    continue
                level = re.match(r'^\[(WARNING|WARN|ERROR)\]', line)
                if level or diagnostic.search(line):
                    warnings.append(dict(project_id=path.parent.name, step=path.stem, source_path=name,
                                         line=number, severity=level.group(1) if level else 'DIAGNOSTIC', message=line))
    for name in ('metadata.json', 'runs.csv', 'projects.csv'):
        path = data / name
        if path.exists():
            hashes.append(dict(path=name, sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    published = data / 'diagnostics/warnings.csv'
    if published.exists():
        with published.open() as stream:
            warnings.extend(row for row in csv.DictReader(stream) if not (data / row['source_path']).exists())
    manifest = data / 'integrity.json'
    if manifest.exists():
        previous = json.loads(manifest.read_text())
        hashes.extend(row for row in previous.get('inputs', [])
                      if row['path'].endswith('.log') and not (data / row['path']).exists())
    hashes.sort(key=lambda row: row['path'])
    warnings.sort(key=lambda row: (row['source_path'], int(row['line'])))
    executions = []
    if (data / 'runs.csv').exists():
        with (data / 'runs.csv').open() as stream:
            executions = list(csv.DictReader(stream))
    return warnings, hashes, executions


def export_summaries(root, data, projects, remediation, warnings, hashes, executions, missing, private_evidence=False):
    summaries, diagnostics = root / 'summaries', root / 'diagnostics'
    summaries.mkdir(parents=True, exist_ok=True)
    diagnostics.mkdir(parents=True, exist_ok=True)
    coordinates, inventories, global_projects = [], [], {}
    for project, stats in projects.items():
        for candidate in stats.pop('coordinate_candidates_not_merged', []):
            coordinates.append(dict(project_id=project, **candidate))
        for pair in ('c1_c2', 'c2_c3', 'sbom_c3'):
            inventory = stats.get(pair, {}).get('inventory')
            if inventory is None:
                continue
            for side in ('left_only', 'right_only'):
                values = inventory[side]
                inventories.extend(dict(project_id=project, comparison=pair, side=side,
                                        dependency=dependency, version=version) for dependency, version in values)
                inventory[side] = len(values)
        if 'cyclonedx_control' in stats:
            stats['cyclonedx_control'].pop('generator', None)
        times = {step: next((float(r['duration_s']) for r in executions
                           if r['project_id'] == project and r['step'] == step and r['duration_s']), None)
                 for step in ('c1', 'c2', 'c3', 'sbom')}
        stats['duration_s'] = times
        if 'c3' in stats:
            selected = [r for r in remediation if r['project_id'] == project and r['decision'] in ('MANDATORY', 'RECOMMENDED')]
            stats['c3']['selected_updates'] = len(selected)
            stats['c3']['selected_effort'] = sum(r['effort_cost'] for r in selected)
            stats['c3']['potential_risk_addressed'] = sum(r['potential_risk_addressed'] for r in selected)
            graph = stats['c3'].get('global_graph_validation')
            if graph is not None:
                stats['c3']['global_graph_validation'] = dict(status=graph.get('status'),
                    analyzed_artifacts=len(graph.get('analyzedArtifacts', [])),
                    vulnerable_dependencies=len(graph.get('newVulnerableDeps', [])))
        detail = dict(project_id=project, **stats,
                      missing_reports=[p for p in missing if p.startswith('raw/' + project + '/')])
        (summaries / (project + '.json')).write_text(json.dumps(detail, indent=2, sort_keys=True) + '\n')
        compact = {key: value for key, value in stats.items() if key != 'reachability_cross_tab'}
        if 'c3' in compact:
            compact['c3'] = dict(compact['c3'])
            failures = compact['c3'].pop('vulnerability_lookup_failures', None)
            compact['c3']['failed_vulnerability_lookups'] = len(failures) if failures is not None else None
            infeasibility = compact['c3'].get('infeasibility')
            if infeasibility:
                compact['c3']['infeasibility'] = {k: v for k, v in infeasibility.items() if k != 'mandatoryUpgrades'}
        global_projects[project] = compact
    if private_evidence:
        write_csv(diagnostics / 'warnings.csv', warnings,
                  ['project_id', 'step', 'source_path', 'line', 'severity', 'message'])
    write_csv(diagnostics / 'coordinate_mismatches.csv', coordinates,
              ['project_id', 'osv_dependency', 'crbf_dependency', 'version'])
    write_csv(diagnostics / 'inventory_differences.csv', inventories,
              ['project_id', 'comparison', 'side', 'dependency', 'version'])
    result = dict(projects=global_projects, missing_reports=missing)
    (root / 'summary.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    if private_evidence:
        integrity = dict(inputs=hashes, unavailable_inputs=[r['path'] for r in hashes if not (data / r['path']).exists()],
                         parser_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
        (root / 'integrity.json').write_text(json.dumps(integrity, indent=2, sort_keys=True) + '\n')
    return result


def run(data, out, project_filter=None, configs=None, private_evidence=False):
    data, out = data.resolve(), out.resolve()
    raw = data / 'raw'
    if out == raw or raw in out.parents:
        raise ValueError('Normalised outputs must not replace raw data or execution metadata')
    documents, missing = {}, []
    selected = configs or ('c1', 'c2', 'c3', 'sbom')
    for directory in sorted(raw.iterdir()):
        if not directory.is_dir() or project_filter and directory.name != project_filter:
            continue
        for config in selected:
            path = directory / ('osv-sbom.json' if config == 'sbom' else f'{config}.json')
            if path.exists():
                documents[directory.name, config] = json.loads(path.read_text())
            else:
                missing.append(path.relative_to(data).as_posix())
    if not documents:
        raise ValueError('No reports found for the selected project/configuration')
    identities = collect_identities(documents)
    findings_output, inventory_output, remediation_output, comparisons = [], [], [], []
    summary = {}
    for project in sorted({p for p, c in documents}):
        parsed, stats = {}, {}
        for config in selected:
            if (project, config) not in documents:
                continue
            path = f'raw/{project}/' + ('osv-sbom.json' if config == 'sbom' else f'{config}.json')
            findings, inventory, remediation = normalise(project, config, documents[project, config], identities, path)
            parsed[config] = findings, inventory
            findings_output.extend(findings[k] for k in sorted(findings))
            inventory_output.extend(dict(project_id=project, config=config, group_id=d.rsplit(':', 1)[0],
                                         artifact_id=d.rsplit(':', 1)[1], dependency=d, version=v)
                                    for d, v in sorted(inventory))
            remediation_output.extend(remediation)
            stats[config] = dict(inventory_entries=len(inventory),
                                 vulnerable_dependencies=len({k[:2] for k in findings}), occurrences=len(findings),
                                 cvss_available=sum(r['cvss_score'] is not None for r in findings.values()))
            if config == 'c2':
                stats[config]['called'] = dict(Counter('MISSING' if r['osv_called'] is None else str(r['osv_called']).lower() for r in findings.values()))
            elif config == 'c3':
                doc = documents[project, config]
                stats[config].update(reachability=dict(Counter(r['crbf_reachability'] or 'MISSING' for r in findings.values())),
                                     remediation=dict(Counter(r['decision'] or 'MISSING' for r in remediation)),
                                     optimisation_status=doc.get('optimisationStatus'),
                                     available_effort_budget=doc.get('availableEffortBudget'),
                                     unselected_risk=doc.get('unselectedRisk', doc.get('residualRisk')), infeasibility=doc.get('infeasibility'),
                                     global_graph_validation=doc.get('globalGraphValidation'),
                                     vulnerability_lookup_failures=doc.get('vulnerabilityLookupFailures'))
        for left, right in (('c1', 'c2'), ('c2', 'c3'), ('sbom', 'c3')):
            pair = f'{left}_{right}'
            if left not in parsed or right not in parsed:
                stats[pair] = {'status': 'NOT_COMPARABLE_MISSING_REPORT'}
                continue
            lf, li = parsed[left]
            rf, ri = parsed[right]
            rows = comparison_rows(project, pair, lf, rf, li, ri)
            comparisons.extend(rows)
            stats[pair] = dict(occurrences=dict(Counter(r['presence'] for r in rows)),
                               inventory=inventory_difference(li, ri))
            if pair == 'c2_c3':
                shared = [r for r in rows if r['presence'] == 'BOTH']
                stats['reachability_cross_tab'] = [dict(osv_called=c, crbf_reachability=s, occurrences=n)
                    for (c, s), n in sorted(Counter(
                        ('MISSING' if r['left_osv_called'] is None else str(r['left_osv_called']).lower(),
                         r['right_crbf_reachability'] or 'MISSING') for r in shared).items())]
        if 'c2' in parsed and 'c3' in parsed:
            li, ri = parsed['c2'][1], parsed['c3'][1]
            stats['coordinate_candidates_not_merged'] = [dict(osv_dependency=l, crbf_dependency=r, version=v)
                for r, v in sorted(ri - li) for l, lv in sorted(li - ri)
                if lv == v and l.rsplit(':', 1)[1] == r.rsplit(':', 1)[1]]
        bom_path = raw / project / 'bom.json'
        if bom_path.exists():
            bom = json.loads(bom_path.read_text())
            si = {(c.get('group', '') + ':' + c['name'], c['version']) for c in bom['components']}
            stats['cyclonedx_control'] = dict(components=len(bom['components']), inventory_entries=len(si),
                spec_version=bom.get('specVersion'),
                generator=bom.get('metadata', {}).get('tools'),
                matches_crbf=si == parsed['c3'][1] if 'c3' in parsed else None,
                matches_osv_sbom=si == parsed['sbom'][1] if 'sbom' in parsed else None)
        summary[project] = stats
    warnings, hashes, executions = execution_evidence(data)
    out.mkdir(parents=True, exist_ok=True)
    write_csv(out / 'findings.csv', findings_output, FINDING_FIELDS)
    write_csv(out / 'inventory.csv', inventory_output, ['project_id', 'config', 'group_id', 'artifact_id', 'dependency', 'version'])
    write_csv(out / 'comparisons.csv', comparisons, COMPARISON_FIELDS)
    write_csv(out / 'remediation.csv', remediation_output, REMEDIATION_FIELDS)
    return export_summaries(out.parent if out.name == 'normalised' else out, data, summary,
                            remediation_output, warnings, hashes, executions, missing, private_evidence)


def publish(data, out):
    """Copy saved reports for publication without local paths or execution dates."""
    data, out = data.resolve(), out.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError('Publication requires a new or empty output directory')
    out.mkdir(parents=True, exist_ok=True)
    for source in sorted((data / 'raw').glob('*/*.json')):
        document = json.loads(source.read_text())
        project = source.parent.name
        if source.name in ('c1.json', 'c2.json', 'osv-sbom.json'):
            for result in document.get('results', []):
                origin = result.get('source', {})
                if 'path' in origin:
                    origin['path'] = (f'raw/{project}/bom.json' if source.name == 'osv-sbom.json'
                                      else 'target/' + Path(origin['path']).name)
        elif source.name == 'bom.json':
            document.get('metadata', {}).pop('timestamp', None)
        target = out / 'raw' / project / source.name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(document, indent=2) + '\n')
    shutil.copyfile(data / 'projects.csv', out / 'projects.csv')
    with (data / 'projects.csv').open() as stream:
        repositories = {r['project_id']: r['repo_url'] for r in csv.DictReader(stream)}

    def public_argument(value, project):
        if '=' in value and not value.startswith('/'):
            key, argument = value.split('=', 1)
            return key + '=' + public_argument(argument, project)
        if value.startswith('/'):
            marker = '/raw/' + project
            if marker in value:
                return 'raw/' + project + value.split(marker, 1)[1]
            return 'checkouts/' + project if Path(value).name == project else '[local-path]/' + Path(value).name
        return value

    rows = []
    with (data / 'runs.csv').open() as stream:
        for row in csv.DictReader(stream):
            project = row['project_id']
            command = json.loads(row['command'])
            if row['step'] == 'clone':
                command[-2] = repositories[project]
            if row['step'] in ('c1', 'c2', 'sbom'):
                command[0] = 'osv-scanner'
            row['command'] = json.dumps([public_argument(a, project) for a in command])
            rows.append({k: row[k] for k in ('project_id', 'commit', 'step', 'command',
                                           'duration_s', 'exit_code', 'status', 'raw_path')})
    write_csv(out / 'runs.csv', rows,
              ['project_id', 'commit', 'step', 'command', 'duration_s', 'exit_code', 'status', 'raw_path'])
    return run(out, out / 'normalised')



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', required=True, type=Path)
    parser.add_argument('--out', type=Path, help='Alternative export root; CSV files go in its normalised/ directory')
    parser.add_argument('--project')
    parser.add_argument('--only', nargs='+', choices=['c1', 'c2', 'c3', 'sbom'])
    parser.add_argument('--publish', action='store_true', help='Copy privacy-sanitised reports and normalise them in a new --out directory')
    parser.add_argument('--private-evidence', action='store_true', help='Also export local warnings and integrity evidence; do not publish these files')
    args = parser.parse_args()
    try:
        if args.publish:
            if not args.out or args.project or args.only or args.private_evidence:
                parser.error('--publish requires --out and cannot be combined with subset/private-evidence options')
            publish(args.data, args.out)
        else:
            run(args.data, (args.out / 'normalised') if args.out else args.data / 'normalised',
                args.project, args.only, args.private_evidence)
    except (ValueError, OSError, KeyError) as error:
        parser.error(str(error))
    print('Normalised saved reports; no tools were re-executed.')
