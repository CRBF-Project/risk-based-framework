"""Collect pinned CRBF evaluation runs; raw outputs are never overwritten."""

import argparse
import csv
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

STEPS = ('c1', 'c2', 'c3', 'sbom')
OSV_VERSION = '2.7.0'
CYCLONEDX_VERSION = '2.9.1'
CALL_GRAPH_TIMEOUT = 600
EFFORT_BUDGET = 30
TIMEOUT = 1800
FIELDS = ['project_id', 'commit', 'step', 'command', 'cwd', 'started_at_utc',
          'duration_s', 'exit_code', 'status', 'raw_path', 'log_path', 'error']


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def capture(command, cwd=None, env=None):
    return subprocess.check_output(command, cwd=cwd, env=env, text=True,
                                   stderr=subprocess.STDOUT, timeout=60).strip()


def build_commands(project, raw, osv):
    jar = project['uberjar_path']
    common = [osv, 'scan', 'source', '--x-plugins=artifact', '--all-packages',
              '--all-vulns', '--format=json']
    return {
        'c1': common + ['--output-file', str(raw / 'c1.json'), jar],
        'c2': common + ['--call-analysis=jar', '--output-file', str(raw / 'c2.json'), jar],
        'c3': ['mvn', '-B', f'-Dcontextframework.effortBudget={EFFORT_BUDGET}',
               f'-Dcontextframework.callGraphTimeoutSeconds={CALL_GRAPH_TIMEOUT}',
               project['plugin_goal']],
        'cyclonedx': ['mvn', '-B', f'org.cyclonedx:cyclonedx-maven-plugin:{CYCLONEDX_VERSION}:makeAggregateBom',
                     '-DincludeCompileScope=true', '-DincludeRuntimeScope=true', '-DincludeTestScope=false',
                     '-DincludeProvidedScope=false', '-DincludeSystemScope=false', '-DschemaVersion=1.6',
                     '-DoutputFormat=json', '-Dcyclonedx.skipAttach=true', '-DoutputDirectory=' + str(raw)],
        'sbom': [osv, 'scan', 'source', '--sbom=' + str(raw / 'bom.json'),
                 '--all-packages', '--all-vulns', '--format=json', '--output-file', str(raw / 'osv-sbom.json')],
    }


def validate_report(path, kind):
    if not path.is_file():
        return 'No output report produced'
    try:
        data = json.loads(path.read_text())
        required = ('findings', 'scannedArtifacts') if kind == 'c3' else ('components',) if kind == 'cyclonedx' else ('results',)
        if not isinstance(data, dict) or any(key not in data for key in required):
            return 'Report schema does not contain required fields'
        if kind == 'c3' and data.get('availableEffortBudget') != EFFORT_BUDGET:
            return f'CRBF effort budget must be {EFFORT_BUDGET}; found {data.get("availableEffortBudget")}'
    except (ValueError, OSError) as error:
        return str(error)
    return ''


def step_status(step, exit_code, error=''):
    allowed = (0, 1) if step in ('c1', 'c2', 'sbom') else (0,)
    return 'ERROR' if error or exit_code not in allowed else 'OK'


class Recorder:
    def __init__(self, out, env):
        self.out, self.env = out, env
        self.failed = False

    def execute(self, project, step, command, cwd, output=None, collect=None):
        raw = self.out / 'raw' / project['project_id']
        raw.mkdir(parents=True, exist_ok=True)
        log_path = raw / f'{step}.log'
        if log_path.exists() or output and output.exists():
            raise FileExistsError(f'Refusing to overwrite {log_path} or {output}')
        started = datetime.now(timezone.utc).isoformat()
        tick = time.monotonic()
        error = ''
        code = -1
        print(f"{project['project_id']}: {step}", flush=True)
        with log_path.open('x') as log:
            log.write('$ ' + shlex.join(command) + '\n')
            log.flush()
            try:
                process = subprocess.Popen(command, cwd=cwd, env=self.env, stdout=log,
                                           stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    code = process.wait(timeout=TIMEOUT)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    code, error = 124, f'Timeout after {TIMEOUT}s'
            except OSError as exc:
                error = str(exc)
            if collect and collect.exists():
                shutil.copyfile(collect, output)
            if output:
                error = error or validate_report(output, step)
            status = step_status(step, code, error)
            if status == 'ERROR' and not error:
                error = f'Unexpected exit code {code}'
            log.write(f'\nexit_code={code}\nstatus={status}\nerror={error}\n')
        row = dict(project_id=project['project_id'], commit=project['commit_hash'], step=step,
                   command=json.dumps(command), cwd=str(cwd), started_at_utc=started,
                   duration_s=round(time.monotonic() - tick, 3), exit_code=code, status=status,
                   raw_path=output.relative_to(self.out).as_posix() if output and output.exists() else '',
                   log_path=log_path.relative_to(self.out).as_posix(), error=error)
        manifest = self.out / 'runs.csv'
        exists = manifest.exists()
        with manifest.open('a', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=FIELDS)
            if not exists:
                writer.writeheader()
            writer.writerow(row)
        self.failed |= status == 'ERROR'
        return status == 'OK'


def source_repository(project, source_dir):
    local = source_dir.resolve() / project['project_id'] if source_dir else None
    return str(local) if local and local.exists() else project['repo_url']


def prepare_project(project, workdir, source_dir, recorder):
    project_id = project['project_id']
    checkout = workdir / project_id
    if checkout.exists():
        raise FileExistsError(f'Fresh checkout required: {checkout}')
    source = source_repository(project, source_dir)
    if not recorder.execute(project, 'clone', ['git', 'clone', '--no-hardlinks', '--no-checkout', source, str(checkout)], workdir):
        return None
    capture(['git', 'remote', 'set-url', 'origin', project['repo_url']], checkout)
    if not recorder.execute(project, 'checkout', ['git', 'checkout', '--detach', project['commit_hash']], checkout):
        return None
    if capture(['git', 'rev-parse', 'HEAD'], checkout) != project['commit_hash']:
        raise ValueError(f'Commit mismatch for {project_id}')
    if capture(['git', 'diff', '--name-only', 'HEAD'], checkout):
        raise ValueError(f'Modified tracked project files: {project_id}')
    if not recorder.execute(project, 'build', shlex.split(project['build_cmd']), checkout):
        return None
    jar = checkout / project['uberjar_path']
    if not jar.is_file():
        raise ValueError(f'Executable JAR missing: {jar}')
    return checkout


def software_snapshot(repository):
    paths = ['risk-based-framework-core', 'risk-based-framework-maven-plugin', 'pom.xml']
    if capture(['git', 'ls-files', '--others', '--exclude-standard', '--', *paths], repository):
        raise ValueError('Untracked CRBF source cannot be reproduced; stage it before collection')
    patch = subprocess.check_output(['git', 'diff', '--binary', 'HEAD', '--', *paths],
                                    cwd=repository, text=True, stderr=subprocess.STDOUT, timeout=60)
    return dict(crbf_source_patch=patch,
                crbf_source_patch_sha256=hashlib.sha256(patch.encode()).hexdigest())


def preflight(osv, env, project_file):
    version = capture([osv, '--version'], env=env)
    if not re.search(r'^osv-scanner version: 2\.7\.0\s*$', version, re.M):
        raise ValueError(f'OSV {OSV_VERSION} required; found {version}')
    maven = capture(['mvn', '--version'], env=env)
    if not re.search(r'Java version: 17\.', maven):
        raise ValueError('A Java 17 runtime is required for all projects; set --java-home')
    repository = Path(__file__).resolve().parents[2]
    snapshot = software_snapshot(repository)
    plugin_root = Path.home() / '.m2/repository/org/crbf'
    artifacts = {}
    for module in ('risk-based-framework-core', 'risk-based-framework-maven-plugin'):
        installed = plugin_root / module / '1.0-SNAPSHOT' / f'{module}-1.0-SNAPSHOT.jar'
        built = repository / module / 'target' / installed.name
        if not installed.is_file() or not built.is_file() or sha256(installed) != sha256(built):
            raise ValueError(f'Build/install CRBF first; installed and built {module} must match')
        artifacts[module] = {'installed_path': str(installed), 'sha256': sha256(installed)}
    return dict(started_at_utc=datetime.now(timezone.utc).isoformat(), platform=platform.platform(),
                machine=platform.machine(), python=sys.version, osv_version=version,
                osv_path=osv, osv_sha256=sha256(osv), maven_and_java=maven,
                java_home=env.get('JAVA_HOME'), crbf_artifacts=artifacts,
                crbf_commit=capture(['git', 'rev-parse', 'HEAD'], repository), **snapshot,
                working_tree_status=capture(['git', 'status', '--short'], repository),
                projects_sha256=sha256(project_file), cyclonedx_version=CYCLONEDX_VERSION,
                scopes={'compile': True, 'runtime': True, 'test': False, 'provided': False, 'system': False},
                call_graph_timeout_s=CALL_GRAPH_TIMEOUT, effort_budget=EFFORT_BUDGET, step_timeout_s=TIMEOUT,
                interpretation='C1/C2 report all vulnerabilities; sbom is detection control only. called:true is not confirmed reachability.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--projects', type=Path, default=Path(__file__).with_name('projects.csv'))
    parser.add_argument('--out', type=Path, required=True, help='New run directory; must not exist')
    parser.add_argument('--workdir', type=Path, help='New directory for isolated checkouts')
    parser.add_argument('--osv', required=True, help='OSV-Scanner 2.7.0 executable')
    parser.add_argument('--java-home', type=Path)
    parser.add_argument('--source-dir', type=Path, help='Optional local clones; source files are never modified')
    parser.add_argument('--project', help='Run only this project_id')
    parser.add_argument('--only', nargs='+', choices=STEPS, default=list(STEPS), help='sbom is a detection control, not C4')
    parser.add_argument('--check', action='store_true', help='Validate requirements without collecting a run')
    args = parser.parse_args()
    args.out = args.out.resolve()
    args.workdir = (args.workdir or args.out.parents[1] / 'checkouts' / args.out.name).resolve()
    env = os.environ.copy()
    if args.java_home:
        env['JAVA_HOME'] = str(args.java_home.resolve())
        env['PATH'] = str(args.java_home / 'bin') + os.pathsep + env['PATH']
    osv = shutil.which(args.osv)
    if not osv:
        parser.error(f'OSV executable not found: {args.osv}')
    with args.projects.open(newline='') as stream:
        projects = list(csv.DictReader(stream))
    if args.project:
        projects = [p for p in projects if p['project_id'] == args.project]
    if not projects:
        parser.error('No projects selected')
    for project in projects:
        if not re.fullmatch(r'[0-9a-f]{40}', project['commit_hash']):
            parser.error(f"Full pinned commit required for {project['project_id']}")
    created = False
    try:
        metadata = preflight(str(Path(osv).resolve()), env, args.projects)
        if args.check:
            print(json.dumps(metadata, indent=2))
            return 0
        if args.out.exists() or args.workdir.exists():
            raise FileExistsError('Run output and checkout directories must be new; use parse.py to reuse raw results')
        args.out.mkdir(parents=True)
        created = True
        args.workdir.mkdir(parents=True)
        metadata['projects'] = projects
        metadata['selected_steps'] = args.only
        metadata['jar_sha256'] = {}
        metadata['pom_sha256'] = {}
        shutil.copyfile(args.projects, args.out / 'projects.csv')
        metadata['script_sha256'] = {name: sha256(Path(__file__).with_name(name)) for name in ('run.py', 'parse.py')}
        (args.out / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
        recorder = Recorder(args.out, env)
        for project in projects:
            checkout = prepare_project(project, args.workdir, args.source_dir, recorder)
            if not checkout:
                continue
            jar = checkout / project['uberjar_path']
            metadata['jar_sha256'][project['project_id']] = sha256(jar)
            metadata['pom_sha256'][project['project_id']] = sha256(checkout / 'pom.xml')
            raw = args.out / 'raw' / project['project_id']
            commands = build_commands(project, raw, metadata['osv_path'])
            for step in args.only:
                if step == 'sbom':
                    if recorder.execute(project, 'cyclonedx', commands['cyclonedx'], checkout, raw / 'bom.json'):
                        recorder.execute(project, step, commands[step], checkout, raw / 'osv-sbom.json')
                elif step == 'c3':
                    source = checkout / project['plugin_report_path']
                    if source.exists():
                        raise FileExistsError(f'Unexpected existing CRBF report: {source}')
                    recorder.execute(project, step, commands[step], checkout, raw / 'c3.json', source)
                else:
                    recorder.execute(project, step, commands[step], checkout, raw / f'{step}.json')
                if sha256(jar) != metadata['jar_sha256'][project['project_id']]:
                    raise ValueError('JAR changed between configurations')
            if capture(['git', 'diff', '--name-only', 'HEAD'], checkout):
                raise ValueError(f"Tracked subject files changed: {project['project_id']}")
            metadata['project_sources_unchanged'] = metadata.get('project_sources_unchanged', []) + [project['project_id']]
            (args.out / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
        metadata['finished_at_utc'] = datetime.now(timezone.utc).isoformat()
        metadata['status'] = 'ERROR' if recorder.failed else 'COMPLETE'
        (args.out / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
        return 1 if recorder.failed else 0
    except (ValueError, FileExistsError, OSError, subprocess.SubprocessError) as error:
        if created:
            metadata.update(status='ERROR', error=str(error), finished_at_utc=datetime.now(timezone.utc).isoformat())
            (args.out / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
        print(f'ERROR: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
