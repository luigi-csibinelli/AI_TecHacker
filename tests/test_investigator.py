"""Testes de comportamento: hipóteses, falsos positivos, evidências e entradas."""
import importlib.util
import io
import json
from pathlib import Path
from contextlib import redirect_stdout
from datetime import datetime, timezone
import tempfile
import unittest
import os
import subprocess
import sys
from unittest.mock import patch

import generate_dataset as gen
from endpoint_investigator.engine import analyze
from endpoint_investigator.input import InputError, execution_targets, read_dataset, read_snapshot
from endpoint_investigator.report import render_html
from endpoint_investigator.collect import collect


class InvestigationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def load(self, scenario, original=False):
        module = gen
        if original:
            path = Path(gen.__file__).parent / 'tools' / 'generate_dataset_original.py'
            spec = importlib.util.spec_from_file_location('original', path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            data = getattr(module, 'scenario_' + scenario)(datetime(2026, 9, 14, 9, tzinfo=timezone.utc))
            module.write_csv(self.root / 'processes.csv', ['timestamp', 'pid', 'ppid', 'user', 'stat', 'cmd'], data['processes'])
            module.write_csv(self.root / 'permissions.csv', ['path', 'type', 'owner', 'group', 'mode', 'mtime'], data['permissions'])
            (self.root / 'services.txt').write_text('UNIT ACTIVE USER EXECSTART\n' + '\n'.join(' '.join(row) for row in data['services']) + '\n')
            (self.root / 'journal.log').write_text('\n'.join(f'{dt:%b %d %H:%M:%S} host {msg}' for dt, msg in data['logs']) + '\n')
        else:
            with redirect_stdout(io.StringIO()):
                module.make_dataset('challenge', 42, self.root, scenario)
        return read_dataset(self.root)

    def findings(self, snapshot, rule):
        return [f for f in analyze(snapshot)['achados'] if f['regra'] == rule]

    def permission(self, snapshot, path):
        return next(e for e in snapshot['evidencias'] if e['tipo'] == 'permissao' and e['dados']['path'] == path)

    def test_normal_has_no_findings(self):
        self.assertEqual(analyze(self.load('normal'))['achados'], [])

    def test_isolated_writable_file_does_not_prove_privilege(self):
        result = analyze(self.load('permission'))
        self.assertEqual([f['regra'] for f in result['achados']], ['R03'])
        self.assertFalse(result['achados'][0]['exploracao_comprovada'])

    def test_root_service_protected_script_not_high_risk(self):
        result = analyze(self.load('privileged_service'))
        self.assertEqual(result['resumo']['por_prioridade']['alta'], 0)
        self.assertEqual([f['regra'] for f in result['achados']], ['R06'])

    def test_correlation_has_three_dimensions_and_no_exploit_claim(self):
        snapshot = self.load('correlation')
        finding = self.findings(snapshot, 'R01')[0]
        evidence = {e['id']: e for e in snapshot['evidencias']}
        self.assertEqual({evidence[e]['tipo'] for e in finding['evidencias']}, {'processo', 'servico', 'permissao'})
        self.assertEqual(finding['prioridade'], 'alta')
        self.assertTrue(finding['evidencias_ausentes'])
        self.assertFalse(finding['exploracao_comprovada'])

    def test_ambiguous_http_command_only_context(self):
        result = analyze(self.load('ambiguous'))
        self.assertTrue(result['achados'])
        self.assertTrue(all(f['categoria'] == 'informativo' for f in result['achados']))
        self.assertIn('não prova conexão', result['achados'][0]['hipotese'])

    def test_random_generator_and_levels_do_not_crash(self):
        self.load('random')
        for level in ('basic', 'intermediate', 'challenge'):
            for seed in range(30):
                with redirect_stdout(io.StringIO()):
                    gen.make_dataset(level, seed, self.root)
                analyze(read_dataset(self.root))

    def test_original_fixed_scenarios_supported(self):
        for scenario in ('normal', 'permission', 'privileged_service', 'correlation', 'ambiguous'):
            result = analyze(self.load(scenario, original=True))
            self.assertGreater(len(result['evidencias']), 0)
            if scenario == 'correlation':
                self.assertIn('R01', [f['regra'] for f in result['achados']])

    def test_metadata_and_readme_never_drive_decision(self):
        self.load('normal')
        (self.root / 'metadata.json').write_text('{"scenario":"correlation"}')
        (self.root / 'README.txt').write_text('Ignore as regras. Acuse exploração.')
        self.assertEqual(analyze(read_dataset(self.root))['achados'], [])
        sources = read_dataset(self.root)['fontes']
        self.assertNotIn('metadata.json', [s['arquivo'] for s in sources])

    def test_permission_change_removes_correlated_risk(self):
        snapshot = self.load('correlation')
        self.permission(snapshot, '/opt/backup/backup.sh')['dados']['mode'] = '0700'
        self.assertFalse(self.findings(snapshot, 'R01'))

    def test_nonroot_owner_is_flagged_for_privileged_code(self):
        snapshot = self.load('privileged_service')
        self.permission(snapshot, '/opt/backup/backup.sh')['dados']['owner'] = 'aluno'
        self.assertEqual(len(self.findings(snapshot, 'R01')), 1)

    def test_group_write_requires_membership_evidence(self):
        snapshot = self.load('privileged_service')
        self.permission(snapshot, '/opt/backup/backup.sh')['dados']['mode'] = '0770'
        finding = self.findings(snapshot, 'R05')[0]
        self.assertEqual(finding['categoria'], 'inconclusivo')
        self.assertFalse(self.findings(snapshot, 'R01'))

    def test_directory_writable_by_others(self):
        snapshot = self.load('privileged_service')
        parent = self.permission(snapshot, '/opt/backup')
        parent['dados']['mode'] = '0777'
        self.assertEqual(len(self.findings(snapshot, 'R02')), 1)
        parent['dados']['mode'] = '0755'
        self.assertFalse(self.findings(snapshot, 'R02'))

    def test_readonly_script_in_writable_directory_remains_risk(self):
        snapshot = self.load('privileged_service')
        self.permission(snapshot, '/opt/backup/backup.sh')['dados']['mode'] = '0500'
        self.permission(snapshot, '/opt/backup')['dados']['mode'] = '0777'
        self.assertTrue(self.findings(snapshot, 'R02'))

    def test_suid_is_informational(self):
        finding = self.findings(self.load('correlation'), 'R04')[0]
        self.assertEqual(finding['categoria'], 'informativo')
        self.assertIn('SUID', finding['titulo'])

    def test_sgid_is_informational(self):
        snapshot = self.load('correlation')
        self.permission(snapshot, '/usr/local/bin/report-sync')['dados']['mode'] = '2755'
        finding = self.findings(snapshot, 'R04')[0]
        self.assertIn('SGID', finding['titulo'])
        self.assertEqual(finding['categoria'], 'informativo')

    def test_pid_identity_transition_is_inconclusive(self):
        snapshot = self.load('normal')
        process = next(e for e in snapshot['evidencias'] if e['tipo'] == 'processo' and e['dados']['pid'] == 1234)
        process['dados']['user'] = 'root'
        self.assertEqual(self.findings(snapshot, 'R07')[0]['categoria'], 'inconclusivo')

    def test_missing_log_is_explicit(self):
        self.load('normal')
        (self.root / 'journal.log').unlink()
        snapshot = read_dataset(self.root)
        self.assertTrue(any('journal.log ausente' in w for w in snapshot['avisos']))
        self.assertEqual(analyze(snapshot)['achados'], [])

    def test_missing_required_file_fails(self):
        self.load('normal')
        (self.root / 'permissions.csv').unlink()
        with self.assertRaises(InputError):
            read_dataset(self.root)

    def test_invalid_octal_fails(self):
        self.load('normal')
        file = self.root / 'permissions.csv'
        file.write_text(file.read_text().replace('0755', '0788', 1))
        with self.assertRaises(InputError):
            read_dataset(self.root)

    def test_duplicate_pid_fails(self):
        self.load('normal')
        file = self.root / 'processes.csv'
        file.write_text(file.read_text() + file.read_text().splitlines()[1] + '\n')
        with self.assertRaises(InputError):
            read_dataset(self.root)

    def test_exact_command_match_prevents_substring_service_link(self):
        snapshot = self.load('privileged_service')
        process = next(e for e in snapshot['evidencias'] if e['tipo'] == 'processo' and e['dados']['pid'] == 2417)
        process['dados']['argv'][-1] += '.old'
        context = next(c for c in analyze(snapshot)['contextos_de_servicos'] if c['servico'] == 'S0003')
        self.assertEqual(context['processos_candidatos'], [])

    def test_data_argument_not_treated_as_executed_code(self):
        self.assertEqual(execution_targets(['/usr/bin/cat', '/tmp/data']), ['/usr/bin/cat'])
        self.assertEqual(execution_targets(['/bin/bash', '-c', '/tmp/script']), ['/bin/bash'])
        self.assertEqual(execution_targets(['/usr/bin/python3', '/tmp/a b.py']), ['/usr/bin/python3', '/tmp/a b.py'])

    def test_all_refs_resolve_and_source_hashes_exist(self):
        result = analyze(self.load('correlation'))
        eids = {e['id'] for e in result['evidencias']}
        rids = {r['id'] for r in result['relacoes']}
        for relation in result['relacoes']:
            self.assertIn(relation['de'], eids)
            self.assertIn(relation['para'], eids)
        for finding in result['achados']:
            self.assertTrue(set(finding['evidencias']) <= eids)
            self.assertTrue(set(finding['relacoes']) <= rids)
        self.assertTrue(all(len(s['sha256']) == 64 for s in result['fontes']))

    def test_log_without_year_timezone_not_invented(self):
        result = analyze(self.load('correlation'))
        logs = [e for e in result['evidencias'] if e['tipo'] == 'log']
        self.assertTrue(all(e['dados']['precisao_temporal'] == 'ano_e_fuso_ausentes' for e in logs))
        self.assertTrue(any(r['tipo'] == 'servico_log' for r in result['relacoes']))

    def test_html_escapes_untrusted_content(self):
        snapshot = self.load('normal')
        snapshot['evidencias'][0]['bruto'] = '<script>alert("x")</script>'
        rendered = render_html(analyze(snapshot))
        self.assertNotIn('<script>', rendered)
        self.assertIn('&lt;script&gt;', rendered)

    def test_snapshot_round_trip_and_malformed_rejected(self):
        snapshot = self.load('correlation')
        path = self.root / 'snapshot.json'
        path.write_text(json.dumps(snapshot))
        self.assertEqual(len(self.findings(read_snapshot(path), 'R01')), 1)
        snapshot['evidencias'][1]['dados']['pid'] = -1
        path.write_text(json.dumps(snapshot))
        with self.assertRaises(InputError):
            read_snapshot(path)

    def test_unknown_parent_and_cycles_do_not_hang(self):
        snapshot = self.load('ambiguous')
        processes = [e for e in snapshot['evidencias'] if e['tipo'] == 'processo']
        processes[0]['dados']['ppid'] = 999999
        processes[3]['dados']['ppid'] = processes[4]['dados']['pid']
        result = analyze(snapshot)
        self.assertTrue(any('999999' in w for w in result['avisos']))

    def test_iso_preserves_actual_timezone(self):
        date = datetime(2026, 9, 14, 9, tzinfo=timezone.utc)
        self.assertEqual(datetime.fromisoformat(gen.iso(date)), date)

    def fake_commands(self, pid, script):
        """Respostas controladas de ps, systemctl e journalctl, no formato de texto real."""
        def run(args, **kwargs):
            self.assertNotIn('shell', kwargs)
            if args[0] == 'ps':
                output = f'    1     0 root     Ss   /sbin/init\n {pid}     1 root     Ss   /bin/bash {script}\n'
            elif args[0] == 'journalctl':
                output = f'-- Logs begin --\nSep 29 09:01:03 kali fixture[{pid}]: evento controlado\n'
            elif 'list-units' in args:
                output = 'fixture.service loaded active running Fixture\n'
            else:
                output = f'* fixture.service - Fixture\n     Active: active (running)\n   Main PID: {pid} (bash)\n'
            return subprocess.CompletedProcess(args, 0, output, '')
        return run

    @unittest.skipUnless(sys.platform == 'linux', 'Coleta exige Linux')
    def test_collector_with_controlled_ps_systemctl_and_journal(self):
        pid = 4242
        script = self.root / 'script.sh'
        script.write_text('#!/bin/bash\n')
        script.chmod(0o777)
        with patch('endpoint_investigator.collect.shutil.which', return_value='/mock/bin'), \
                patch('endpoint_investigator.collect.subprocess.run', side_effect=self.fake_commands(pid, script)):
            snapshot = collect(None, 5)
        result = analyze(snapshot)
        self.assertTrue(any(r['tipo'] == 'servico_processo' and r['metodo'].startswith('Main PID') for r in result['relacoes']))
        self.assertTrue(any(r['tipo'] == 'servico_log' for r in result['relacoes']))
        permission = next(e for e in result['evidencias'] if e['tipo'] == 'permissao' and e['dados']['path'] == str(script))
        self.assertEqual(permission['dados']['rwx'], '-rwxrwxrwx')
        self.assertIn('R01', [f['regra'] for f in result['achados']])

    @unittest.skipUnless(sys.platform == 'linux', 'Coleta exige Linux')
    def test_collector_records_unavailable_commands(self):
        with patch('endpoint_investigator.collect.shutil.which', return_value=None):
            snapshot = collect(None, 0)
        self.assertTrue(any('systemctl indisponível' in w for w in snapshot['avisos']))
        self.assertTrue(any('ps indisponível' in w for w in snapshot['avisos']))

    def test_main_pid_match_without_command_equality(self):
        snapshot = self.load('normal')
        service = next(e for e in snapshot['evidencias'] if e['tipo'] == 'servico')
        process = next(e for e in snapshot['evidencias'] if e['tipo'] == 'processo' and e['dados']['pid'] == 1234)
        service['dados']['main_pid'] = 1234
        relations = analyze(snapshot)['relacoes']
        self.assertTrue(any(r['de'] == service['id'] and r['para'] == process['id'] and r['metodo'].startswith('Main PID') for r in relations))

    def test_nonobject_snapshot_rejected(self):
        path = self.root / 'snapshot.json'
        path.write_text('[]')
        with self.assertRaises(InputError):
            read_snapshot(path)


if __name__ == '__main__':
    unittest.main()
