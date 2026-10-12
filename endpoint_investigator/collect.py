"""Snapshot Linux somente de leitura com os comandos vistos em aula: ps, systemctl, journalctl e ls -l."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import PurePosixPath
import re
import shutil
import stat
import subprocess
import sys

from .input import InputError, argv, execution_targets, parse_syslog_line


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def collect(pids=None, journal_lines=200) -> dict:
    if sys.platform != 'linux':
        raise InputError('Coleta local requer Linux; análise de datasets também funciona fora do Linux.')
    import pwd
    import grp

    evidence, warnings, counters = [], [], {}
    started = now()

    def add(kind, source, raw, data):
        prefix = {'processo': 'P', 'permissao': 'A', 'servico': 'S', 'log': 'L'}[kind]
        counters[kind] = counters.get(kind, 0) + 1
        item = {'id': f'{prefix}{counters[kind]:04d}', 'tipo': kind,
                'origem': {'arquivo': source, 'linha': None, 'observado_em': now()},
                'bruto': raw, 'dados': data}
        evidence.append(item)
        return item

    def command(args, accept=(0,)):
        """Executa um comando de consulta (nunca via shell) e devolve a saída de texto."""
        if shutil.which(args[0]) is None:
            warnings.append(f'{args[0]} indisponível; fonte não coletada.')
            return ''
        try:
            result = subprocess.run(args, capture_output=True, text=True, errors='replace',
                                    timeout=15, env={**os.environ, 'LC_ALL': 'C', 'SYSTEMD_PAGER': 'cat'})
        except (OSError, subprocess.TimeoutExpired) as exc:
            warnings.append(f'{args[0]}: {type(exc).__name__}; fonte incompleta.')
            return ''
        if result.returncode not in accept:
            warnings.append(f'{" ".join(args[:2])} retornou {result.returncode}: {result.stderr.strip()[:400]}')
            return ''
        return result.stdout

    # 1. Processos: mesmo comando do handout da Aula 2 (ps -eo pid,ppid,user,stat,cmd).
    process_by_pid = {}
    ps_output = command(['ps', '-eo', 'pid,ppid,user:32,stat,cmd', '--no-headers'])
    for line in ps_output.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 5 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        pid, ppid, user, state, cmd = int(parts[0]), int(parts[1]), parts[2], parts[3], parts[4]
        if pids and pid not in pids:
            continue
        data = {'timestamp': now(), 'pid': pid, 'ppid': ppid, 'user': user,
                'stat': state, 'cmd': cmd, 'argv': argv(cmd)}
        process_by_pid[pid] = add('processo', 'ps -eo pid,ppid,user,stat,cmd', line, data)

    # 2. Serviços: systemctl list-units e systemctl status, como no handout.
    units_text = command(['systemctl', 'list-units', '--type=service', '--state=running', '--no-legend', '--no-pager', '--plain'])
    units = [line.split()[0] for line in units_text.splitlines()
             if line.split() and line.split()[0].endswith('.service')]
    services = []
    for unit in units:
        # systemctl status retorna 3 para serviços parados; aqui só pedimos serviços running.
        status = command(['systemctl', 'status', '--no-pager', '-n', '0', unit], accept=(0, 3))
        match = re.search(r'Main PID:\s*(\d+)', status)
        main_pid = int(match[1]) if match else 0
        main_process = process_by_pid.get(main_pid)
        if main_process:
            user, cmd = main_process['dados']['user'], main_process['dados']['cmd']
        else:
            user, cmd = 'desconhecido', ''
            warnings.append(f'{unit}: processo principal não encontrado na saída do ps; usuário e comando desconhecidos.')
        data = {'unit': unit, 'active': 'running', 'user': user, 'execstart': cmd,
                'argv': argv(cmd), 'main_pid': main_pid}
        services.append(add('servico', f'systemctl status {unit}', status, data))
    if not units:
        warnings.append('Nenhum serviço em execução foi obtido. Isso não significa que o host não tenha serviços.')

    # 3. Permissões: as mesmas informações do ls -l (dono, grupo, rwx) para o código usado
    #    pelos processos/serviços e para os diretórios do caminho.
    targets = set()
    for item in [*process_by_pid.values(), *services]:
        for target in execution_targets(item['dados'].get('argv', [])):
            targets.add(target)
            targets.update(str(p) for p in PurePosixPath(target).parents)
    for path in sorted(targets):
        try:
            details = os.stat(path)
        except OSError as exc:
            warnings.append(f'{path}: {type(exc).__name__}; permissões indisponíveis.')
            continue
        if not (stat.S_ISREG(details.st_mode) or stat.S_ISDIR(details.st_mode)):
            continue
        try:
            owner = pwd.getpwuid(details.st_uid).pw_name
        except KeyError:
            owner = str(details.st_uid)
        try:
            group = grp.getgrgid(details.st_gid).gr_name
        except KeyError:
            group = str(details.st_gid)
        data = {'path': path, 'type': 'directory' if stat.S_ISDIR(details.st_mode) else 'file',
                'owner': owner, 'group': group,
                'mode': f'{stat.S_IMODE(details.st_mode):04o}',
                'rwx': stat.filemode(details.st_mode),
                'mtime': datetime.fromtimestamp(details.st_mtime, timezone.utc).isoformat()}
        add('permissao', 'ls -ld ' + path, json.dumps(data, ensure_ascii=False), data)

    # 4. Logs: journalctl -n <linhas>, no mesmo formato de texto visto em aula.
    if journal_lines:
        raw = command(['journalctl', '--no-pager', '-n', str(journal_lines)])
        for line in raw.splitlines():
            if not line.strip() or line.startswith('--'):
                continue
            data = parse_syslog_line(line)
            if data['tag'] is None:
                warnings.append(f'journalctl: linha em formato desconhecido preservada: {line[:80]}')
            add('log', 'journalctl -n', line, data)

    if pids:
        warnings.append('Coleta de processos restrita aos PIDs solicitados; pais e filhos podem não constar.')
    warnings.append('Permissões obtidas como no ls -l (dono, grupo e rwx).')
    return {'versao_snapshot': 1, 'tipo_coleta': 'linux_local', 'inicio': started, 'fim': now(),
            'fontes': [], 'avisos': warnings, 'evidencias': evidence}
