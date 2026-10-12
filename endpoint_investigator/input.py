"""Leitura dos artefatos; nenhum rótulo didático entra no motor de análise."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import shlex
from pathlib import Path, PurePosixPath


class InputError(ValueError):
    pass


def argv(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return []


def execution_targets(args: list[str]) -> list[str]:
    """Executável absoluto e script simples; não confunde argumento de dados com código.

    Não interpreta comandos de shell, Python -c/-m, expansões ou scripts relativos.
    """
    if not args:
        return []
    targets = [args[0]] if args[0].startswith('/') else []
    binary = PurePosixPath(args[0]).name
    interpreters = {'sh', 'bash', 'dash', 'zsh', 'ksh', 'python', 'python2', 'python3', 'perl', 'ruby'}
    if binary not in interpreters and not re.fullmatch(r'python\d+(?:\.\d+)?', binary):
        return targets
    for token in args[1:]:
        if token == '--':
            continue
        if token.startswith('-'):
            # Só tratamos a forma direta "interpretador /caminho/script".
            return targets
        if token.startswith('/'):
            targets.append(token)
        break
    return list(dict.fromkeys(targets))


def parse_syslog_line(raw: str) -> dict:
    """Linha no formato do journalctl/syslog: 'Mon DD HH:MM:SS host tag[pid]: mensagem'."""
    data = {'mensagem': raw, 'timestamp': None, 'pid': None, 'tag': None}
    match = re.match(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)$', raw)
    if match:
        timestamp, host, tag, message = match.groups()
        emitter = re.fullmatch(r'(.+?)\[(\d+)\]', tag)
        data.update(timestamp=timestamp, host=host, mensagem=message,
                    tag=emitter[1] if emitter else tag,
                    pid=int(emitter[2]) if emitter else None,
                    precisao_temporal='ano_e_fuso_ausentes')
    return data


def read_dataset(directory: Path) -> dict:
    evidence, sources, warnings = [], [], []
    counters = {'processo': 0, 'permissao': 0, 'servico': 0, 'log': 0}
    prefixes = {'processo': 'P', 'permissao': 'A', 'servico': 'S', 'log': 'L'}

    def source(filename, required=True):
        path = directory / filename
        if not path.exists():
            if required:
                raise InputError(f'Arquivo obrigatório ausente: {filename}')
            warnings.append(f'{filename} ausente: correlação com logs indisponível.')
            return None
        raw = path.read_bytes()
        sources.append({'arquivo': filename, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)})
        try:
            return raw.decode('utf-8-sig')
        except UnicodeDecodeError as exc:
            raise InputError(f'{filename}: esperado UTF-8') from exc

    def add(kind, filename, line, raw, data):
        counters[kind] += 1
        evidence.append({'id': f'{prefixes[kind]}{counters[kind]:04d}', 'tipo': kind,
                         'origem': {'arquivo': filename, 'linha': line},
                         'bruto': raw, 'dados': data})

    def rows(filename, fields):
        content = source(filename)
        reader = csv.DictReader(io.StringIO(content, newline=''))
        if not reader.fieldnames or not set(fields).issubset(reader.fieldnames):
            raise InputError(f'{filename}: colunas obrigatórias: {", ".join(fields)}')
        lines = content.splitlines()
        previous = 1
        for row in reader:
            start = previous + 1
            previous = reader.line_num
            if None in row or any(row.get(k) is None for k in fields):
                raise InputError(f'{filename}:{start}: número incorreto de colunas')
            yield start, '\n'.join(lines[start - 1:reader.line_num]), row

    seen = set()
    for line, raw, row in rows('processes.csv', ['timestamp', 'pid', 'ppid', 'user', 'stat', 'cmd']):
        try:
            pid, ppid = int(row['pid']), int(row['ppid'])
            if pid <= 0 or ppid < 0 or pid in seen or ppid == pid:
                raise ValueError('PID inválido ou duplicado')
        except ValueError as exc:
            raise InputError(f'processes.csv:{line}: PID/PPID inválido ou duplicado') from exc
        seen.add(pid)
        args = argv(row['cmd'])
        if row['cmd'] and not args:
            warnings.append(f'processes.csv:{line}: comando com aspas inválidas; alvos não extraídos.')
        add('processo', 'processes.csv', line, raw, {**row, 'pid': pid, 'ppid': ppid, 'argv': args})

    seen = set()
    for line, raw, row in rows('permissions.csv', ['path', 'type', 'owner', 'group', 'mode', 'mtime']):
        if not re.fullmatch(r'[0-7]{3,4}', row['mode']) or row['type'] not in ('file', 'directory'):
            raise InputError(f'permissions.csv:{line}: modo octal ou tipo inválido')
        if not row['path'].startswith('/') or row['path'] in seen:
            raise InputError(f'permissions.csv:{line}: caminho deve ser absoluto e único')
        seen.add(row['path'])
        add('permissao', 'permissions.csv', line, raw, {**row, 'mode': f"{int(row['mode'], 8):04o}"})

    seen = set()
    content = source('services.txt')
    lines = content.splitlines()
    if not lines or lines[0].split() != ['UNIT', 'ACTIVE', 'USER', 'EXECSTART']:
        raise InputError('services.txt: cabeçalho inválido')
    for line, raw in enumerate(lines[1:], 2):
        if not raw.strip():
            continue
        parts = raw.split(None, 3)
        if len(parts) != 4 or not parts[0].endswith('.service') or parts[0] in seen:
            raise InputError(f'services.txt:{line}: serviço inválido ou duplicado')
        unit, active, user, command = parts
        seen.add(unit)
        add('servico', 'services.txt', line, raw,
            {'unit': unit, 'active': active, 'user': user, 'execstart': command, 'argv': argv(command)})

    content = source('journal.log', False)
    if content is not None:
        for line, raw in enumerate(content.splitlines(), 1):
            if not raw.strip():
                continue
            data = parse_syslog_line(raw)
            if data['tag'] is None:
                warnings.append(f'journal.log:{line}: formato desconhecido; linha preservada.')
            add('log', 'journal.log', line, raw, data)
    warnings.append('Datasets: USER é apenas o nome do usuário informado; UID/GID e grupos não foram fornecidos.')
    if content:
        warnings.append('journal.log não informa ano/fuso: não é combinado com timestamps ISO como uma cronologia absoluta.')
    return {'versao_snapshot': 1, 'tipo_coleta': 'dataset', 'fontes': sources,
            'avisos': warnings, 'evidencias': evidence}


def read_snapshot(path: Path) -> dict:
    try:
        raw = path.read_bytes()
        data = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise InputError(f'Snapshot JSON inválido: {exc}') from exc
    if not isinstance(data, dict) or data.get('versao_snapshot') != 1 or not isinstance(data.get('evidencias'), list):
        raise InputError('Snapshot incompatível: esperado versao_snapshot=1 e lista evidencias')
    ids = set()
    required = {'processo': {'pid', 'ppid', 'user', 'cmd', 'argv'},
                'permissao': {'path', 'type', 'mode', 'owner', 'group'},
                'servico': {'unit', 'user', 'active', 'execstart', 'argv'},
                'log': {'mensagem'}}
    keys = {kind: set() for kind in required}
    for record in data['evidencias']:
        if not isinstance(record, dict):
            raise InputError('Evidência deve ser objeto JSON')
        kind, value = record.get('tipo'), record.get('dados')
        if kind not in required or not isinstance(value, dict) or not required[kind].issubset(value):
            raise InputError('Evidência inválida no snapshot')
        if not record.get('id') or record['id'] in ids or 'origem' not in record or 'bruto' not in record:
            raise InputError('ID ausente/duplicado ou proveniência ausente no snapshot')
        ids.add(record['id'])
        if kind == 'permissao' and (not re.fullmatch(r'[0-7]{3,4}', str(value['mode'])) or value['type'] not in ('file', 'directory')):
            raise InputError('Permissão inválida no snapshot')
        if kind == 'processo' and (type(value['pid']) is not int or type(value['ppid']) is not int or value['pid'] <= 0 or value['ppid'] < 0 or value['pid'] == value['ppid']):
            raise InputError('PID/PPID inválido no snapshot')
        if kind in ('processo', 'servico') and (not isinstance(value['argv'], list) or not all(isinstance(x, str) for x in value['argv'])):
            raise InputError('argv inválido no snapshot')
        key = value.get({'processo': 'pid', 'permissao': 'path', 'servico': 'unit', 'log': 'unused'}[kind])
        if key is not None:
            if key in keys[kind]:
                raise InputError(f'Registro duplicado de {kind}')
            keys[kind].add(key)
    data['fontes'] = [{'arquivo': path.name, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}]
    return data
