"""Correlações determinísticas. Risco de configuração não é prova de incidente."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import PurePosixPath
import re

from . import __version__
from .input import execution_targets


LIMITATIONS = [
    'A coleta é uma foto do momento: processos podem terminar ou ter o PID reaproveitado durante a coleta.',
    'A análise usa as permissões rwx de dono, grupo e outros; outros controles de acesso do sistema não são considerados.',
    'A linha de comando mostrada pelo ps não prova qual arquivo foi executado nem o conteúdo de um script.',
    'Só são reconhecidos executáveis com caminho absoluto e scripts chamados diretamente (ex.: bash /opt/x.sh); bash -c e caminhos relativos não são resolvidos.',
    'mtime é a data da última modificação, não da criação, e não prova alteração maliciosa. O hash identifica os arquivos analisados, não quem os produziu.',
    'Nenhuma regra demonstra exploração. Ausência de achados não demonstra segurança.',
]


def is_root(data):
    return str(data.get('user', '')).strip() in ('root', '0')


def analyze(snapshot: dict) -> dict:
    evidence = snapshot['evidencias']
    groups = {kind: [e for e in evidence if e['tipo'] == kind]
              for kind in ('processo', 'permissao', 'servico', 'log')}
    processes = {e['dados']['pid']: e for e in groups['processo']}
    files = {e['dados']['path']: e for e in groups['permissao']}
    relations, findings, contexts = [], [], []
    warnings = list(snapshot.get('avisos', []))
    relation_index = {}

    def relation(kind, origin, target, method, confidence='moderada', limitation=''):
        key = (kind, origin['id'], target['id'])
        if key in relation_index:
            return relation_index[key]
        rid = f'C{len(relations) + 1:04d}'
        relations.append({'id': rid, 'tipo': kind, 'de': origin['id'], 'para': target['id'],
                          'metodo': method, 'confianca': confidence, 'limitacao': limitation})
        relation_index[key] = rid
        return rid

    def finding(rule, title, category, priority, records, observed, interpretation, hypothesis, missing, steps):
        refs = list(dict.fromkeys(e['id'] for e in records))
        findings.append({'id': f'F{len(findings) + 1:04d}', 'regra': rule,
                         'titulo': title, 'categoria': category, 'prioridade': priority,
                         'evidencias': refs,
                         'relacoes': [r['id'] for r in relations if r['de'] in refs and r['para'] in refs],
                         'observado': observed, 'interpretacao': interpretation, 'hipotese': hypothesis,
                         'evidencias_ausentes': missing, 'proximos_passos': steps,
                         'exploracao_comprovada': False})

    children = defaultdict(list)
    for process in groups['processo']:
        data = process['dados']
        parent = processes.get(data['ppid'])
        if parent:
            children[data['ppid']].append(process)
            relation('processo_pai', process, parent, 'PPID do filho = PID do pai no snapshot',
                     limitation='Não demonstra qual identidade foi usada no instante de criação.')
        elif data['ppid'] != 0:
            warnings.append(f"{process['id']}: pai PID {data['ppid']} ausente do snapshot.")
        for target in execution_targets(data.get('argv', [])):
            if target in files:
                relation('processo_codigo', process, files[target], 'Caminho absoluto em posição de executável/script',
                         limitation='O conteúdo do arquivo não foi observado durante a execução.')

    linked = {}
    service_resources = {}
    for service in groups['servico']:
        sd = service['dados']
        if sd['active'] not in ('running', 'active'):
            continue
        main = sd.get('main_pid')
        matches = []
        for process in groups['processo']:
            pd = process['dados']
            method = None
            if main and pd['pid'] == main:
                method = 'Main PID mostrado pelo systemctl status'
            elif not main and sd.get('argv') and sd['argv'] == pd.get('argv') and str(sd['user']) == str(pd['user']):
                method = 'argv completo e usuário iguais; associação candidata'
            if method:
                matches.append(process)
                relation('servico_processo', service, process, method,
                         'alta' if main == pd['pid'] else 'moderada',
                         'Associação atual não autentica eventos históricos; argv idêntico pode ocorrer em instâncias distintas.')
        linked[service['id']] = matches
        targets = execution_targets(sd.get('argv', []))
        for process in matches:
            targets += execution_targets(process['dados'].get('argv', []))
        targets = list(dict.fromkeys(targets))
        service_resources[service['id']] = targets
        for path in targets:
            if path in files:
                relation('servico_codigo', service, files[path], 'Código referenciado pelo ExecStart ou por processo associado',
                         limitation='Dependências carregadas indiretamente não são enumeradas.')
        log_ids = []
        for log in groups['log']:
            ld = log['dados']
            unit = sd['unit']
            unit_in_message = re.search(r'(?<![\w@.\-])' + re.escape(unit) + r'(?![\w@.\-])', ld.get('mensagem', ''))
            if ld.get('unit') == unit or ld.get('tag') == unit.removesuffix('.service') or unit_in_message:
                relation('servico_log', service, log, 'Unidade explícita ou tag correspondente ao nome completo do serviço',
                         limitation='Tag textual pode ser falsificada; logs podem estar incompletos.')
                log_ids.append(log['id'])
        contexts.append({'servico': service['id'], 'processos_candidatos': [p['id'] for p in matches],
                         'alvos_de_codigo': targets, 'alvos_sem_metadados': [t for t in targets if t not in files],
                         'eventos_na_ordem_da_fonte': log_ids,
                         'nota': 'Lista de eventos da fonte; não estabelece causalidade nem uma cronologia absoluta.'})

    for log in groups['log']:
        process = processes.get(log['dados'].get('pid'))
        if process:
            relation('processo_log', process, log, 'PID numérico comum', 'baixa',
                     'O PID pode ter sido reaproveitado por outro processo depois do evento registrado.')

    covered_files, covered_directories = set(), set()
    base_missing = ['Quem de fato consegue alterar o arquivo: integrantes do grupo e permissões de todos os diretórios do caminho.',
                    'Conteúdo do script e se ele foi alterado (comparar o hash SHA-256 com uma versão conhecida).',
                    'Logs que mostrem uma alteração não autorizada seguida de execução pelo serviço.']
    for service in groups['servico']:
        if service['id'] not in linked:
            continue
        sd = service['dados']
        matches = linked[service['id']]
        roots = [p for p in matches if is_root(p['dados'])]
        if not is_root(sd) and not roots:
            continue
        execution = 'Processo associado observado com identidade root.' if roots else 'Serviço configurado como root; execução root não confirmada neste snapshot.'
        for target in service_resources[service['id']]:
            file = files.get(target)
            if file and file['dados']['type'] == 'file':
                fd = file['dados']
                mode = int(fd['mode'], 8)
                root_owner = str(fd.get('uid', fd['owner'])) in ('0', 'root')
                if mode & 0o002 or not root_owner:
                    covered_files.add(file['id'])
                    reason = 'bit de escrita para outros' if mode & 0o002 else 'proprietário não root, que pode alterar o arquivo e suas permissões com chmod'
                    finding('R01', f"Código modificável associado a {sd['unit']}", 'risco', 'alta',
                            [service, *matches, file],
                            [f"{sd['unit']}: usuário declarado {sd['user']}; ExecStart={sd['execstart']}.",
                             execution, f"{target}: proprietário {fd['owner']}, modo {fd['mode']}; {reason}."],
                            'O privilégio de execução está relacionado a um recurso de código cuja modificação merece verificação.',
                            'Se um usuário não privilegiado conseguir alterar esse recurso e o serviço o utilizar depois, poderá influenciar código executado como root.',
                            base_missing, ['Verificar as permissões de todos os diretórios do caminho (ls -ld).', 'Comparar o hash do script com uma versão aprovada e revisar o serviço (systemctl status).'])
                elif mode & 0o020:
                    finding('R05', f"Escrita por grupo em código de {sd['unit']}", 'inconclusivo', 'media',
                            [service, *matches, file], [execution, f"{target}: modo {fd['mode']}, grupo {fd['group']}."],
                            'O grupo pode escrever pelos bits de modo; seus integrantes e demais controles não foram determinados.',
                            'Pode haver delegação administrativa legítima ou capacidade de alterar código privilegiado.',
                            ['Integrantes do grupo (comandos id/groups ou /etc/group) e motivo da permissão de escrita.', *base_missing],
                            ['Conferir os integrantes do grupo e a necessidade da escrita.'])
            parent = files.get(str(PurePosixPath(target).parent))
            if parent and parent['dados']['type'] == 'directory':
                mode = int(parent['dados']['mode'], 8)
                if mode & 0o002:
                    if (service['id'], parent['id']) in covered_directories:
                        continue
                    covered_directories.add((service['id'], parent['id']))
                    if file:
                        relation('arquivo_diretorio', file, parent, 'Diretório pai imediato do caminho', 'alta')
                    relation('servico_diretorio', service, parent, 'Diretório pai de código referenciado', 'alta')
                    finding('R02', f"Diretório permite substituição potencial de código de {sd['unit']}", 'risco', 'alta',
                            [service, *matches, *([file] if file else []), parent],
                            [execution, f"Diretório {parent['dados']['path']}: modo {parent['dados']['mode']}; escrita (w) para outros."],
                            'Quem pode escrever no diretório pode apagar e recriar arquivos dentro dele, mesmo que o arquivo em si não permita escrita.',
                            'Um usuário que consiga escrever no diretório pode substituir o script que o serviço utilizará.',
                            base_missing, ['Verificar dono, grupo e necessidade de escrita no diretório (ls -ld).'])

    for file in groups['permissao']:
        fd = file['dados']
        mode = int(fd['mode'], 8)
        if fd['type'] != 'file':
            continue
        if mode & 0o002 and file['id'] not in covered_files:
            finding('R03', f"Arquivo com escrita para outros: {fd['path']}", 'risco', 'media', [file],
                    [f"{fd['path']}: proprietário {fd['owner']}, grupo {fd['group']}, modo {fd['mode']}."],
                    'O modo concede escrita a outros; nenhuma relação com execução privilegiada foi estabelecida.',
                    'Pode ser compartilhamento intencional ou uma configuração inadequada.',
                    ['Finalidade do arquivo e quem deveria poder alterá-lo.', 'Serviço/processo que usa o arquivo e com qual usuário.'],
                    ['Identificar quem usa o arquivo e quais permissões são necessárias.'])
        special = [name for bit, name in ((0o4000, 'SUID'), (0o2000, 'SGID')) if mode & bit]
        if special and mode & 0o111 and str(fd.get('uid', fd['owner'])) in ('root', '0'):
            bits = '/'.join(special)
            finding('R04', f"Arquivo root com bit {bits}: {fd['path']}", 'informativo', 'informativa', [file],
                    [f"{fd['path']}: tipo file, proprietário {fd['owner']}, grupo {fd['group']}, modo {fd['mode']}."],
                    f'O bit {bits} faz o programa executar com o usuário/grupo do dono, e não de quem o chamou.',
                    'Pode ser um utilitário legítimo (ex.: passwd, sudo) ou uma instalação que precise de revisão.',
                    ['Finalidade do programa e se ele faz parte do sistema (comparar o hash SHA-256 com o do pacote original).', 'Logs de uso do programa por usuários comuns.'],
                    ['Verificar o arquivo sem executá-lo e comparar com a lista de SUID/SGID esperados (find / -perm -4000).'])

    for service in groups['servico']:
        if service['id'] not in linked:
            continue
        frontier = list(linked[service['id']])
        seen, descendants = set(), []
        while frontier:
            process = frontier.pop(0)
            if process['id'] in seen:
                continue
            seen.add(process['id'])
            descendants.append(process)
            frontier.extend(children[process['dados']['pid']])
        for process in descendants:
            pd = process['dados']
            urls = [a for a in pd.get('argv', []) if re.match(r'^https?://', a)]
            if urls and is_root(pd):
                finding('R06', f"URL em comando root no contexto de {service['dados']['unit']}", 'informativo', 'informativa',
                        [service, *linked[service['id']], process],
                        [f"PID {pd['pid']}, PPID {pd['ppid']}, usuário {pd['user']}; URL(s): {', '.join(urls)}."],
                        'O comando contém um destino HTTP(S). A ancestralidade relaciona o processo ao serviço.',
                        'Pode ser atualização, backup ou monitoramento. A linha de comando não prova conexão estabelecida nem envio de dados.',
                        ['Conexões abertas pelo processo (sockets em /proc/<PID>/fd), resolução DNS do destino e tráfego capturado.'],
                        ['Comparar o destino com a configuração do serviço e capturar o tráfego com tcpdump se necessário.'])

    for process in groups['processo']:
        parent = processes.get(process['dados']['ppid'])
        if parent and is_root(process['dados']) and not is_root(parent['dados']):
            finding('R07', f"Filho root de pai não root: PID {process['dados']['pid']}", 'inconclusivo', 'media',
                    [parent, process],
                    [f"Pai PID {parent['dados']['pid']} ({parent['dados']['user']}); filho PID {process['dados']['pid']} ({process['dados']['user']})."],
                    'As identidades observadas diferem e o filho apresenta identidade root.',
                    'Pode haver sudo, SUID ou mudança autorizada de credenciais; o snapshot não reconstrói a transição.',
                    ['Logs de autenticação (ex.: uso de sudo) e se o executável do filho tem bit SUID.'],
                    ['Correlacionar com autenticação e política de privilégio.'])

    # Referências são completadas após todas as relações terem sido produzidas.
    for item in findings:
        refs = set(item['evidencias'])
        item['relacoes'] = [r['id'] for r in relations if r['de'] in refs and r['para'] in refs]
    counts = Counter(f['prioridade'] for f in findings)
    return {'versao_formato': '1.0', 'ferramenta': {'nome': 'Endpoint Investigator', 'versao': __version__},
            'analisado_em': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'tipo_coleta': snapshot.get('tipo_coleta', 'desconhecido'),
            'fontes': snapshot.get('fontes', []), 'evidencias': evidence, 'relacoes': relations,
            'contextos_de_servicos': contexts, 'achados': findings,
            'resumo': {'evidencias': len(evidence), 'relacoes': len(relations), 'achados': len(findings),
                       'por_prioridade': {key: counts.get(key, 0) for key in ('alta', 'media', 'baixa', 'informativa')},
                       'por_tipo_de_evidencia': {key: len(value) for key, value in groups.items()},
                       'conclusao': 'As regras não determinam ocorrência de exploração; os achados indicam verificações a realizar.'},
            'avisos': list(dict.fromkeys(warnings)), 'limitacoes': LIMITATIONS}
