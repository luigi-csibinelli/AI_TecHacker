"""Relatórios locais: JSON rastreável, Markdown e HTML sem conteúdo remoto."""
from __future__ import annotations

import html
import json
from pathlib import Path


def write_reports(result: dict, output: Path):
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidencias.json').write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    md = ['# Endpoint Investigator', '', f"Análise: {result['analisado_em']}", '',
          result['resumo']['conclusao'], '', '## Resumo', '',
          f"{len(result['evidencias'])} evidências; {len(result['relacoes'])} relações; {len(result['achados'])} achados.", '']
    for finding in result['achados']:
        md += [f"## {finding['id']} · {finding['regra']} · {finding['titulo']}", '',
               f"Categoria: {finding['categoria']}. Prioridade: {finding['prioridade']}.", '',
               'Evidências: ' + ', '.join(finding['evidencias']), '', '**Observado**', '']
        md += ['- ' + x for x in finding['observado']]
        for key, label in [('interpretacao', 'Interpretação'), ('hipotese', 'Hipótese')]:
            md += ['', f'**{label}**', '', finding[key]]
        for key, label in [('evidencias_ausentes', 'Evidências ausentes'), ('proximos_passos', 'Próximos passos')]:
            md += ['', f'**{label}**', ''] + ['- ' + x for x in finding[key]]
        md += ['', 'Exploração comprovada: não.', '']
    md += ['## Avisos e limitações', ''] + ['- ' + x for x in result['avisos'] + result['limitacoes']]
    md += ['', '## Fontes e integridade', '', 'SHA-256 permite conferir os artefatos analisados; não autentica sua origem.', '']
    md += [f"- {s['arquivo']}: {s['sha256']} ({s['bytes']} bytes)" for s in result['fontes']]
    (output / 'relatorio.md').write_text('\n'.join(md) + '\n', encoding='utf-8')
    (output / 'relatorio.html').write_text(render_html(result), encoding='utf-8')


def render_html(result):
    def esc(value):
        return html.escape(str(value), quote=True)

    def listing(values):
        return '<ul>' + ''.join(f'<li>{esc(x)}</li>' for x in values) + '</ul>'

    def refs(ids):
        return ' '.join(f'<a class="ref" href="#{esc(x)}">{esc(x)}</a>' for x in ids)

    parts = ['''<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>Endpoint Investigator · Evidências</title><style>
:root{font-family:system-ui,-apple-system,sans-serif;color:#192b3b;background:#edf1f4;line-height:1.6}
*{box-sizing:border-box}body{margin:0;overflow-wrap:anywhere}main{max-width:1120px;margin:auto;padding:32px 24px 64px}
header{background:#102b3f;color:#fff;padding:36px 28px;border-radius:12px}h1{font-size:32px;margin:0 0 10px}
h2{margin-top:34px;font-size:24px}h3{font-size:19px;margin:6px 0 16px}h4{margin:20px 0 4px}
p{margin:8px 0 14px}.eyebrow{font-size:12px;letter-spacing:2px;text-transform:uppercase;color:#9fd4e4}
.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:20px 0}.metric,article,details,.box{background:white;border:1px solid #d6dfe5;border-radius:9px;padding:20px;margin:14px 0}
.metric{margin:0}.metric strong{display:block;font-size:29px}.tag{display:inline-block;padding:2px 9px;background:#eaf0f4;border-radius:5px;font-size:13px}
.alta{border-left:5px solid #ad3e30}.media{border-left:5px solid #aa7315}.informativa{border-left:5px solid #27748e}
a{color:#126881}.ref{display:inline-block;padding:2px 7px;background:#edf6f9;border-radius:4px;margin:2px;font-family:monospace}
code,pre{font-family:ui-monospace,monospace;font-size:12px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f5f7;padding:12px;border-radius:5px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #dce4e9;padding:10px;overflow-wrap:anywhere}
summary{cursor:pointer;font-weight:600}.small{font-size:13px;color:#536676}li{margin:5px 0}.scroll{overflow-x:auto}footer{margin-top:36px}
@media(max-width:650px){.cards{grid-template-columns:1fr}main{padding:16px}h1{font-size:26px}th,td{min-width:100px}}
@media print{body{background:white}main{padding:0}article{break-inside:avoid}header{color:#102b3f;background:white;border:1px solid #bbc9d2}.ref{color:#102b3f}details{break-inside:avoid}}
</style></head><body><main><header><div class="eyebrow">Tecnologias Hackers · investigação de endpoint</div>
<h1>Endpoint Investigator</h1><p>Evidência → relação → interpretação → hipótese</p>''']
    parts.append(f"<p>Origem: {esc(result['tipo_coleta'])} · Análise: {esc(result['analisado_em'])}</p></header>")
    parts.append('<div class="cards">' + ''.join(f'<div class="metric"><strong>{result["resumo"][key]}</strong>{label}</div>' for key, label in [('evidencias', 'Evidências registradas'), ('relacoes', 'Relações explícitas'), ('achados', 'Achados para investigação')]) + '</div>')
    parts.append('<p class="box">' + esc(result['resumo']['conclusao']) + '</p>')
    parts.append('<nav><a href="#achados">Achados</a> · <a href="#contextos">Serviços e logs</a> · <a href="#relacoes">Relações</a> · <a href="#evidencias">Evidências</a> · <a href="#limites">Limitações</a></nav><h2 id="achados">Achados</h2>')
    if not result['achados']:
        parts.append('<p class="box">As regras implementadas não produziram achados. Isso não demonstra ausência de outros riscos.</p>')
    for f in result['achados']:
        parts.append(f'<article id="{esc(f["id"])}" class="{esc(f["prioridade"])}"><span class="tag">{esc(f["id"])} / {esc(f["regra"])} · {esc(f["categoria"])} · prioridade {esc(f["prioridade"])}</span><h3>{esc(f["titulo"])}</h3><p>{refs(f["evidencias"])}</p>')
        for key, label in [('observado', 'Observado'), ('interpretacao', 'Interpretação'), ('hipotese', 'Hipótese'), ('evidencias_ausentes', 'Evidências ausentes'), ('proximos_passos', 'Próximos passos')]:
            parts.append(f'<h4>{label}</h4>' + (listing(f[key]) if isinstance(f[key], list) else '<p>' + esc(f[key]) + '</p>'))
        parts.append('<p class="small">Exploração comprovada: não. Relações: ' + refs(f['relacoes']) + '</p></article>')
    parts.append('<h2 id="contextos">Serviços e eventos</h2>')
    for c in result['contextos_de_servicos']:
        parts.append('<details><summary>Contexto ' + esc(c['servico']) + '</summary><p>Serviço: ' + refs([c['servico']]) + ' · Processos candidatos: ' + refs(c['processos_candidatos']) + '</p><h4>Código referenciado</h4>' + listing(c['alvos_de_codigo']) + '<h4>Sem metadados</h4>' + listing(c['alvos_sem_metadados']) + '<h4>Eventos na ordem da fonte</h4><p>' + refs(c['eventos_na_ordem_da_fonte']) + '</p><p class="small">' + esc(c['nota']) + '</p></details>')
    parts.append('<h2 id="relacoes">Relações</h2><div class="scroll"><table><thead><tr><th>ID</th><th>Relação</th><th>Origem / destino</th><th>Critério e limite</th></tr></thead><tbody>')
    for r in result['relacoes']:
        parts.append(f'<tr id="{esc(r["id"])}"><td>{esc(r["id"])}</td><td>{esc(r["tipo"])}</td><td>{refs([r["de"], r["para"]])}</td><td>{esc(r["metodo"])}<br><span class="small">Confiança da associação: {esc(r["confianca"])}. {esc(r["limitacao"])}</span></td></tr>')
    parts.append('</tbody></table></div><h2 id="evidencias">Evidências e proveniência</h2>')
    for e in result['evidencias']:
        parts.append(f'<details id="{esc(e["id"])}"><summary>{esc(e["id"])} · {esc(e["tipo"])} · {esc(e["origem"]["arquivo"])}' + (f':{e["origem"]["linha"]}' if e['origem'].get('linha') else '') + '</summary><h4>Registro original</h4><pre>' + esc(e['bruto']) + '</pre><h4>Normalizado</h4><pre>' + esc(json.dumps(e['dados'], indent=2, ensure_ascii=False)) + '</pre></details>')
    parts.append('<h2 id="limites">Avisos e limitações</h2><div class="box">' + listing(result['avisos'] + result['limitacoes']) + '</div><h2>Artefatos analisados</h2><p>Hashes identificam os bytes analisados; não autenticam a origem da coleta.</p>')
    for source in result['fontes']:
        parts.append('<pre>' + esc(source['arquivo']) + '\nSHA-256 ' + esc(source['sha256']) + f'\n{source["bytes"]} bytes</pre>')
    parts.append('<footer class="small">Regras locais e determinísticas. Nenhum modelo de linguagem é chamado durante a execução.</footer></main></body></html>')
    return ''.join(parts)
