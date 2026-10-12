"""Registra execução verificável dos testes e um smoke test local limitado."""
import contextlib
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import platform
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from endpoint_investigator.collect import collect
from endpoint_investigator.engine import analyze


def main():
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    output = ROOT / 'evidencias'
    output.mkdir(exist_ok=True)
    (output / 'testes.txt').write_text(stream.getvalue(), encoding='utf-8')
    summary = {'executado_em': datetime.now(timezone.utc).isoformat(timespec='seconds'),
               'python': platform.python_version(), 'sistema': platform.system(),
               'testes': result.testsRun, 'falhas': len(result.failures), 'erros': len(result.errors),
               'ignorados': len(result.skipped), 'sucesso': result.wasSuccessful()}
    if sys.platform == 'linux':
        snapshot = collect([1], 0)
        report = analyze(snapshot)
        summary['smoke_test_coleta_local'] = {
            'escopo': 'Somente o PID 1 da saída do ps; sem leitura de journal.',
            'processos': sum(e['tipo'] == 'processo' for e in snapshot['evidencias']),
            'permissoes': sum(e['tipo'] == 'permissao' for e in snapshot['evidencias']),
            'servicos': sum(e['tipo'] == 'servico' for e in snapshot['evidencias']),
            'resultado_gerado': bool(report.get('versao_formato')),
            'systemd_real_validado': any(e['tipo'] == 'servico' for e in snapshot['evidencias']),
            'nota': 'O snapshot local bruto não é distribuído. Respostas de systemd/journal também são testadas com fixtures controladas.'}
    (output / 'validacao.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
