"""Gera seis cenários, analisa os artefatos e registra resultados reais."""
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path

from generate_dataset import make_dataset
from endpoint_investigator.engine import analyze
from endpoint_investigator.input import read_dataset
from endpoint_investigator.report import write_reports


def main():
    root = Path(__file__).resolve().parent
    scenarios = ['normal', 'permission', 'privileged_service', 'correlation', 'ambiguous', 'random']
    results = []
    for scenario in scenarios:
        dataset = root / 'examples' / scenario
        make_dataset('challenge', 42, dataset, scenario)
        report = analyze(read_dataset(dataset))
        write_reports(report, root / 'evidencias' / scenario)
        row = {'cenario': scenario, **report['resumo'],
               'regras': dict(sorted(Counter(f['regra'] for f in report['achados']).items()))}
        results.append(row)
        print(f"{scenario:20s} achados={row['achados']} prioridades={row['por_prioridade']} regras={row['regras']}")
    (root / 'evidencias' / 'demonstracao.json').write_text(json.dumps({
        'executado_em': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'natureza': 'Dados sintéticos; resultados obtidos por execução do motor.',
        'cenarios': results}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
