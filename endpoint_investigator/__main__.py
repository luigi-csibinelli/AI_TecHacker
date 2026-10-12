"""python -m endpoint_investigator --help"""
import argparse
import json
from pathlib import Path
import sys

from .collect import collect
from .engine import analyze
from .input import InputError, read_dataset, read_snapshot
from .report import write_reports


def main():
    parser = argparse.ArgumentParser(description='Endpoint Investigator: processos, permissões, serviços e logs.')
    commands = parser.add_subparsers(dest='command', required=True)
    analyze_parser = commands.add_parser('analyze', help='Analisar dataset ou snapshot já coletado')
    sources = analyze_parser.add_mutually_exclusive_group(required=True)
    sources.add_argument('--dataset', type=Path)
    sources.add_argument('--snapshot', type=Path)
    analyze_parser.add_argument('--out', type=Path, required=True)
    collect_parser = commands.add_parser('collect', help='Coletar snapshot local Linux, sem modificar serviços ou permissões')
    collect_parser.add_argument('--out', type=Path, required=True)
    collect_parser.add_argument('--pid', type=int, action='append', help='Restringir processos; opção repetível')
    collect_parser.add_argument('--journal-lines', type=int, default=200)
    args = parser.parse_args()
    try:
        if args.command == 'collect':
            if not 0 <= args.journal_lines <= 10000 or (args.pid and any(pid <= 0 for pid in args.pid)):
                raise InputError('Use PIDs positivos e journal-lines entre 0 e 10000.')
            snapshot = collect(args.pid, args.journal_lines)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
            print(f"Snapshot salvo: {args.out}; {len(snapshot['evidencias'])} evidências; {len(snapshot['avisos'])} avisos.")
        else:
            snapshot = read_dataset(args.dataset) if args.dataset else read_snapshot(args.snapshot)
            result = analyze(snapshot)
            write_reports(result, args.out)
            counts = result['resumo']['por_prioridade']
            print(f"{len(result['evidencias'])} evidências | {len(result['relacoes'])} relações | {len(result['achados'])} achados")
            print('Prioridades: ' + ', '.join(f'{name}={value}' for name, value in counts.items()))
            print(f"Saídas: {args.out / 'evidencias.json'}, {args.out / 'relatorio.html'}, {args.out / 'relatorio.md'}")
        return 0
    except (InputError, OSError, ValueError) as exc:
        print(f'Erro: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
