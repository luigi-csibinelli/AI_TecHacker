# Adaptações no gerador

O original recebido está preservado em `tools/generate_dataset_original.py`. As mudanças abaixo afetam somente a cópia `generate_dataset.py` incluída no projeto.

| Ponto | Comportamento observado | Correção |
| --- | --- | --- |
| `random_noise` | `scenario_normal` já entrega processos/permissões como dicionários, mas `build` espera tuplas. A execução original gerou `ValueError: too many values to unpack (expected 5)` | Reconstruir as tuplas antes de chamar `build` |
| Logs no cenário aleatório | O cenário base já contém objetos datetime, mas `build` espera deslocamentos em segundos | Converter cada datetime em segundos relativos ao início |
| `iso` | O início é UTC; a função anterior escrevia `-03:00` sem converter a hora | Usar `datetime.isoformat`, preservando o fuso real |
| `scenario_permission` | Herdava `kind=normal`, apesar da permissão adicional | Definir `kind=permission` |
| Escolha dos cenários | O sorteio não garante os seis casos em uma apresentação | Adicionar `--scenario` explícito, sem remover `--level` ou `--batch` |

As correções do gerador não são usadas como resposta pela análise. O motor só lê os quatro artefatos observacionais. O teste de compatibilidade também analisa os cinco cenários fixos produzidos pelas funções originais.

Os logs textuais continuam sem ano ou fuso. Não se preenchem esses campos por adivinhação. A alteração em `iso` não resolve a incerteza dos logs nem transforma timestamps sintéticos de observação em instantes de início de processos.
