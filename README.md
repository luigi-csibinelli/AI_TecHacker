# Endpoint Investigator

**Integrantes:** Luigi Sibinelli, Mathias Zanotto

Ferramenta para a Avaliação Intermediária de Tecnologias Hackers. Analisa processos, permissões e serviços Linux, produzindo evidências estruturadas antes de qualquer interpretação humana ou por IA.

A implementação usa regras locais. Não chama LLM, não executa os comandos encontrados nos dados e não altera serviços ou permissões. Escreve apenas os arquivos de saída solicitados. Os exemplos distribuídos são sintéticos.

## Executar a demonstração

Requisito: **Python 3.10 ou posterior**. A ferramenta, os testes e a demonstração usam somente a biblioteca padrão. Não é necessário instalar pacotes com pip.

Extraia o ZIP, abra um terminal na pasta `Endpoint_Investigator` e execute:

```bash
python3 demo.py
python3 -m endpoint_investigator analyze --dataset examples/correlation --out saida
```

No Windows, substitua `python3` por `py -3` ou `python`, conforme a instalação. A análise de datasets funciona no Windows; a coleta local requer Linux.

Abra `saida/relatorio.html` em um navegador. A execução também produz:

| Arquivo | Conteúdo |
| --- | --- |
| `evidencias.json` | Fontes, hashes, registros brutos, normalização, relações e achados |
| `relatorio.html` | Consulta por achado, serviço, relação e evidência, com links internos |
| `relatorio.md` | Resumo textual, limitações e hashes das fontes |

O JSON é o registro completo. O Markdown é um resumo; seus IDs devem ser consultados no JSON ou HTML.

## Coleta na VM Kali

```bash
python3 -m endpoint_investigator collect --out coleta/snapshot.json
python3 -m endpoint_investigator analyze --snapshot coleta/snapshot.json --out saida_kali
```

A coleta usa os mesmos comandos do handout da Aula 2: `ps -eo pid,ppid,user,stat,cmd` para processos, `systemctl list-units --type=service --state=running` e `systemctl status <serviço>` para serviços, as permissões do `ls -l` (dono, grupo e rwx) para os arquivos usados pelos serviços e `journalctl -n 200` para logs. A falta de acesso a uma fonte fica em `avisos`; não é convertida em ausência de atividade.

Para restringir a coleta:

```bash
python3 -m endpoint_investigator collect --pid 1234 --journal-lines 0 --out coleta/parcial.json
```

Substitua 1234 por um PID existente. O filtro restringe os processos; a consulta de serviços continua abrangendo os serviços `running`. O valor zero desativa a leitura do journal. Não é necessário iniciar como root para analisar datasets. Na coleta local, a visibilidade depende das permissões da conta utilizada.

A coleta real foi executada na VM Kali: 139 processos, 17 serviços ligados aos seus processos pelo Main PID, 81 registros de permissão e 50 linhas de log, sem erros.

## Arquitetura e fontes

O fluxo é: coleta ou importação, normalização, correlações explícitas, achados, relatórios.

| Módulo | Responsabilidade |
| --- | --- |
| `collect.py` | Executar `ps`, `systemctl`, `journalctl` e ler permissões como o `ls -l` |
| `input.py` | Validar CSV/texto/JSON e construir registros com proveniência |
| `engine.py` | Construir relações e aplicar as regras R01-R07 |
| `report.py` | Serializar JSON e gerar HTML/Markdown |
| `__main__.py` | Interface de linha de comando e erros de entrada |

O leitor de datasets espera `processes.csv`, `permissions.csv` e `services.txt`; `journal.log` é opcional. Os cabeçalhos seguem o gerador fornecido. Modos são lidos em base 8, PIDs são inteiros, caminhos precisam ser absolutos e identificadores duplicados são rejeitados.

`README.txt` e `metadata.json` **não são lidos pelo motor**. O nome do cenário também não participa das regras. Assim, os achados são derivados dos registros, sem consultar as respostas didáticas do gerador.

Na coleta local, o `ps` fornece PID, PPID, usuário, estado e comando de cada processo. O `systemctl status` informa o Main PID de cada serviço; a partir dele, o usuário e o comando do serviço são obtidos do processo correspondente no `ps`. As permissões são lidas para o executável/script de cada processo e para os diretórios do caminho. O `journalctl` é lido em texto, no mesmo formato do `journal.log` dos datasets.

## Contrato das evidências

| Campo | Significado |
| --- | --- |
| `id` | Identificador local: P para processo, A para metadados, S para serviço, L para log |
| `tipo` | `processo`, `permissao`, `servico` ou `log` |
| `origem` | Arquivo e linha; na coleta local, fonte e instante de observação |
| `bruto` | Registro que originou a normalização |
| `dados` | Campos normalizados, preservando os valores observados |

Os IDs são estáveis para a mesma ordem de entrada; não são identidades globais entre máquinas ou execuções. Os hashes SHA-256 identificam os bytes dos artefatos analisados, sem autenticar a origem ou estabelecer cadeia de custódia. No modo local, a análise calcula o hash do snapshot JSON.

Uma relação contém `de`, `para`, `tipo`, `metodo`, `confianca` e `limitacao`. A confiança é qualitativa e refere-se à associação, não à probabilidade de um ataque. Um achado contém referências às evidências e relações, `observado`, `interpretacao`, `hipotese`, `evidencias_ausentes`, `proximos_passos` e `exploracao_comprovada: false`.

## Correlações implementadas

| Correlação | Critério e alcance |
| --- | --- |
| Processo + pai + identidade | PPID do filho = PID do pai; diferença de usuários contextualizada |
| Serviço + processo | Main PID do `systemctl status` na coleta local; comando completo e usuário iguais como associação candidata no dataset |
| Processo/serviço + permissão | Caminho absoluto em posição de executável ou script simples e metadados do mesmo caminho |
| Serviço + arquivo + diretório | Código referenciado e seu diretório pai imediato |
| Serviço + log | Unidade explícita ou tag igual ao nome completo do serviço |
| Processo + log | PID numérico comum, com confiança baixa por possível reutilização |
| Serviço + descendente + URL | Percurso por PPID; URL em argumento não é observação de socket |

Não se associa um serviço por substring do nome do comando. `cat /tmp/dados` não transforma `/tmp/dados` em código executado. Formas indiretas, como `bash -c`, `env`, Python `-m` e scripts relativos, não são resolvidas.

## Regras e prioridades

| Regra | Condição observada | Resultado |
| --- | --- | --- |
| R01 | Serviço root ou processo associado root; código gravável por outros ou pertencente a não root | Risco, prioridade alta |
| R02 | Código privilegiado em diretório pai com escrita (w) para outros | Risco de substituição, alta |
| R03 | Arquivo gravável por outros sem correlação privilegiada estabelecida | Risco de configuração, média |
| R04 | Arquivo root com SUID ou SGID e algum bit de execução | Informação para revisão |
| R05 | Código privilegiado gravável pelo grupo, sem prova dos integrantes | Inconclusivo, média |
| R06 | Processo root associado/descendente de serviço com URL HTTP(S) em argv | Contexto informativo |
| R07 | Filho root de pai observado como não root | Transição a investigar, média |

A prioridade ordena verificações; não é uma nota de gravidade nem veredito de comprometimento. R01 pode indicar configuração privilegiada mesmo sem processo correspondente, mas explicita que a execução root não foi confirmada. R02 considera apenas o diretório pai imediato: quem pode escrever no diretório pode apagar e recriar o script, mesmo que o arquivo em si esteja protegido.

## Demonstração e resultados registrados

`python3 demo.py` gera seis datasets com seed 42 e executa o motor. O arquivo `evidencias/demonstracao.json` guarda as contagens; cada subpasta contém a evidência completa e os relatórios.

| Cenário | Alta | Média | Informativa | Leitura do resultado |
| --- | --- | --- | --- | --- |
| normal | 0 | 0 | 0 | Nenhuma regra acionada |
| permission | 0 | 1 | 0 | Arquivo 0777 sem vínculo privilegiado estabelecido |
| privileged_service | 0 | 0 | 1 | Script 0700; URL do processo filho contextualizada |
| correlation | 1 | 0 | 2 | Script 0777 + serviço root; SUID e URL informativos |
| ambiguous | 0 | 0 | 1 | URL no contexto de monitoramento; sem diagnóstico de atividade maliciosa |
| random, seed 42 | 0 | 0 | 0 | Código do serviço gerado com modo 0750 |

No cenário principal: `S0003` identifica `backup-agent.service`; `P0004`, o PID 2417 executado como root; `A0002`, `/opt/backup/backup.sh` com modo 0777. `F0001` referencia os três registros. A hipótese é modificação de código privilegiado, condicionada a alguém realmente conseguir alterar o script e o serviço executá-lo depois. Não há prova de alteração ou de exploração.

## Verificação reproduzível

```bash
python3 -m unittest discover -s tests -v
python3 tools/validate.py
```

Foram executados **32 testes, sem falhas ou erros**, em Python 3.13 na VM Kali. O registro está em `evidencias/testes.txt` e `evidencias/validacao.json`. Um dos testes percorre 90 combinações de nível/seed. Outros verificam os cinco cenários fixos do gerador original, controles negativos, mudança 0777 para 0700, diretório gravável, escrita por grupo, SUID/SGID, PPID, coleta com `ps`/`systemctl`/`journalctl`, integridade referencial, HTML escapado e fontes ausentes.

Esses testes verificam os comportamentos definidos, sem estimar sensibilidade ou especificidade em endpoints reais. Alterações em regras devem ser acompanhadas pela reexecução da validação. O comando `tools/validate.py` também refaz uma coleta limitada na máquina local.

## Gerador fornecido

`tools/generate_dataset_original.py` preserva o arquivo recebido, byte a byte. `generate_dataset.py` é a cópia adaptada para o projeto: corrige as tuplas do cenário aleatório, o fuso no ISO e o rótulo do cenário permission. Acrescenta seleção explícita de cenário. Veja `docs/correcoes_gerador.md`.

```bash
python3 generate_dataset.py --scenario correlation --seed 42 --output meu_dataset
python3 -m endpoint_investigator analyze --dataset meu_dataset --out minha_analise
```

`--scenario` tem precedência sobre `--level`. Datasets já existentes do gerador original também podem ser analisados; não precisam ser regenerados. `generated_at` varia entre execuções. Os quatro artefatos observacionais dos cenários fixos permanecem reproduzíveis.

## Limitações

- A coleta é uma foto do momento: processos podem terminar ou ter o PID reaproveitado. Logs ligados por PID não provam que se trata do mesmo processo.
- Só são analisadas as permissões rwx de dono, grupo e outros, e apenas do arquivo e do diretório pai imediato. Os integrantes dos grupos não são verificados.
- Não é feita varredura completa do disco: só os arquivos usados pelos processos e serviços observados. O conteúdo dos scripts não é analisado.
- A linha de comando e os logs podem ser manipulados. O comando mostrado pelo `ps` não comprova o arquivo efetivamente executado.
- URL em comando não prova conexão, envio de dados ou malware; a ferramenta não coleta conexões de rede. SUID/SGID isolado não prova falha.
- Logs do dataset não contêm ano/fuso. O programa preserva essa incerteza e não usa a ordem temporal como prova de causalidade. `mtime` é a data da última modificação, não da criação.
- No cenário privileged_service, o log registra desativação e a tabela declara running, sem instante comum suficiente para resolver a diferença. As fontes são preservadas, sem reconstruir um estado histórico único.
- A quantidade de achados não mede a segurança da máquina. Configurações legítimas podem exigir revisão e condições não modeladas podem passar despercebidas.
- A coleta local pode registrar argumentos e logs sensíveis; o conjunto distribuído contém apenas dados sintéticos e resumos de validação.

## Entregáveis e apresentação

- Código completo na pasta `endpoint_investigator`, com gerador, testes e comandos de reprodução.
- `docs/Documento_Tecnico.pdf`: documento técnico de quatro páginas; fonte editável em Markdown.
- `docs/demonstracao.md`: sequência de apresentação e perguntas para domínio do código.
- `evidencias`: saídas efetivamente produzidas pelo motor e registros de validação.
- `SHA256SUMS.txt`: integridade dos arquivos distribuídos, exceto o próprio manifesto.

O uso de IA na elaboração do código, documentação e testes está declarado no documento técnico.

O PDF já está pronto. Para regenerá-lo após editar o Markdown, instale `reportlab` separadamente e execute `python3 tools/build_document.py`. Essa dependência é apenas da geração do documento, não da ferramenta.

## Referências técnicas

- Enunciado fornecido: *AI - Tecnologias Hackers 26-2.pdf*, páginas 1-6.
- Gerador original fornecido: `generate_dataset.py`.
- Handout da Aula 2, *Investigando o sistema operacional*: `ps`, PID/PPID, permissões rwx, `chmod 777`, SUID/SGID, `systemctl` e `journalctl`.
- OccupyTheWeb, *Linux Basics for Hackers*, cap. 5 e 6: permissões e processos.

Referências consultadas em 29/09/2026.
