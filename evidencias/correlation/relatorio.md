# Endpoint Investigator

Análise: 2026-09-29T18:57:47+00:00

As regras não determinam ocorrência de exploração; os achados indicam verificações a realizar.

## Resumo

21 evidências; 22 relações; 3 achados.

## F0001 · R01 · Código modificável associado a backup-agent.service

Categoria: risco. Prioridade: alta.

Evidências: S0003, P0004, A0002

**Observado**

- backup-agent.service: usuário declarado root; ExecStart=/bin/bash /opt/backup/backup.sh.
- Processo associado observado com identidade root.
- /opt/backup/backup.sh: proprietário root, modo 0777; bit de escrita para outros.

**Interpretação**

O privilégio de execução está relacionado a um recurso de código cuja modificação merece verificação.

**Hipótese**

Se um usuário não privilegiado conseguir alterar esse recurso e o serviço o utilizar depois, poderá influenciar código executado como root.

**Evidências ausentes**

- Quem de fato consegue alterar o arquivo: integrantes do grupo e permissões de todos os diretórios do caminho.
- Conteúdo do script e se ele foi alterado (comparar o hash SHA-256 com uma versão conhecida).
- Logs que mostrem uma alteração não autorizada seguida de execução pelo serviço.

**Próximos passos**

- Verificar as permissões de todos os diretórios do caminho (ls -ld).
- Comparar o hash do script com uma versão aprovada e revisar o serviço (systemctl status).

Exploração comprovada: não.

## F0002 · R04 · Arquivo root com bit SUID: /usr/local/bin/report-sync

Categoria: informativo. Prioridade: informativa.

Evidências: A0004

**Observado**

- /usr/local/bin/report-sync: tipo file, proprietário root, grupo root, modo 4755.

**Interpretação**

O bit SUID faz o programa executar com o usuário/grupo do dono, e não de quem o chamou.

**Hipótese**

Pode ser um utilitário legítimo (ex.: passwd, sudo) ou uma instalação que precise de revisão.

**Evidências ausentes**

- Finalidade do programa e se ele faz parte do sistema (comparar o hash SHA-256 com o do pacote original).
- Logs de uso do programa por usuários comuns.

**Próximos passos**

- Verificar o arquivo sem executá-lo e comparar com a lista de SUID/SGID esperados (find / -perm -4000).

Exploração comprovada: não.

## F0003 · R06 · URL em comando root no contexto de backup-agent.service

Categoria: informativo. Prioridade: informativa.

Evidências: S0003, P0004, P0005

**Observado**

- PID 2421, PPID 2417, usuário root; URL(s): https://updates.example.invalid/status.

**Interpretação**

O comando contém um destino HTTP(S). A ancestralidade relaciona o processo ao serviço.

**Hipótese**

Pode ser atualização, backup ou monitoramento. A linha de comando não prova conexão estabelecida nem envio de dados.

**Evidências ausentes**

- Conexões abertas pelo processo (sockets em /proc/<PID>/fd), resolução DNS do destino e tráfego capturado.

**Próximos passos**

- Comparar o destino com a configuração do serviço e capturar o tráfego com tcpdump se necessário.

Exploração comprovada: não.

## Avisos e limitações

- Datasets: USER é apenas o nome do usuário informado; UID/GID e grupos não foram fornecidos.
- journal.log não informa ano/fuso: não é combinado com timestamps ISO como uma cronologia absoluta.
- A coleta é uma foto do momento: processos podem terminar ou ter o PID reaproveitado durante a coleta.
- A análise usa as permissões rwx de dono, grupo e outros; outros controles de acesso do sistema não são considerados.
- A linha de comando mostrada pelo ps não prova qual arquivo foi executado nem o conteúdo de um script.
- Só são reconhecidos executáveis com caminho absoluto e scripts chamados diretamente (ex.: bash /opt/x.sh); bash -c e caminhos relativos não são resolvidos.
- mtime é a data da última modificação, não da criação, e não prova alteração maliciosa. O hash identifica os arquivos analisados, não quem os produziu.
- Nenhuma regra demonstra exploração. Ausência de achados não demonstra segurança.

## Fontes e integridade

SHA-256 permite conferir os artefatos analisados; não autentica sua origem.

- processes.csv: 4f1e0aec1093ce10e37c3462190d63b2e68d62cdce267d4a253dfe3fcd73cd15 (496 bytes)
- permissions.csv: 7e31f7c9b39cfa92a0d507dcde61820bdbb3515c969f77497f3b9427ed5cfd76 (313 bytes)
- services.txt: 993ecfa8b562932583905d1721ec10cc976e03b9af7f8094071cfd07a4ce9285 (267 bytes)
- journal.log: 36659e3b60701cbf9e05b4a85f662856e1ab5ffcc8d66d9557135eb09f3d6388 (588 bytes)
