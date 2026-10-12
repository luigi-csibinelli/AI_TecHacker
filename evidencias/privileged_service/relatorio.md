# Endpoint Investigator

Análise: 2026-09-29T18:57:47+00:00

As regras não determinam ocorrência de exploração; os achados indicam verificações a realizar.

## Resumo

17 evidências; 21 relações; 1 achados.

## F0001 · R06 · URL em comando root no contexto de backup-agent.service

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

- processes.csv: 88c13c507a8fc66969a9214ef41b1a430b6184c50f0562a63f77283c21938384 (378 bytes)
- permissions.csv: 65f5c9675ee1fc20f1e0267abdc6f129b15edd4bf2fd8c02be28f1bd703d025b (239 bytes)
- services.txt: 993ecfa8b562932583905d1721ec10cc976e03b9af7f8094071cfd07a4ce9285 (267 bytes)
- journal.log: 3ee48c169e717e565f7839a25c69b23f05ba7f76edb167720b7ae29785e1243f (497 bytes)
