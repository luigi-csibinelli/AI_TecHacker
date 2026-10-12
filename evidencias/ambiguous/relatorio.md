# Endpoint Investigator

Análise: 2026-09-29T18:57:47+00:00

As regras não determinam ocorrência de exploração; os achados indicam verificações a realizar.

## Resumo

20 evidências; 23 relações; 1 achados.

## F0001 · R06 · URL em comando root no contexto de monitor-agent.service

Categoria: informativo. Prioridade: informativa.

Evidências: S0003, P0004, P0005

**Observado**

- PID 1510, PPID 1500, usuário root; URL(s): https://metrics.example.invalid/v1/push.

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

- processes.csv: aa12611c78a57b9292f6388bca9712500e5faac0eea3fd0a71833fc945573bda (586 bytes)
- permissions.csv: 15b467eb93436477d4452f1092e6b64eb56ee3c04d83657916549f05079ca5f6 (238 bytes)
- services.txt: 8af3a398c409aca72c910909bd96923f8cb75efad598905ab1647eee77d3b59a (274 bytes)
- journal.log: 5871e270ef6683947b8be5ed37ad9e1c574cea8c262868559a5092137dc46081 (487 bytes)
