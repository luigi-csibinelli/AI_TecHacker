# Endpoint Investigator

Análise: 2026-09-29T18:57:47+00:00

As regras não determinam ocorrência de exploração; os achados indicam verificações a realizar.

## Resumo

26 evidências; 22 relações; 0 achados.

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

- processes.csv: 12ee54e4e3ae94867d6c2778d801c7cf21206aeadc56a1a6bc60135bc147a5bd (624 bytes)
- permissions.csv: ad7e7502d1cba4b713ea3d8a22272c8de0b4e5e4e0f47e5dc6afda1b60a7a738 (507 bytes)
- services.txt: b604fb93dd87743f37da79da2a6078e462f2d3b3e143e560a979663147370909 (343 bytes)
- journal.log: 49a147bef6e531b7931031c4552d3daede075f79f92e55fa03843b3da96e9c49 (525 bytes)
