# Endpoint Investigator

Análise: 2026-09-29T18:57:47+00:00

As regras não determinam ocorrência de exploração; os achados indicam verificações a realizar.

## Resumo

21 evidências; 16 relações; 0 achados.

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

- processes.csv: 421b37b2d8f72fddc2df037febd8f646a89a1ae0dbd72e9f9a6a89e9ef4359ba (547 bytes)
- permissions.csv: 2a63571b4f51e9124f8133d42510778d98f740d6f1dd08aada9d4966afaaddf6 (365 bytes)
- services.txt: 9bfbfef4332589a8874b1ba53bacedfb304c7a6f461219b17370efb51e02a132 (261 bytes)
- journal.log: a814cb31f7be232f1aa7d5acd09eec361acb45eec9c672ba5054dbcb3134fba8 (433 bytes)
