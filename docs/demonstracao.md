# Demonstração em aula

## Preparação

Extraia o ZIP e abra o terminal dentro de `Endpoint_Investigator`. Confira `python3 --version`. No Windows, use `py -3` se esse for o comando disponível.

```bash
python3 demo.py
python3 -m unittest discover -s tests -v
```

Os resultados esperados estão no README; o registro efetivamente produzido está em `evidencias/demonstracao.json`. A execução não depende de internet ou LLM.

## Sequência de apresentação: aproximadamente 6 minutos

1. **Objetivo, 30 s.** Explicar que a ferramenta investiga relações entre processo, identidade, recurso e serviço. Ela registra o observado e formula hipóteses condicionais.
2. **Caso correlacionado, 2 min.** Executar o comando abaixo e abrir o HTML. No achado F0001, seguir os links S0003, P0004 e A0002. Mostrar os registros originais e suas linhas. Distinguir modo 0777, interpretação de escrita e hipótese de influenciar código root.
3. **Controles, 1 min.** Comparar os relatórios `permission`, `privileged_service` e `ambiguous`. Um arquivo gravável sem consumidor privilegiado não sustenta a mesma inferência. Um serviço root com script 0700 não aciona R01. URL não comprova atividade maliciosa.
4. **Teste contrafactual, 1 min.** Mostrar `test_permission_change_removes_correlated_risk`: mudar somente o modo para 0700 remove R01. Mostrar também o teste do diretório: um script protegido pode ser apagado e recriado se o diretório pai for gravável por outros.
5. **Arquitetura, 1 min.** Mostrar `input.py`, `engine.py` e um objeto em `evidencias.json`. Explicar como as referências permitem auditar cada relação. Destacar que os rótulos do gerador não entram na análise.
6. **Limites, 30 s.** Citar integrantes de grupos não verificados, reutilização de PIDs, falta de conexões de rede e logs sem ano/fuso. Mostrar que exploração não foi comprovada.

```bash
python3 -m endpoint_investigator analyze --dataset examples/correlation --out apresentacao
```

Abra `apresentacao/relatorio.html`. O HTML funciona como arquivo local e não depende de recursos externos.

## Explicação do achado central

| Elemento | Resposta sustentada pelos dados |
| --- | --- |
| Observação | Serviço backup-agent configurado como root; processo candidato PID 2417 root; script com modo 0777 |
| Relação | Mesmo argv e usuário associam serviço/processo; mesmo caminho associa o script |
| Interpretação | Há uma relação entre privilégio e código com escrita para outros |
| Hipótese | Se alguém alterar o script e o serviço executá-lo depois, essa pessoa influencia código executado como root |
| Ainda falta | Integrantes dos grupos, permissões dos diretórios do caminho, conteúdo/hash do script e prova de alteração/execução não autorizada |
| Conclusão | Risco de configuração a investigar; não há demonstração de exploração |

## Perguntas para preparar o grupo

- **Por que PPID não basta para afirmar ataque?** Ele relaciona processos no snapshot; não comprova intenção, identidade histórica ou autorização.
- **Por que 0777 e root não provam exploração?** Indicam uma condição de risco. Ainda são necessárias evidências de que alguém alterou o script e de que o serviço executou a versão alterada.
- **Qual é a diferença entre arquivo e diretório gravável?** No arquivo, o modo pode conceder escrita do conteúdo. No diretório, a escrita permite apagar e recriar arquivos dentro dele, mesmo que o arquivo esteja protegido.
- **O que muda entre dataset e coleta Linux?** O dataset fornece usuário e comandos prontos. Na coleta real, o `ps` fornece os processos e o `systemctl status` informa o Main PID de cada serviço, que liga o serviço ao processo com mais confiança.
- **Qual o limite de associar comandos iguais?** Instâncias diferentes podem ter argv e usuário iguais. A associação é candidata e fica explicitada no JSON.
- **Como evita respostas baseadas no gerador?** O leitor não consulta README.txt ou metadata.json; há um teste que modifica esses arquivos sem modificar os resultados.
- **Por que não concluir malware ao ver curl?** Nome, URL e privilégio podem fazer parte de backup, atualização ou monitoramento. A ferramenta não coleta conexões de rede; o próximo passo seria olhar `/proc/<PID>/fd` e capturar tráfego com `tcpdump`.
- **O hash prova autenticidade?** Não. Ele identifica os bytes analisados e permite detectar mudanças posteriores no artefato.
- **Qual foi o uso de IA?** Apoio à implementação, documentação e testes. A análise em execução é determinística e local.

## Coleta local opcional na Kali

```bash
python3 -m endpoint_investigator collect --out coleta/snapshot.json
python3 -m endpoint_investigator analyze --snapshot coleta/snapshot.json --out kali
```

Confira `avisos` e `contextos_de_servicos`. Na Kali, um exemplo real é o achado R07 do `fusermount3`: processo root com pai não root, explicado por ser um programa SUID legítimo. É um bom caso para mostrar o resultado "inconclusivo".
