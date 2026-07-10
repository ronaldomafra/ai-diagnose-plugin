# Diagnose Plugin

Diagnose é um plugin para Codex voltado a investigações técnicas guiadas e
aprovadas localmente. O agente organiza hipóteses e evidências; qualquer ação
que futuramente tocar um target deverá ser validada pela política, mostrada em
um terminal local e aprovada uma única vez.

Esta primeira entrega implementa o M0: base segura de domínio, persistência,
auditoria, IPC local, MCP por STDIO, CLI e Skill. Consulte o
[guia de desenvolvimento](doc/diagnose-plugin-development-guide.md) para a
arquitetura e os próximos milestones.

## Escopo atual

O M0 disponibiliza estas tools MCP:

- `server_info`, `capabilities_list`, `target_list` e `target_describe`;
- `diagnosis_session_create`, `diagnosis_session_status` e
  `diagnosis_session_close`;
- `action_status`, `action_result`, `action_cancel` e `action_history`.

Ainda não há executores reais para SSH, shell, rede, HTTP/TLS, bancos, arquivos,
Nginx ou containers. O único executor é um fake usado pelos testes do fluxo de
aprovação. Quando o Terminal Server não estiver ativo, o MCP continua online e
retorna um erro estruturado; a Skill deve seguir em modo manual.

## Garantias de segurança

- O MCP nunca executa diretamente em um target.
- Planos de execução são imutáveis e têm hash SHA-256.
- A aprovação local faz a transição para execução de forma atômica; expiração,
  mudança de target/política, sessão fechada ou plano adulterado invalidam a
  ação.
- Resultados, transição terminal e entrada de auditoria são persistidos na
  mesma transação SQLite.
- A auditoria é append-only e encadeada por hash.
- Saídas, metadados e planos passam por remoção de escapes de terminal,
  redaction de segredos e limites de tamanho/linhas.
- No Windows, o IPC usa TCP loopback com token por inicialização e ACL privada;
  no Unix, usa socket com permissões restritas.

## Pré-requisitos

- Python 3.12 ou superior;
- [uv](https://docs.astral.sh/uv/);
- Codex CLI para instalar o plugin;
- um terminal visível para executar `diagnose-terminal start`.

## Desenvolvimento local

No diretório deste repositório:

```powershell
uv sync --all-groups
uv run diagnose-terminal doctor
uv run pytest
uv build
```

Em Linux/macOS, os mesmos comandos funcionam substituindo PowerShell pelo seu
shell habitual.

Os comandos de qualidade usados pelo CI são:

```powershell
uv run ruff check src tests
uv run mypy src tests
uv run pytest
uv build
```

## Instalação do pacote

Crie o wheel e instale os dois console scripts:

```powershell
uv build
uv tool install --python 3.12 --force .\dist\diagnose_plugin-0.1.0-py3-none-any.whl
uv tool update-shell
```

Feche e reabra o terminal após `uv tool update-shell`. Em seguida, confirme a
instalação:

```powershell
diagnose-terminal doctor
diagnose-terminal --help
```

Os comandos instalados são:

```text
diagnose-mcp
diagnose-terminal
```

### Instalação assistida no Linux

No Linux, o caminho mais simples é executar o instalador deste repositório:

~~~bash
chmod +x scripts/install-linux.sh
./scripts/install-linux.sh --update-path
~~~

Se o uv ainda não estiver instalado, acrescente --install-uv:

~~~bash
./scripts/install-linux.sh --install-uv --update-path
~~~

O script cria o wheel, instala os comandos, cria arquivos de configuração
seguros apenas quando eles ainda não existem, prepara
~/plugins/diagnose-plugin, registra o marketplace pessoal e executa
codex plugin add diagnose-plugin@personal. Ele nunca sobrescreve
settings.yaml, targets.yaml ou policies.yaml.

Opções úteis:

- --dry-run: mostra as ações sem modificar o sistema;
- --config-dir DIR: configura outro diretório em vez de
  ~/.config/diagnose;
- --skip-plugin: instala apenas o pacote e a configuração, sem exigir Codex;
- --start: inicia o Terminal Server visível ao final;
- --help: mostra todas as opções.

O --update-path é opcional, mas recomendado: ele pede ao uv para configurar o
PATH em novos terminais. O instalador requer Python 3.12+, Codex CLI e os
auxiliares de plugin distribuídos com o Codex. Para conferir pré-requisitos sem
fazer alterações, execute:

~~~bash
./scripts/install-linux.sh --dry-run
~~~

## Instalação do plugin no Codex

O bundle do plugin está em `plugins/diagnose-plugin`. O fluxo pessoal padrão
usa:

```text
~/plugins/diagnose-plugin
~/.agents/plugins/marketplace.json
```

Depois que o bundle estiver registrado no marketplace pessoal, instale ou
reinstale com:

```powershell
codex plugin add diagnose-plugin@personal
```

No Linux, prefira o instalador assistido da seção anterior. Os passos abaixo
são a alternativa manual, útil principalmente no Windows ou para depuração do
staging.

Para preparar esse staging em uma nova máquina com Codex instalado, use o
scaffold de plugin e copie o bundle deste repositório para o destino criado:

```powershell
$pluginRoot = "$HOME\plugins"
python "$HOME\.codex\skills\.system\plugin-creator\scripts\create_basic_plugin.py" `
  diagnose-plugin --path $pluginRoot --with-skills --with-scripts --with-mcp `
  --with-marketplace --force

Get-ChildItem .\plugins\diagnose-plugin -Force | `
  Copy-Item -Destination "$pluginRoot\diagnose-plugin" -Recurse -Force
codex plugin add diagnose-plugin@personal
```

No Linux/macOS, o script equivalente fica em
`$HOME/.codex/skills/.system/plugin-creator/scripts/create_basic_plugin.py`.

O arquivo `.mcp.json` usa o mapa MCP direto aceito pelo Codex CLI atual. Uma
versão legada do validador local espera um wrapper `mcpServers` e pode acusar
falso negativo; valide a instalação com `codex plugin add`.

## Operação

Inicie o Terminal Server em uma janela de terminal visível:

```powershell
diagnose-terminal start
```

O terminal apresenta comandos de aprovação locais:

```text
list
show <request-id>
approve <request-id>
reject <request-id> [motivo]
help
quit
```

Em outra janela, os comandos úteis são:

```powershell
diagnose-terminal status
diagnose-terminal doctor
diagnose-terminal targets list
diagnose-terminal actions list
diagnose-terminal sessions list
diagnose-terminal audit verify
```

Abra um novo thread no Codex após instalar ou atualizar o plugin. Use
`$diagnose` explicitamente: a invocação implícita está desativada nesta fase.

## Configuração

Por padrão, a configuração é resolvida por `platformdirs`:

- Windows: `%LOCALAPPDATA%\diagnose`;
- Linux: `~/.config/diagnose`.

Use `DIAGNOSE_CONFIG_DIR` ou `--config-dir` para substituir esse diretório. Os
arquivos aceitos são `settings.yaml`, `targets.yaml` e `policies.yaml`.

Exemplo mínimo de metadados de target e política default-deny:

```yaml
# settings.yaml
approvalTimeoutSeconds: 300
maxOutputBytes: 8388608
maxOutputLines: 100000
```

```yaml
# targets.yaml
targets:
  - id: local-metadata
    displayName: Local metadata only
    type: fake
    tags: [development]
    connectionRef: fake:local-metadata
    policyRef: default-deny
```

```yaml
# policies.yaml
policies:
  default-deny:
    targets: [local-metadata]
    defaultDecision: DENY
    tools: {}
```

Nunca coloque senha, token, chave privada, URL com credenciais ou connection
string em `connectionRef`, targets, policies, logs ou argumentos de tool.
`connectionRef` deve apontar somente para um provedor lógico, por exemplo
`ssh:production-api` ou `database:production-db`.

## Atualização durante o desenvolvimento

Depois de alterar o bundle, copie-o novamente para `~/plugins/diagnose-plugin`,
atualize o cachebuster e reinstale no marketplace pessoal:

```powershell
python "$HOME\.codex\skills\.system\plugin-creator\scripts\update_plugin_cachebuster.py" `
  "$HOME\plugins\diagnose-plugin"
codex plugin add diagnose-plugin@personal
```

Abra um novo thread no Codex depois da reinstalação para que Skill e tools sejam
recarregadas.

## Estrutura

```text
src/diagnose/              pacote Python
plugins/diagnose-plugin/   bundle Codex (manifesto, Skill e MCP)
tests/                     testes unitários, integração e E2E
doc/                       especificação de desenvolvimento
```

## Licença

Nenhuma licença foi definida ainda.
