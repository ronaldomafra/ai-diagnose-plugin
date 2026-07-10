#!/usr/bin/env bash
#
# Instala o Diagnose Plugin em Linux e prepara uma configuração inicial segura.
# Este script não sobrescreve arquivos de configuração existentes.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

PROGRAM_NAME="install-linux.sh"
if [[ -z "${HOME:-}" ]]; then
    printf '[diagnose] erro: A variável HOME precisa estar definida.\n' >&2
    exit 1
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
SOURCE_DIR="$REPOSITORY_DIR"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/diagnose"
PLUGIN_NAME="diagnose-plugin"
PLUGIN_STAGE_DIR="$HOME/plugins/$PLUGIN_NAME"
MARKETPLACE_FILE="$HOME/.agents/plugins/marketplace.json"
CODEX_ROOT="${CODEX_HOME:-$HOME/.codex}"
TOOL_BIN_DIR="${UV_TOOL_BIN_DIR:-$HOME/.local/bin}"

DRY_RUN=0
INSTALL_UV=0
UPDATE_PATH=0
SKIP_PLUGIN=0
START_SERVER=0
PYTHON_BIN="${PYTHON_BIN:-}"
UV_BIN=""
CODEX_BIN=""
MARKETPLACE_STATE=""

usage() {
    printf '%s\n' \
        "Uso: $PROGRAM_NAME [opções]" \
        "" \
        "Instala o pacote Python, cria uma configuração default-deny e instala" \
        "o bundle no marketplace pessoal do Codex." \
        "" \
        "Opções:" \
        "  --install-uv       Instala o uv pelo instalador oficial se ele não existir." \
        "  --update-path      Executa 'uv tool update-shell' para persistir o PATH." \
        "  --config-dir DIR   Usa DIR para settings.yaml, targets.yaml e policies.yaml." \
        "  --source DIR       Usa outro checkout do repositório como fonte do bundle." \
        "  --skip-plugin      Instala somente o pacote e a configuração; não chama o Codex." \
        "  --start            Inicia o Terminal Server no primeiro plano ao concluir." \
        "  --dry-run          Mostra as ações sem modificar o sistema." \
        "  -h, --help         Mostra esta ajuda." \
        "" \
        "Exemplos:" \
        "  ./scripts/install-linux.sh --update-path" \
        "  ./scripts/install-linux.sh --install-uv --update-path" \
        "  ./scripts/install-linux.sh --config-dir \"\$HOME/.config/diagnose\""
}

info() {
    printf '[diagnose] %s\n' "$*"
}

die() {
    printf '[diagnose] erro: %s\n' "$*" >&2
    exit 1
}

show_command() {
    local argument
    printf '+'
    for argument in "$@"; do
        printf ' %q' "$argument"
    done
    printf '\n'
}

run() {
    if (( DRY_RUN )); then
        show_command "$@"
        return 0
    fi
    "$@"
}

path_exists() {
    [[ -e "$1" || -L "$1" ]]
}

resolve_directory() {
    local directory="$1"
    [[ -d "$directory" ]] || die "Diretório não encontrado: $directory"
    CDPATH= cd -- "$directory" && pwd -P
}

find_command() {
    local command_name="$1"
    local path=""

    if command -v "$command_name" >/dev/null 2>&1; then
        command -v "$command_name"
        return 0
    fi

    path="$HOME/.local/bin/$command_name"
    if [[ -x "$path" ]]; then
        printf '%s\n' "$path"
        return 0
    fi

    return 1
}

select_python() {
    local candidate=""

    if [[ -n "${PYTHON_BIN:-}" ]]; then
        candidate="$PYTHON_BIN"
        if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' >/dev/null 2>&1; then
            PYTHON_BIN="$candidate"
            return 0
        fi
        die "PYTHON_BIN deve apontar para Python 3.12 ou superior."
    fi

    for candidate in python3.12 python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 && \
            "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' >/dev/null 2>&1; then
            PYTHON_BIN="$(command -v "$candidate")"
            return 0
        fi
    done

    die "Python 3.12 ou superior não foi encontrado. Instale-o e execute o script novamente."
}

find_uv() {
    local candidate=""

    if command -v uv >/dev/null 2>&1; then
        UV_BIN="$(command -v uv)"
        return 0
    fi

    for candidate in "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv"; do
        if [[ -x "$candidate" ]]; then
            UV_BIN="$candidate"
            return 0
        fi
    done

    return 1
}

install_uv() {
    local installer=""

    if (( DRY_RUN )); then
        info "O uv seria instalado pelo instalador oficial em https://astral.sh/uv/."
        UV_BIN="uv"
        return 0
    fi

    if command -v curl >/dev/null 2>&1; then
        installer="$(mktemp "${TMPDIR:-/tmp}/diagnose-uv-install.XXXXXX")"
        if ! curl --fail --location --proto '=https' --tlsv1.2 --silent --show-error \
            https://astral.sh/uv/install.sh --output "$installer"; then
            rm -f -- "$installer"
            die "Não foi possível baixar o instalador oficial do uv."
        fi
    elif command -v wget >/dev/null 2>&1; then
        installer="$(mktemp "${TMPDIR:-/tmp}/diagnose-uv-install.XXXXXX")"
        if ! wget --quiet --output-document="$installer" https://astral.sh/uv/install.sh; then
            rm -f -- "$installer"
            die "Não foi possível baixar o instalador oficial do uv."
        fi
    else
        die "uv não foi encontrado e curl/wget não estão disponíveis. Instale o uv manualmente ou instale curl e use --install-uv."
    fi

    info "Instalando uv pelo instalador oficial."
    if ! sh "$installer"; then
        rm -f -- "$installer"
        die "O instalador do uv terminou com erro."
    fi
    rm -f -- "$installer"
}

ensure_uv() {
    if find_uv; then
        return 0
    fi

    if (( ! INSTALL_UV )); then
        die "uv não foi encontrado. Instale-o antes ou execute novamente com --install-uv."
    fi

    install_uv
    find_uv || die "O uv foi instalado, mas não foi localizado. Abra outro terminal e execute o script novamente."
}

find_wheel() {
    local candidate=""
    local newest=""

    for candidate in "$SOURCE_DIR"/dist/diagnose_plugin-*.whl; do
        [[ -f "$candidate" ]] || continue
        if [[ -z "$newest" || "$candidate" -nt "$newest" ]]; then
            newest="$candidate"
        fi
    done

    [[ -n "$newest" ]] || return 1
    printf '%s\n' "$newest"
}

install_package() {
    local wheel=""

    info "Gerando e instalando o pacote Python."
    if (( DRY_RUN )); then
        run "$UV_BIN" build
        run "$UV_BIN" tool install --python "$PYTHON_BIN" --force "<wheel-gerado-em-$SOURCE_DIR/dist>"
        return 0
    fi

    run "$UV_BIN" build
    wheel="$(find_wheel)" || die "Nenhum wheel diagnose_plugin-*.whl foi gerado em $SOURCE_DIR/dist."
    run "$UV_BIN" tool install --python "$PYTHON_BIN" --force "$wheel"
}

write_default_file() {
    local path="$1"
    local content="$2"

    if path_exists "$path"; then
        info "Preservando configuração existente: $path"
        return 0
    fi

    if (( DRY_RUN )); then
        info "Criaria configuração inicial: $path"
        return 0
    fi

    printf '%s\n' "$content" > "$path"
    chmod 600 "$path"
    info "Criada configuração inicial: $path"
}

prepare_configuration() {
    if path_exists "$CONFIG_DIR" && [[ ! -d "$CONFIG_DIR" ]]; then
        die "O caminho de configuração existe, mas não é um diretório: $CONFIG_DIR"
    fi

    if (( DRY_RUN )); then
        info "Criaria, se necessário, o diretório de configuração seguro: $CONFIG_DIR"
        write_default_file "$CONFIG_DIR/settings.yaml" ""
        write_default_file "$CONFIG_DIR/targets.yaml" ""
        write_default_file "$CONFIG_DIR/policies.yaml" ""
        return 0
    fi

    if [[ ! -d "$CONFIG_DIR" ]]; then
        mkdir -p -- "$CONFIG_DIR"
        chmod 700 "$CONFIG_DIR"
        info "Criado diretório de configuração: $CONFIG_DIR"
    fi

    write_default_file "$CONFIG_DIR/settings.yaml" $'# Parâmetros locais; não inclua segredos neste arquivo.\napprovalTimeoutSeconds: 300\nmaxOutputBytes: 8388608\nmaxOutputLines: 100000'
    write_default_file "$CONFIG_DIR/targets.yaml" $'# Nenhum alvo é habilitado automaticamente.\ntargets: []'
    write_default_file "$CONFIG_DIR/policies.yaml" $'# Sem políticas de permissão: o comportamento global permanece default-deny.\npolicies: {}'
}

marketplace_state() {
    "$PYTHON_BIN" - "$MARKETPLACE_FILE" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    print("missing-file")
    raise SystemExit(0)

try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    print(f"Não foi possível ler {path}: {exc}", file=sys.stderr)
    raise SystemExit(2)

if not isinstance(payload, dict):
    print(f"{path} deve conter um objeto JSON.", file=sys.stderr)
    raise SystemExit(2)
if payload.get("name") != "personal":
    print(
        f"{path} não é o marketplace pessoal esperado (name deve ser 'personal').",
        file=sys.stderr,
    )
    raise SystemExit(2)

plugins = payload.get("plugins", [])
if not isinstance(plugins, list):
    print(f"{path} tem um campo plugins inválido.", file=sys.stderr)
    raise SystemExit(2)

for entry in plugins:
    if not isinstance(entry, dict) or entry.get("name") != "diagnose-plugin":
        continue
    source = entry.get("source")
    if source == {"source": "local", "path": "./plugins/diagnose-plugin"}:
        print("ready")
    else:
        print("conflicting-entry")
    raise SystemExit(0)

print("missing-entry")
PY
}

prepare_plugin_prerequisites() {
    local cachebuster_script="$CODEX_ROOT/skills/.system/plugin-creator/scripts/update_plugin_cachebuster.py"
    local scaffold_script="$CODEX_ROOT/skills/.system/plugin-creator/scripts/create_basic_plugin.py"

    if (( SKIP_PLUGIN )); then
        return 0
    fi

    CODEX_BIN="$(find_command codex || true)"
    [[ -n "$CODEX_BIN" ]] || die "Codex CLI não foi encontrado. Instale-o ou use --skip-plugin para preparar apenas o pacote e a configuração."

    [[ -f "$scaffold_script" ]] || die "Não encontrei o auxiliar do marketplace em $scaffold_script. Atualize ou reinstale o Codex, ou use --skip-plugin."
    [[ -f "$cachebuster_script" ]] || die "Não encontrei o auxiliar de atualização do plugin em $cachebuster_script. Atualize ou reinstale o Codex, ou use --skip-plugin."

    if ! MARKETPLACE_STATE="$(marketplace_state)"; then
        die "Não foi possível validar o marketplace pessoal em $MARKETPLACE_FILE."
    fi
    MARKETPLACE_STATE="${MARKETPLACE_STATE//$'\r'/}"

    case "$MARKETPLACE_STATE" in
        ready|missing-file|missing-entry)
            ;;
        conflicting-entry)
            die "A entrada existente de $PLUGIN_NAME no marketplace pessoal aponta para outra origem. O script não a sobrescreve."
            ;;
        *)
            die "Estado inesperado do marketplace pessoal: $MARKETPLACE_STATE"
            ;;
    esac

    if [[ "$MARKETPLACE_STATE" != "ready" ]] && \
        path_exists "$PLUGIN_STAGE_DIR/.codex-plugin/plugin.json"; then
        die "Já existe um staging de $PLUGIN_NAME sem entrada no marketplace pessoal. Para preservar esse staging, o script não usa --force; resolva a entrada manualmente ou escolha outro HOME."
    fi
}

prepare_marketplace_entry() {
    local scaffold_script="$CODEX_ROOT/skills/.system/plugin-creator/scripts/create_basic_plugin.py"

    (( SKIP_PLUGIN )) && return 0
    if [[ "$MARKETPLACE_STATE" == "ready" ]]; then
        info "A entrada do marketplace pessoal já está pronta."
        return 0
    fi

    info "Registrando o bundle no marketplace pessoal do Codex."
    run "$PYTHON_BIN" "$scaffold_script" "$PLUGIN_NAME" \
        --path "$HOME/plugins" \
        --with-marketplace
}

install_plugin() {
    local cachebuster_script="$CODEX_ROOT/skills/.system/plugin-creator/scripts/update_plugin_cachebuster.py"

    (( SKIP_PLUGIN )) && return 0

    info "Atualizando o staging do plugin em $PLUGIN_STAGE_DIR."
    run mkdir -p -- "$PLUGIN_STAGE_DIR"
    run cp -a "$SOURCE_DIR/plugins/$PLUGIN_NAME/." "$PLUGIN_STAGE_DIR/"

    info "Atualizando o cachebuster do bundle para que o Codex recarregue a versão local."
    run "$PYTHON_BIN" "$cachebuster_script" "$PLUGIN_STAGE_DIR"

    info "Instalando o plugin no Codex."
    run "$CODEX_BIN" plugin add "$PLUGIN_NAME@personal"
}

configure_shell_path() {
    (( UPDATE_PATH )) || return 0
    info "Configurando o PATH pelo uv."
    run "$UV_BIN" tool update-shell
}

run_doctor() {
    local terminal_bin=""

    if (( DRY_RUN )); then
        run diagnose-terminal --config-dir "$CONFIG_DIR" doctor
        return 0
    fi

    terminal_bin="$(find_command diagnose-terminal || true)"
    [[ -n "$terminal_bin" ]] || die "O pacote foi instalado, mas diagnose-terminal não foi localizado em $TOOL_BIN_DIR. Abra outro terminal ou use --update-path."

    info "Validando a instalação local."
    run "$terminal_bin" --config-dir "$CONFIG_DIR" doctor
}

start_server() {
    local terminal_bin=""

    (( START_SERVER )) || return 0
    (( DRY_RUN )) && {
        run diagnose-terminal --config-dir "$CONFIG_DIR" start
        return 0
    }

    [[ -t 0 && -t 1 ]] || die "--start exige um terminal interativo visível."
    terminal_bin="$(find_command diagnose-terminal || true)"
    [[ -n "$terminal_bin" ]] || die "diagnose-terminal não foi localizado; abra outro terminal ou use --update-path."

    info "Iniciando o Terminal Server. Use Ctrl+C para encerrar."
    run "$terminal_bin" --config-dir "$CONFIG_DIR" start
}

print_next_steps() {
    printf '\n'
    info "Instalação concluída."
    info "Configuração: $CONFIG_DIR"

    if (( ! UPDATE_PATH )); then
        info "Para disponibilizar os comandos em novos terminais, execute 'uv tool update-shell' ou rode este script com --update-path."
    fi
    if (( ! SKIP_PLUGIN )); then
        info "Abra um novo thread no Codex e use \$diagnose para iniciar uma investigação."
    fi
    if (( ! START_SERVER )); then
        info "Para abrir a fila visível de aprovações: diagnose-terminal --config-dir \"$CONFIG_DIR\" start"
    fi
}

while (( $# > 0 )); do
    case "$1" in
        --install-uv)
            INSTALL_UV=1
            shift
            ;;
        --update-path)
            UPDATE_PATH=1
            shift
            ;;
        --config-dir)
            (( $# >= 2 )) || die "--config-dir exige um diretório."
            CONFIG_DIR="$2"
            shift 2
            ;;
        --source)
            (( $# >= 2 )) || die "--source exige um diretório."
            SOURCE_DIR="$2"
            shift 2
            ;;
        --skip-plugin)
            SKIP_PLUGIN=1
            shift
            ;;
        --start)
            START_SERVER=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "Opção desconhecida: $1. Use --help para ver as opções."
            ;;
    esac
done

[[ "$(uname -s)" == "Linux" ]] || die "Este instalador é destinado a Linux."
SOURCE_DIR="$(resolve_directory "$SOURCE_DIR")"

[[ -f "$SOURCE_DIR/pyproject.toml" ]] || die "pyproject.toml não foi encontrado em $SOURCE_DIR."
[[ -d "$SOURCE_DIR/plugins/$PLUGIN_NAME" ]] || die "Bundle do plugin não encontrado em $SOURCE_DIR/plugins/$PLUGIN_NAME."

export PATH="$TOOL_BIN_DIR:$PATH"

select_python
ensure_uv
prepare_plugin_prerequisites

info "Usando Python: $PYTHON_BIN"
info "Usando uv: $UV_BIN"

install_package
prepare_configuration
prepare_marketplace_entry
install_plugin
configure_shell_path
run_doctor
start_server
print_next_steps
