#!/usr/bin/env bash
# run.sh — one entry point for the audit-log forensics agent.
#
# Subcommands:
#   demo                    Run the 5-query CLI demo against the live audit log
#   ask "<question>"        Run the agent on one ad-hoc question
#   eval                    Run the full 30-question eval (needs ANTHROPIC_API_KEY)
#   eval-dry                Run the eval without the Claude judge (offline)
#   eval-resume <jsonl>     Resume an interrupted eval into an existing JSONL
#                           (auto-detects first ungraded question; re-runs
#                           the agent for those questions — use when the
#                           agent answers themselves are missing)
#   grade <jsonl>           Re-judge existing ungraded rows in place, without
#                           re-running the agent. Use this when the judge
#                           ran out of credit mid-run and you want to grade
#                           the captured answers after a top-up. Idempotent.
#   compare <base> <new>    Diff two eval-run JSONL files
#   trace [<file>]          Pretty-print a trace file (defaults to newest)
#   start-mlx [<model>]     Foreground-run mlx_lm.server with a Qwen 2.5 MLX
#                           model (default: mlx-community/Qwen2.5-7B-Instruct-4bit)
#                           on port 8765. Stop with Ctrl-C.
#   doctor                  Pre-flight every dependency + connection
#   setup                   First-time: create venv + install deps + check tools
#   help                    Print this usage
#
# Backends:
#   BACKEND=mlx     (default) — http://localhost:8765/v1  (mlx_lm.server,
#                                start with: ./run.sh start-mlx)
#   BACKEND=lmstudio          — http://localhost:1234/v1  (LM Studio)
#   BACKEND=ollama            — http://localhost:11434/v1 (Ollama)
#   BACKEND=auto              — probe lmstudio → ollama → mlx in that order,
#                                use the first responsive one
#
# MLX is the default because it's the lightest path on Apple Silicon
# (one process, MLX-native, reuses LocallyAI's mlx_lm.server install).
# If MLX isn't running, the preflight prints the start-mlx command.
#
# When BACKEND is set, sensible BASE_URL + MODEL defaults are filled
# in. Explicit BASE_URL / MODEL overrides always win. Examples:
#   ./run.sh demo                                # uses MLX (default)
#   BACKEND=lmstudio ./run.sh demo               # switch to LM Studio
#   BACKEND=ollama   ./run.sh demo               # switch to Ollama
#   BACKEND=auto     ./run.sh demo               # auto-detect
#   BASE_URL=http://office-mac.local:11434/v1 MODEL=qwen2.5:14b ./run.sh eval
#
# Every command auto-sources LocallyAI's .env if it exists at the
# expected path, activates the venv, then dispatches to Python.

set -euo pipefail

# ── colours (no-op if NO_COLOR is set or stdout isn't a terminal) ────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RED=$'\033[31m';   C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m';  C_DIM=$'\033[2m';    C_BOLD=$'\033[1m'
    C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_DIM=""; C_BOLD=""; C_RESET=""
fi

log()    { printf '%s[run.sh]%s %s\n'        "$C_BLUE"   "$C_RESET" "$*" >&2; }
warn()   { printf '%s[run.sh] warn:%s %s\n'  "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()    { printf '%s[run.sh] error:%s %s\n' "$C_RED"    "$C_RESET" "$*" >&2; }
ok()     { printf '%s[run.sh] ok:%s %s\n'    "$C_GREEN"  "$C_RESET" "$*" >&2; }
die()    { err "$*"; exit 1; }

# ── paths ───────────────────────────────────────────────────────────────
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
LOCALLYAI_REPO="${LOCALLYAI_REPO:-$HOME/locallyai}"
LOCALLYAI_ENV="${LOCALLYAI_ENV:-$LOCALLYAI_REPO/.env}"

# ── backend selection + per-backend defaults ────────────────────────────
# BACKEND env var: lmstudio | ollama | mlx | auto (default)
# Per-backend defaults are applied ONLY if BASE_URL / MODEL aren't
# already set in the environment. Explicit overrides always win.

: "${BACKEND:=mlx}"
: "${LOCALLYAI_AUDIT_LOG:=$LOCALLYAI_REPO/logs/audit.log}"

# Default port / model per backend. Tuned to what each tool ships:
#   LM Studio: port 1234 by default, Qwen 2.5 Coder 7B MLX (our baseline model)
#   Ollama:    port 11434 by default, Qwen 2.5 14B (Ollama publishes :14b as the instruct variant)
#   mlx_lm.server: port 8765 by convention here, Qwen 2.5 7B Instruct 4bit (already on disk)
LMSTUDIO_DEFAULT_URL="http://localhost:1234/v1"
LMSTUDIO_DEFAULT_MODEL="qwen2.5-coder-7b-instruct-mlx"
OLLAMA_DEFAULT_URL="http://localhost:11434/v1"
OLLAMA_DEFAULT_MODEL="qwen2.5:14b"
MLX_DEFAULT_URL="http://localhost:8765/v1"
MLX_DEFAULT_MODEL="mlx-community/Qwen2.5-7B-Instruct-4bit"

_probe() {  # _probe <base_url>  — returns 0 if /models is reachable
    curl -sS -o /dev/null --max-time 2 "$1/models" 2>/dev/null
}

_apply_backend_defaults() {
    case "$BACKEND" in
        lmstudio)
            : "${BASE_URL:=$LMSTUDIO_DEFAULT_URL}"
            : "${MODEL:=$LMSTUDIO_DEFAULT_MODEL}"
            ;;
        ollama)
            : "${BASE_URL:=$OLLAMA_DEFAULT_URL}"
            : "${MODEL:=$OLLAMA_DEFAULT_MODEL}"
            ;;
        mlx)
            : "${BASE_URL:=$MLX_DEFAULT_URL}"
            : "${MODEL:=$MLX_DEFAULT_MODEL}"
            ;;
        auto)
            # Probe in preference order. First responsive port wins.
            # If the operator set BASE_URL explicitly, skip probing.
            if [ -z "${BASE_URL:-}" ]; then
                if   _probe "$LMSTUDIO_DEFAULT_URL"; then
                    BACKEND=lmstudio; BASE_URL="$LMSTUDIO_DEFAULT_URL"; : "${MODEL:=$LMSTUDIO_DEFAULT_MODEL}"
                elif _probe "$OLLAMA_DEFAULT_URL"; then
                    BACKEND=ollama;   BASE_URL="$OLLAMA_DEFAULT_URL";   : "${MODEL:=$OLLAMA_DEFAULT_MODEL}"
                elif _probe "$MLX_DEFAULT_URL"; then
                    BACKEND=mlx;      BASE_URL="$MLX_DEFAULT_URL";      : "${MODEL:=$MLX_DEFAULT_MODEL}"
                else
                    # Nothing reachable. Fall back to LM Studio defaults
                    # so the doctor / preflight steps fire a helpful error.
                    BACKEND=lmstudio
                    BASE_URL="$LMSTUDIO_DEFAULT_URL"
                    : "${MODEL:=$LMSTUDIO_DEFAULT_MODEL}"
                fi
            else
                : "${MODEL:=$LMSTUDIO_DEFAULT_MODEL}"
            fi
            ;;
        *)
            die "unknown BACKEND='$BACKEND'. Use lmstudio | ollama | mlx | auto."
            ;;
    esac
    export BACKEND BASE_URL MODEL
}

# ── helpers ─────────────────────────────────────────────────────────────
require_venv() {
    if [ ! -d "$HERE/.venv" ]; then
        die "venv missing at $HERE/.venv. Run: $0 setup"
    fi
    # shellcheck disable=SC1091
    source "$HERE/.venv/bin/activate"
}

source_locallyai_env() {
    if [ -f "$LOCALLYAI_ENV" ]; then
        # shellcheck disable=SC1090
        set -a; source "$LOCALLYAI_ENV"; set +a
    else
        warn "$LOCALLYAI_ENV not found — LOCALLYAI_AUDIT_HMAC_KEY will be unset; hmac_verify will fail."
    fi
}

check_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        die "python3 not on PATH. Install via Homebrew: brew install python@3.12"
    fi
    local py_ver
    py_ver="$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
    case "$py_ver" in
        3.1[0-9]|3.[2-9][0-9]) : ;;   # 3.10+
        *) die "Python $py_ver found; need 3.10 or newer." ;;
    esac
}

check_backend() {  # backend-aware probe; replaces the old check_backend
    if ! curl -sS -o /dev/null --max-time 3 "$BASE_URL/models" 2>/dev/null; then
        err "BACKEND=$BACKEND endpoint $BASE_URL is unreachable."
        case "$BACKEND" in
            lmstudio)
                cat >&2 <<EOF
  Fix checklist for LM Studio:
    1. LM Studio app is open                       (check Dock)
    2. Developer tab → Status: Running             (toggle ON)
    3. A chat-capable model is loaded               (Qwen 2.5 14B or Coder 7B)
    4. Port 1234 not taken: lsof -nP -iTCP:1234 -sTCP:LISTEN
EOF
                ;;
            ollama)
                cat >&2 <<EOF
  Fix checklist for Ollama:
    1. Ollama app running: open -a Ollama   (or brew services restart ollama)
    2. Ollama version is recent: ollama --version   (some older builds crash on
       macOS Metal — symptom is "llama runner process has terminated").
       Fix with: brew install --cask ollama-app --force
    3. The model is pulled: ollama list   (expect qwen2.5:14b or similar)
EOF
                ;;
            mlx)
                cat >&2 <<EOF
  Fix checklist for MLX (mlx_lm.server):
    1. Start the server in another terminal:
         $0 start-mlx                # uses default Qwen 2.5 7B 4bit
         $0 start-mlx <model-id>     # specify a different MLX model
    2. Confirm: curl http://localhost:8765/v1/models
EOF
                ;;
        esac
        cat >&2 <<EOF

  Other options:
    - Try auto-detect: BACKEND=auto $0 doctor
    - Use a remote backend: BASE_URL=http://host:port/v1 $0 <subcommand>
EOF
        return 1
    fi
    # Confirm the requested model is loaded.
    if ! curl -sS --max-time 3 "$BASE_URL/models" 2>/dev/null | python3 -c "
import json,sys
ids = [m['id'] for m in json.load(sys.stdin).get('data',[])]
sys.exit(0 if '$MODEL' in ids else 1)
" 2>/dev/null; then
        warn "Model '$MODEL' is NOT in the $BACKEND-loaded model list."
        warn "  Available: $(curl -sS --max-time 3 "$BASE_URL/models" | python3 -c 'import json,sys; print([m[\"id\"] for m in json.load(sys.stdin).get(\"data\",[])])' 2>/dev/null || echo '?')"
        warn "  Either load '$MODEL' in your backend, or override: MODEL=<id> $0 <subcommand>"
    fi
}

check_audit_log() {
    if [ ! -f "$LOCALLYAI_AUDIT_LOG" ]; then
        err "LOCALLYAI_AUDIT_LOG=$LOCALLYAI_AUDIT_LOG does not exist."
        cat >&2 <<EOF
  Likely causes:
    - The LocallyAI install isn't at $LOCALLYAI_REPO.
      Override with LOCALLYAI_REPO=/path/to/locallyai
    - LocallyAI hasn't generated any audit entries yet.
      Send one request to https://localhost:8000/v1/chat/completions first.
    - Custom log dir set via LOCALLYAI_LOG_DIR in LocallyAI's .env.
      Set LOCALLYAI_AUDIT_LOG explicitly to override.
EOF
        return 1
    fi
    # Empty active log is fine (rotated) — the tool walker picks up .gz siblings.
    if [ ! -s "$LOCALLYAI_AUDIT_LOG" ]; then
        warn "Active log $LOCALLYAI_AUDIT_LOG is empty (just rotated). The walker will read .gz siblings."
    fi
}

check_hmac_key() {
    if [ -z "${LOCALLYAI_AUDIT_HMAC_KEY:-}" ]; then
        warn "LOCALLYAI_AUDIT_HMAC_KEY not set — hmac_verify will raise HmacKeyMissing."
        warn "  Fix: ensure $LOCALLYAI_ENV exists and contains the key (this is sourced automatically)."
    fi
}

check_anthropic_key() {
    if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
        err "ANTHROPIC_API_KEY not set; eval judge will refuse to start."
        cat >&2 <<EOF
  Fix:
    export ANTHROPIC_API_KEY=sk-ant-...
    $0 eval

  Or run an offline dry-run that captures agent answers without grading:
    $0 eval-dry

  To use a cheaper / different judge model: export JUDGE_MODEL=claude-sonnet-4-6-20251022
EOF
        return 1
    fi
}

usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
}

# ── subcommand: setup ───────────────────────────────────────────────────
cmd_setup() {
    log "setup: creating venv + installing deps"
    check_python
    if [ ! -d "$HERE/.venv" ]; then
        python3 -m venv "$HERE/.venv"
        ok "venv created at $HERE/.venv"
    else
        log "venv already exists; reusing"
    fi
    # shellcheck disable=SC1091
    source "$HERE/.venv/bin/activate"
    pip install --quiet --upgrade pip
    pip install --quiet openai pydantic pyyaml anthropic
    ok "deps installed: openai pydantic pyyaml anthropic"
    log "setup complete. Next: $0 doctor"
}

# ── subcommand: doctor ──────────────────────────────────────────────────
cmd_doctor() {
    local fail=0
    log "doctor: probing every dependency"
    echo
    echo "  ${C_BOLD}python${C_RESET}"
    check_python && ok "  python $(python3 -V 2>&1 | awk '{print $2}')"
    echo
    echo "  ${C_BOLD}venv${C_RESET}"
    if [ -d "$HERE/.venv" ]; then
        ok "  venv exists at $HERE/.venv"
        source "$HERE/.venv/bin/activate"
        for pkg in openai pydantic yaml anthropic; do
            if python3 -c "import $pkg" 2>/dev/null; then
                ok "    $pkg installed"
            else
                err "    $pkg MISSING; run: $0 setup"
                fail=1
            fi
        done
    else
        err "  no venv; run: $0 setup"
        fail=1
    fi
    echo
    echo "  ${C_BOLD}LocallyAI .env${C_RESET}"
    if [ -f "$LOCALLYAI_ENV" ]; then
        ok "  found at $LOCALLYAI_ENV"
        # shellcheck disable=SC1090
        set -a; source "$LOCALLYAI_ENV"; set +a
        if [ -n "${LOCALLYAI_AUDIT_HMAC_KEY:-}" ]; then
            ok "    LOCALLYAI_AUDIT_HMAC_KEY set (${#LOCALLYAI_AUDIT_HMAC_KEY} chars)"
        else
            warn "    LOCALLYAI_AUDIT_HMAC_KEY missing — hmac_verify will fail"
        fi
    else
        warn "  not found at $LOCALLYAI_ENV"
        warn "    Override with LOCALLYAI_ENV=/path/to/.env"
        fail=1
    fi
    echo
    echo "  ${C_BOLD}audit log${C_RESET}"
    if [ -f "$LOCALLYAI_AUDIT_LOG" ]; then
        local active_size; active_size=$(wc -c < "$LOCALLYAI_AUDIT_LOG" | tr -d ' ')
        local rotations; rotations=$(ls "$LOCALLYAI_AUDIT_LOG".dir 2>/dev/null; find "$(dirname "$LOCALLYAI_AUDIT_LOG")" -name "$(basename "$LOCALLYAI_AUDIT_LOG" .log)-*.log.gz" 2>/dev/null | wc -l | tr -d ' ')
        ok "  $LOCALLYAI_AUDIT_LOG ($active_size bytes active; $rotations rotation(s))"
    else
        err "  $LOCALLYAI_AUDIT_LOG NOT FOUND"
        fail=1
    fi
    echo
    echo "  ${C_BOLD}backends — probing all three${C_RESET}"
    local any_up=0
    for entry in "lmstudio|$LMSTUDIO_DEFAULT_URL" "ollama|$OLLAMA_DEFAULT_URL" "mlx|$MLX_DEFAULT_URL"; do
        local name="${entry%%|*}"; local url="${entry##*|}"
        if curl -sS -o /dev/null --max-time 2 "$url/models" 2>/dev/null; then
            local available; available=$(curl -sS --max-time 2 "$url/models" | python3 -c 'import json,sys; print(",".join(m["id"] for m in json.load(sys.stdin).get("data",[])))' 2>/dev/null || echo "?")
            ok "  $name ($url) reachable; models: ${available:-<none>}"
            any_up=1
        else
            warn "  $name ($url) unreachable"
        fi
    done
    if [ "$any_up" -eq 0 ]; then
        err "  no backend is reachable. Start one:"
        echo "    LM Studio: open LM Studio → Developer → Status: Running" >&2
        echo "    Ollama:    open -a Ollama   (and: brew install --cask ollama-app --force if old)" >&2
        echo "    MLX:       $0 start-mlx" >&2
        fail=1
    fi
    echo
    echo "  ${C_BOLD}active selection (BACKEND=$BACKEND)${C_RESET}"
    _apply_backend_defaults
    log "  base_url: $BASE_URL"
    log "  model:    $MODEL"
    echo
    echo "  ${C_BOLD}anthropic (for eval judge — optional)${C_RESET}"
    if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
        ok "  ANTHROPIC_API_KEY set (${#ANTHROPIC_API_KEY} chars)"
    else
        warn "  ANTHROPIC_API_KEY not set; eval needs it (eval-dry works without)"
    fi
    echo
    if [ "$fail" -eq 0 ]; then
        ok "doctor: everything looks green for demo / ask / eval"
    else
        warn "doctor: some checks failed — see warnings/errors above"
        exit 1
    fi
}

# ── subcommand: demo ────────────────────────────────────────────────────
cmd_demo() {
    require_venv
    source_locallyai_env
    _apply_backend_defaults
    log "backend: $BACKEND  base_url: $BASE_URL  model: $MODEL"
    check_backend || die "fix the backend issue above first"
    check_audit_log || die "fix the audit-log issue above first"
    check_hmac_key
    log "demo: running cli.py (5 queries)"
    export BASE_URL MODEL LOCALLYAI_AUDIT_LOG
    exec python cli.py
}

# ── subcommand: ask ─────────────────────────────────────────────────────
cmd_ask() {
    if [ "$#" -lt 1 ] || [ -z "$1" ]; then
        die "usage: $0 ask \"<question>\""
    fi
    local q="$1"
    require_venv
    source_locallyai_env
    _apply_backend_defaults
    log "backend: $BACKEND  base_url: $BASE_URL  model: $MODEL"
    check_backend || die "fix the backend issue above first"
    check_audit_log || die "fix the audit-log issue above first"
    check_hmac_key
    log "ask: $q"
    export BASE_URL MODEL LOCALLYAI_AUDIT_LOG
    exec python agent.py "$q"
}

# ── subcommand: eval ────────────────────────────────────────────────────
cmd_eval() {
    require_venv
    source_locallyai_env
    _apply_backend_defaults
    log "backend: $BACKEND  base_url: $BASE_URL  model: $MODEL"
    check_backend || die "fix the backend issue above first"
    check_audit_log || die "fix the audit-log issue above first"
    check_hmac_key
    check_anthropic_key || die "judge needs ANTHROPIC_API_KEY; or use: $0 eval-dry"
    log "eval: 30-question run (~10-15 min on Coder 7B, ~20-40 min on 14B)"
    export BASE_URL MODEL LOCALLYAI_AUDIT_LOG
    exec python -m eval.run "$@"
}

# ── subcommand: eval-dry ────────────────────────────────────────────────
cmd_eval_dry() {
    require_venv
    source_locallyai_env
    _apply_backend_defaults
    log "backend: $BACKEND  base_url: $BASE_URL  model: $MODEL"
    check_backend || die "fix the backend issue above first"
    check_audit_log || die "fix the audit-log issue above first"
    check_hmac_key
    log "eval-dry: 30-question run, judge SKIPPED (no Anthropic call)"
    export BASE_URL MODEL LOCALLYAI_AUDIT_LOG
    exec python -m eval.run --no-judge "$@"
}

# ── subcommand: eval-resume ─────────────────────────────────────────────
cmd_eval_resume() {
    if [ "$#" -lt 1 ]; then
        die "usage: $0 eval-resume <eval/runs/...jsonl>"
    fi
    local target="$1"
    [ -f "$target" ] || die "$target not found"
    require_venv
    source_locallyai_env
    _apply_backend_defaults
    log "backend: $BACKEND  base_url: $BASE_URL  model: $MODEL"
    check_backend || die "fix the backend issue above first"
    check_audit_log || die "fix the audit-log issue above first"
    check_hmac_key
    check_anthropic_key || die "judge needs ANTHROPIC_API_KEY"
    # Auto-detect first ungraded id (judge_error or null pass-axis).
    local first_ungraded
    first_ungraded=$(python3 -c "
import json, sys
ids = []
with open('$target') as f:
    for line in f:
        r = json.loads(line)
        j = r.get('judge') or {}
        if j.get('judge_error') or j.get('tool_pass') is None:
            ids.append(r['id'])
print(ids[0] if ids else '', end='')
")
    if [ -z "$first_ungraded" ]; then
        log "no ungraded rows in $target — nothing to resume"
        exit 0
    fi
    log "eval-resume: starting from $first_ungraded into $target"
    export BASE_URL MODEL LOCALLYAI_AUDIT_LOG
    exec python -m eval.run --start-from "$first_ungraded" --resume-into "$target"
}

# ── subcommand: grade ──────────────────────────────────────────────────
# Re-judge existing ungraded rows in place. NO backend needed (the agent
# is not re-invoked), only ANTHROPIC_API_KEY.
cmd_grade() {
    if [ "$#" -lt 1 ]; then
        die "usage: $0 grade <eval/runs/...jsonl>"
    fi
    local target="$1"
    [ -f "$target" ] || die "$target not found"
    require_venv
    check_anthropic_key || die "judge needs ANTHROPIC_API_KEY"
    log "grade: re-judging ungraded rows in $target (in place)"
    exec python -m eval.run --grade-only "$target"
}

# ── subcommand: compare ─────────────────────────────────────────────────
cmd_compare() {
    if [ "$#" -lt 2 ]; then
        die "usage: $0 compare <base.jsonl> <new.jsonl>"
    fi
    require_venv
    exec python -m eval.compare "$1" "$2"
}

# ── subcommand: trace ───────────────────────────────────────────────────
cmd_trace() {
    require_venv
    local target="${1:-traces/}"
    [ -e "$target" ] || die "$target not found"
    exec python trace_viewer.py "$target"
}

# ── subcommand: start-mlx ───────────────────────────────────────────────
# Foreground-runs mlx_lm.server. Uses the LocallyAI venv's mlx_lm.server
# binary if available (LocallyAI ships mlx-lm as a dep), otherwise the
# system one. The port is 8765 to avoid collisions with LM Studio (1234),
# Ollama (11434), and LocallyAI's own API (8000).
#
# Usage:
#   ./run.sh start-mlx                              # default Qwen 7B 4bit
#   ./run.sh start-mlx mlx-community/<other-model>  # custom
#
# Then in another terminal:  BACKEND=mlx ./run.sh demo
cmd_start_mlx() {
    local model="${1:-$MLX_DEFAULT_MODEL}"
    local port="${MLX_PORT:-8765}"
    local mlx_bin
    if [ -x "$LOCALLYAI_REPO/.venv/bin/mlx_lm.server" ]; then
        mlx_bin="$LOCALLYAI_REPO/.venv/bin/mlx_lm.server"
        log "using LocallyAI venv's mlx_lm.server"
    elif command -v mlx_lm.server >/dev/null 2>&1; then
        mlx_bin="$(command -v mlx_lm.server)"
        log "using system mlx_lm.server at $mlx_bin"
    else
        cat >&2 <<EOF
$(err "mlx_lm.server not found.")
  Install:
    1. Easiest: source LocallyAI's venv — its mlx-lm install includes mlx_lm.server.
       source $LOCALLYAI_REPO/.venv/bin/activate
       $0 start-mlx
    2. Otherwise install into a venv of your choice:
       pip install mlx-lm
       mlx_lm.server --model $MLX_DEFAULT_MODEL --port $port
EOF
        exit 1
    fi
    log "start-mlx: model=$model  port=$port  (Ctrl-C to stop)"
    log "  in another terminal: BACKEND=mlx $0 demo"
    exec "$mlx_bin" --model "$model" --host 127.0.0.1 --port "$port"
}

# ── dispatch ────────────────────────────────────────────────────────────
main() {
    local sub="${1:-help}"
    shift || true
    case "$sub" in
        demo)        cmd_demo ;;
        ask)         cmd_ask "$@" ;;
        eval)        cmd_eval "$@" ;;
        eval-dry)    cmd_eval_dry "$@" ;;
        eval-resume) cmd_eval_resume "$@" ;;
        grade)       cmd_grade "$@" ;;
        compare)     cmd_compare "$@" ;;
        trace)       cmd_trace "$@" ;;
        start-mlx)   cmd_start_mlx "$@" ;;
        doctor)      cmd_doctor ;;
        setup)       cmd_setup ;;
        help|-h|--help) usage ;;
        *)           err "unknown subcommand: $sub"; echo >&2; usage; exit 1 ;;
    esac
}

main "$@"
