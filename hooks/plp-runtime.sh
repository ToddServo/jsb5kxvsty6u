#!/bin/sh
# plp-runtime.sh - Transport lifecycle shim for PartyLinePager.
#
# Abstracts how hooks manage transport processes. Two modes:
#   PARTY_LINE_PAGER_RUNTIME=compose  (default) - passthrough to docker compose
#   PARTY_LINE_PAGER_RUNTIME=direct   - local process management via PID files
#
# Usage:
#   plp-runtime up    <dir> <service>
#   plp-runtime down  <dir>
#   plp-runtime exec  <dir> <service> <cmd...>
#   plp-runtime run   <dir> <service> [flags...] -c <cmd>
#   plp-runtime logs  <dir> <service>
#
# Compose mode reads PLP_COMPOSE_ARGS for extra flags (override files,
# profiles). Direct mode ignores it.

set -eu

RUNTIME="${PARTY_LINE_PAGER_RUNTIME:-compose}"
PID_DIR="${PLP_PID_DIR:-/var/run/plp}"

_log() { echo "plp-runtime[$RUNTIME]: $*" >&2; }

_pid_file() {
    _name="$(basename "$1")"
    echo "$PID_DIR/${_name}.pid"
}

_log_file() {
    _name="$(basename "$1")"
    echo "$PID_DIR/${_name}.log"
}

_pid_alive() {
    [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null
}

_collect_tree() {
    _ct_queue="$1"
    _ct_all="$1"
    _ct_depth=0
    while [ -n "$_ct_queue" ] && [ "$_ct_depth" -lt 5 ]; do
        _ct_next=""
        for _ct_p in $_ct_queue; do
            _ct_c="$(pgrep -P "$_ct_p" 2>/dev/null)" || true
            if [ -n "$_ct_c" ]; then
                _ct_next="$_ct_next $_ct_c"
                _ct_all="$_ct_all $_ct_c"
            fi
        done
        _ct_queue="$_ct_next"
        _ct_depth=$((_ct_depth + 1))
    done
    echo "$_ct_all"
}

_kill_pid() {
    _pf="$1"
    [ ! -f "$_pf" ] && return 0
    _p="$(cat "$_pf")"
    if kill -0 "$_p" 2>/dev/null; then
        _tree="$(_collect_tree "$_p")"
        kill $_tree 2>/dev/null || true
        _waited=0
        while kill -0 "$_p" 2>/dev/null && [ "$_waited" -lt 10 ]; do
            sleep 1
            _waited=$((_waited + 1))
        done
        if kill -0 "$_p" 2>/dev/null; then
            _log "process $_p did not exit after 10s, sending SIGKILL"
            kill -9 $_tree 2>/dev/null || true
        fi
    fi
    rm -f "$_pf"
}

# Strip compose-specific flags from a run/exec command, return the shell
# command to execute. Reads args from "$@", writes the -c argument body
# to stdout.
_extract_shell_cmd() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --rm|--no-deps|-T) shift ;;
            --name|--entrypoint|--user) shift 2 ;;
            -c) shift; echo "$*"; return 0 ;;
            sh|bash) shift ;;
            *) shift ;;
        esac
    done
    return 1
}

# ── compose mode ─────────────────────────────────────────────────────

_compose_up() {
    _dir="$1"; _svc="$2"; shift 2
    # shellcheck disable=SC2086
    (cd "$_dir" && docker compose $PLP_COMPOSE_ARGS up -d "$_svc" "$@")
}

_compose_down() {
    _dir="$1"; shift
    # shellcheck disable=SC2086
    (cd "$_dir" && docker compose $PLP_COMPOSE_ARGS down "$@")
}

_compose_exec() {
    _dir="$1"; _svc="$2"; shift 2
    # shellcheck disable=SC2086
    (cd "$_dir" && docker compose $PLP_COMPOSE_ARGS exec -T "$_svc" "$@")
}

_compose_run() {
    _dir="$1"; _svc="$2"; shift 2
    # Docker compose requires flags before the service name. The hooks
    # pass flags after the service arg, so collect them here.
    _flags=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --name|--entrypoint|--user) _flags="$_flags $1 $2"; shift 2 ;;
            --rm|--no-deps) _flags="$_flags $1"; shift ;;
            *) break ;;
        esac
    done
    # shellcheck disable=SC2086
    (cd "$_dir" && docker compose $PLP_COMPOSE_ARGS run --rm $_flags "$_svc" "$@")
}

_compose_logs() {
    _dir="$1"; _svc="$2"
    # shellcheck disable=SC2086
    (cd "$_dir" && docker compose $PLP_COMPOSE_ARGS logs --no-color "$_svc")
}

# ── direct mode ──────────────────────────────────────────────────────

_direct_up() {
    _dir="$1"; _svc="$2"
    mkdir -p "$PID_DIR"

    _pf="$(_pid_file "$_dir")"
    _lf="$(_log_file "$_dir")"

    if _pid_alive "$_pf"; then
        _log "already running (pid $(cat "$_pf")), stopping first"
        _kill_pid "$_pf"
    fi

    _name="$(basename "$_dir")"
    # Subshell + trap ensures tail is killed when the transport exits
    # or the subshell is signalled. $! captures the subshell PID.
    case "$_name" in
        *tor*)
            _log "starting tor relay via docker/entrypoint.sh"
            ( trap 'kill $(jobs -p) 2>/dev/null' EXIT
              tail -f /dev/null | "$_dir/docker/entrypoint.sh" relay
            ) >"$_lf" 2>&1 &
            ;;
        *i2p*)
            _log "starting i2p relay"
            ( trap 'kill $(jobs -p) 2>/dev/null' EXIT
              tail -f /dev/null | "$_dir/i2p-party-line.sh" relay
            ) >"$_lf" 2>&1 &
            ;;
        *reticulum*|*rns*)
            _log "starting reticulum reflector"
            ( trap 'kill $(jobs -p) 2>/dev/null' EXIT
              tail -f /dev/null | "$_dir/docker/entrypoint.sh" bash "$_dir/rns-party-line.sh" relay
            ) >"$_lf" 2>&1 &
            ;;
        *)
            _log "unknown transport dir: $_name"
            return 1
            ;;
    esac

    echo $! > "$_pf"
    _log "started (pid $!, log $_lf)"
}

_direct_down() {
    _dir="$1"
    _pf="$(_pid_file "$_dir")"
    _kill_pid "$_pf"
    _lf="$(_log_file "$_dir")"
    _log "stopped"
}

_direct_exec() {
    _dir="$1"; shift; shift  # skip dir and service
    _cmd="$(_extract_shell_cmd "$@")" || {
        _log "exec: no -c argument found, running directly"
        (cd "$_dir" && "$@")
        return $?
    }
    (cd "$_dir" && sh -c "$_cmd")
}

_direct_run() {
    _dir="$1"; shift; shift  # skip dir and service
    _cmd="$(_extract_shell_cmd "$@")" || {
        _log "run: no -c argument found, running directly"
        (cd "$_dir" && "$@")
        return $?
    }
    (cd "$_dir" && sh -c "$_cmd")
}

_direct_logs() {
    _dir="$1"
    _lf="$(_log_file "$_dir")"
    [ -f "$_lf" ] && cat "$_lf" || true
}

# ── dispatch ─────────────────────────────────────────────────────────

PLP_COMPOSE_ARGS="${PLP_COMPOSE_ARGS:-}"

verb="${1:?usage: plp-runtime <up|down|exec|run|logs> <dir> ...}"
shift

case "$RUNTIME" in
    compose)
        case "$verb" in
            up)   _compose_up "$@" ;;
            down) _compose_down "$@" ;;
            exec) _compose_exec "$@" ;;
            run)  _compose_run "$@" ;;
            logs) _compose_logs "$@" ;;
            *)    _log "unknown command: $verb"; exit 1 ;;
        esac
        ;;
    direct)
        case "$verb" in
            up)   _direct_up "$@" ;;
            down) _direct_down "$@" ;;
            exec) _direct_exec "$@" ;;
            run)  _direct_run "$@" ;;
            logs) _direct_logs "$@" ;;
            *)    _log "unknown command: $verb"; exit 1 ;;
        esac
        ;;
    *)
        _log "unknown PARTY_LINE_PAGER_RUNTIME: $RUNTIME"
        exit 1
        ;;
esac
