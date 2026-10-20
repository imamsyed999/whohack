#!/usr/bin/env bash
set -eu
export PATH="$HOME/.cargo/bin:$PATH"
cd -- "$(dirname -- "$0")/.."

case "${1:-}" in
  start|start-service)
    bash "$0" prepare
    if ! bash "$0" status >/dev/null; then
      nohup bash "$0" service >.vigil/service-launch.log 2>&1 &
      echo "$!" >.vigil/service.pid
      ready=0
      for attempt in {1..30}; do
        if bash "$0" status >/dev/null; then ready=1; break; fi
        sleep 0.5
      done
      if [ "$ready" != 1 ]; then
        echo 'Service did not start; see .vigil/service-launch.log' >&2
        exit 1
      fi
    fi
    if [ "$1" = start ]; then
      bash "$0" build-tray
      nohup bash "$0" tray >.vigil/tray-launch.log 2>&1 &
      echo "$!" >.vigil/tray.pid
    fi
    bash "$0" status
    echo 'whohack is running in WSL monitor mode. Windows host processes and enforcement are not covered.'
    ;;
  stop)
    for app in tray service; do
      file=".vigil/$app.pid"
      [ -f "$file" ] || continue
      pid=$(cat "$file")
      case "$pid" in ''|*[!0-9]*) echo "Invalid PID file: $file" >&2; exit 1;; esac
      # PID reuse must never signal an unrelated process or another checkout.
      if [ -d "/proc/$pid" ]; then
        executable=$(readlink "/proc/$pid/exe" || true)
        directory=$(readlink "/proc/$pid/cwd" || true)
        if [ "$app" = tray ]; then expected="$HOME/whohack-ui-target/debug/whohack-tray"; else expected="$HOME/whohack-target/debug/whohack-service"; fi
        if [ "$directory" != "$PWD" ] || { [ "$executable" != "$expected" ] && [ "$executable" != "$expected (deleted)" ]; }; then
          echo "Refusing to stop PID $pid: it is not this checkout's $app" >&2
          exit 1
        fi
        kill -TERM "$pid"
        for attempt in {1..30}; do
          kill -0 "$pid" 2>/dev/null || break
          sleep 0.5
        done
        if kill -0 "$pid" 2>/dev/null; then
          echo "$app is still shutting down; its PID file was kept." >&2
          exit 1
        fi
      fi
      rm -- "$file"
    done
    echo 'Stopped processes launched by this checkout.'
    ;;
  prepare)
    export CARGO_TARGET_DIR="$HOME/whohack-target"
    cargo build -q -p whohack-service --locked
    if [ ! -f whohack.local.toml ]; then
      "$CARGO_TARGET_DIR/debug/whohack-service" --init-local
    fi
    "$CARGO_TARGET_DIR/debug/whohack-service" --config whohack.local.toml --check-config
    "$CARGO_TARGET_DIR/debug/whohack-service" --config whohack.local.toml --write-manifest
    ;;
  status)
    "$HOME/whohack-target/debug/whohack-service" --config whohack.local.toml --status 2>/dev/null
    ;;
  service)
    exec "$HOME/whohack-target/debug/whohack-service" --config whohack.local.toml --run
    ;;
  build-tray)
    export CARGO_TARGET_DIR="$HOME/whohack-ui-target"
    cargo build -q --manifest-path ui/src-tauri/Cargo.toml --locked
    ;;
  tray)
    export WHOHACK_CONFIG="$PWD/whohack.local.toml"
    export GDK_BACKEND=x11 LIBGL_ALWAYS_SOFTWARE=1
    exec "$HOME/whohack-ui-target/debug/whohack-tray" --show
    ;;
  *)
    echo 'Usage: bash tools/local-launch.sh start|start-service|stop|prepare|status|service|build-tray|tray' >&2
    exit 2
    ;;
esac
