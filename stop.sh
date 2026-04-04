#!/usr/bin/env bash
# stop.sh — Para os serviços iniciados por start.sh

cd "$(dirname "$0")"

echo "A parar serviços GID Lab..."

for service in sp1 sp2 attacker; do
  pid_file="logs/${service}.pid"
  if [ -f "$pid_file" ]; then
    pid=$(cat "$pid_file")
    if kill "$pid" 2>/dev/null; then
      echo "  ✅ $service (PID $pid) parado"
    else
      echo "  ⚠  $service (PID $pid) já não estava a correr"
    fi
    rm "$pid_file"
  else
    echo "  —  $service: sem PID registado"
  fi
done

echo "Concluído."
