#!/usr/bin/env bash
# start.sh — Inicia os 3 serviços Flask do GID Lab
# Uso: bash start.sh
# Para parar: bash stop.sh

set -e
cd "$(dirname "$0")"

# Verificar se o venv existe
if [ ! -f "venv/bin/activate" ]; then
  echo "[ERRO] venv não encontrado. Corre primeiro:"
  echo "  python3 -m venv venv && source venv/bin/activate"
  echo "  pip install -r sp1/requirements.txt -r sp2/requirements.txt -r attacker/requirements.txt"
  exit 1
fi

source venv/bin/activate
mkdir -p logs

echo "=============================="
echo "  GID Lab — A iniciar serviços"
echo "=============================="

echo ""
echo "▶ SP1  — Portal A    http://localhost:5001"
python sp1/app.py > logs/sp1.log 2>&1 &
echo $! > logs/sp1.pid

echo "▶ SP2  — Portal B    http://localhost:5002"
python sp2/app.py > logs/sp2.log 2>&1 &
echo $! > logs/sp2.pid

echo "▶ Attacker Server    http://localhost:9999"
python attacker/app.py > logs/attacker.log 2>&1 &
echo $! > logs/attacker.pid

sleep 1
echo ""
echo "✅ Serviços iniciados."
echo "   Logs: logs/sp1.log | logs/sp2.log | logs/attacker.log"
echo "   Para parar: bash stop.sh"
