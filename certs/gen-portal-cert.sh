#!/usr/bin/env bash
# Gera um certificado autoassinado para o PORTAL (HTTPS na porta 8443).
# Em produção, troque por um certificado emitido pela CA interna da empresa
# (basta substituir portal.crt e portal.key) — aí o navegador não mostra aviso.
#
# Uso:  ./gen-portal-cert.sh [hostname] [ip]
set -euo pipefail

HOST="${1:-vuln.example.local}"
IP="${2:-10.20.0.10}"
DIR="$(cd "$(dirname "$0")" && pwd)"

openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
  -keyout "$DIR/portal.key" \
  -out    "$DIR/portal.crt" \
  -subj   "/C=BR/O=Rede Brasil/CN=${HOST}" \
  -addext "subjectAltName=DNS:${HOST},IP:${IP}"

chmod 600 "$DIR/portal.key"
echo "Gerados: $DIR/portal.crt e $DIR/portal.key (CN=${HOST}, IP=${IP})"
