#!/usr/bin/env bash
set -euo pipefail

# generates self-signed mutual TLS certs for local testing
# outputs to the solution root

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$OUT_DIR"

DAYS=365
export MSYS_NO_PATHCONV=1

# CA
openssl req -x509 -newkey rsa:2048 -nodes -days $DAYS \
    -keyout ca_key.pem -out certificate_authority.pem \
    -subj "/CN=anticheat-test-ca"

# DH params
openssl dhparam -out dhparams.pem 2048

# server cert
openssl req -newkey rsa:2048 -nodes \
    -keyout server_private_key.pem -out server.csr \
    -subj "/CN=anticheat-server"

openssl x509 -req -in server.csr -CA certificate_authority.pem -CAkey ca_key.pem \
    -CAcreateserial -out server_certificate.pem -days $DAYS

# client cert
openssl req -newkey rsa:2048 -nodes \
    -keyout client_private_key.pem -out client.csr \
    -subj "/CN=anticheat-client"

openssl x509 -req -in client.csr -CA certificate_authority.pem -CAkey ca_key.pem \
    -CAcreateserial -out client_certificate.pem -days $DAYS

# cleanup intermediates
rm -f server.csr client.csr ca_key.pem certificate_authority.srl

echo "certificates generated:"
ls -1 *.pem
