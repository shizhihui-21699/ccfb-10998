#!/bin/sh
# Generate test PKI for the local test servers:
#   ca.pem / ca-key.pem        mini CA
#   server-cert.pem            CA-signed cert for the "modern" server
#   ocsp.der                   real OCSP response (stapled by "modern")
#   key.pem / cert.pem         self-signed cert for "legacy"/"mixed"
set -e
DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$DIR"
cd "$DIR"

if [ ! -f ca.pem ]; then
  echo "== generating CA =="
  openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca.pem \
    -days 3650 -nodes -subj "/CN=tls-scan-test-CA" 2>/dev/null
  chmod 600 ca-key.pem
fi

cat > ca.cnf <<EOF
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = $DIR
database = \$dir/index.txt
new_certs_dir = \$dir
certificate = \$dir/ca.pem
private_key = \$dir/ca-key.pem
serial = \$dir/serial
default_md = sha256
default_days = 825
copy_extensions = copy
unique_subject = no
policy = policy_any
[ policy_any ]
commonName = supplied
organizationName = optional
EOF
[ -f serial ] || echo 01 > serial
[ -f index.txt ] || touch index.txt

if [ ! -f server-cert.pem ]; then
  echo "== issuing CA-signed server cert =="
  openssl req -newkey rsa:2048 -keyout server-key.pem -out server.csr \
    -nodes -subj "/CN=localhost/O=tls-scan-test" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null \
  || openssl req -newkey rsa:2048 -keyout server-key.pem -out server.csr \
    -nodes -subj "/CN=localhost/O=tls-scan-test"
  openssl ca -batch -config ca.cnf -in server.csr -out server-cert.pem >/dev/null 2>&1
  chmod 600 server-key.pem
fi

if [ ! -f ocsp.der ]; then
  echo "== generating OCSP response =="
  openssl ocsp -index index.txt -CA ca.pem \
    -rsigner ca.pem -rkey ca-key.pem \
    -issuer ca.pem -cert server-cert.pem \
    -respout ocsp.der -ndays 3650 >/dev/null 2>&1 \
  && echo "   ocsp.der ok" || echo "   WARNING: ocsp.der generation failed"
fi

if [ ! -f cert.pem ]; then
  echo "== generating self-signed cert =="
  openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
    -days 365 -nodes -subj "/CN=localhost/O=tls-scan-test" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null \
  || openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
    -days 365 -nodes -subj "/CN=localhost/O=tls-scan-test"
  chmod 600 key.pem
fi

echo "done. files in $DIR:"
ls -1 "$DIR" | grep -E '\.pem$|\.der$'
