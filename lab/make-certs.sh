#!/usr/bin/env bash
# Generates the lab's certificate material.
#
# Two chains:
#   server.*  a leaf for 127.0.0.1/localhost, signed by a local test CA, with
#             an AIA URL that points at our own OCSP responder.
#   weak.*    a deliberately bad SHA-1 / 1024-bit RSA certificate, so the
#             "certificate-signature" and "certificate-key-strength" checks
#             have something to fail on.
#
# It also produces a real DER OCSP response for the leaf, which the stapling
# profile serves. Everything lands in lab/certs/ (git-ignored).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/certs"
mkdir -p "$out"
cd "$out"

if ! command -v openssl >/dev/null; then
  echo "openssl is required" >&2
  exit 1
fi

echo "== test CA"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
  -keyout ca.key -out ca.pem -subj "/CN=TLS Checkup Lab CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1

echo "== leaf certificate (localhost, 127.0.0.1)"
openssl req -newkey rsa:2048 -nodes -sha256 \
  -keyout server.key -out server.csr -subj "/CN=localhost" >/dev/null 2>&1
cat > server.ext <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
authorityInfoAccess=OCSP;URI:http://127.0.0.1:18999/
EOF
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 365 -extfile server.ext >/dev/null 2>&1

echo "== deliberately weak certificate (SHA-1, 1024-bit RSA)"
openssl req -x509 -newkey rsa:1024 -nodes -sha1 -days 365 \
  -keyout weak.key -out weak.pem -subj "/CN=weak.lab" \
  -addext "subjectAltName=DNS:weak.lab,IP:127.0.0.1" >/dev/null 2>&1

echo "== OCSP response for the leaf"
serial="$(openssl x509 -in server.pem -noout -serial | cut -d= -f2)"
{
  printf 'V\t%s\t\t%s\tunknown\t/CN=localhost\n' "$(date -u +%Y%m%d%H%M%SZ)" "$serial"
} > index.txt
openssl ocsp -index index.txt -rsigner ca.pem -rkey ca.key -CA ca.pem \
  -issuer ca.pem -cert server.pem -respout response.der -ndays 7 >/dev/null 2>&1

echo
echo "certificates in $out:"
for f in ca.pem server.pem server.key weak.pem weak.key response.der; do
  printf '  %-14s %s bytes\n' "$f" "$(stat -f%z "$out/$f" 2>/dev/null || stat -c%s "$out/$f")"
done
echo
echo "next: node lab/server.ts --cert lab/certs/server.pem --key lab/certs/server.key --chain lab/certs/ca.pem --port 18443"
