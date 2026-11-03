#!/bin/sh
# Creates a private CA and the certificates for the PG <-> VAN mutual TLS link.
# Also creates a "rogue" client certificate from a different CA, used by the tests to show
# that the VAN refuses peers that are not signed by the shared CA.
set -eu
D=${1:-/certs}
mkdir -p "$D"
cd "$D"
if [ -f ca.crt ] && [ -f gateway.crt ] && [ -f van.crt ]; then
  echo "certificates already exist in $D"
  exit 0
fi

subj() { echo "/C=KR/O=PayRelay Demo/CN=$1"; }

openssl req -x509 -newkey rsa:2048 -nodes -days 825 -keyout ca.key -out ca.crt -subj "$(subj 'PayRelay Demo CA')" 2>/dev/null

issue() { # name cn san
  openssl req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "$(subj "$2")" 2>/dev/null
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth,clientAuth\n' "$3" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 -out "$1.crt" -extfile "$1.ext" 2>/dev/null
  rm -f "$1.csr" "$1.ext"
}
issue van "van" "DNS:van"
issue gateway "pg-gateway" "DNS:gateway"

# A certificate the VAN must reject: signed by an unrelated CA.
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout rogue-ca.key -out rogue-ca.crt -subj "$(subj 'Rogue CA')" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout rogue.key -out rogue.csr -subj "$(subj 'rogue-client')" 2>/dev/null
openssl x509 -req -in rogue.csr -CA rogue-ca.crt -CAkey rogue-ca.key -CAcreateserial -days 30 -out rogue.crt 2>/dev/null
rm -f rogue.csr

chmod 644 ./*.crt
chmod 640 ./*.key
echo "created CA, van, gateway and rogue certificates in $D"
