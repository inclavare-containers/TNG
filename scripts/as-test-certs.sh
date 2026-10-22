#!/usr/bin/env bash
# Generate the signing chain for the test Attestation Service into /tmp:
# as-ca.pem (CA), as.pem (leaf), as-full.pem (leaf + CA bundle) and as.key.
# The e2e CoCo unit tests pin /tmp/as-full.pem as their trust root and the AS
# signs tokens with the leaf. Shared by test-dep-as (OpenAnolis trustee RPM)
# and test-dep-as-upstream (mainline confidential-containers/trustee), so
# both AS flavors present the same trust-root layout to the tests.
set -euo pipefail

openssl ecparam -genkey -name prime256v1 -out /tmp/as-ca.key
openssl req -x509 -sha256 -nodes -days 365 -key /tmp/as-ca.key -out /tmp/as-ca.pem -subj "/O=Trustee CA" -addext keyUsage=critical,cRLSign,keyCertSign,digitalSignature
openssl ecparam -genkey -name prime256v1 -noout -out /tmp/as.key
openssl req -new -key /tmp/as.key -out /tmp/as.csr -subj "/CN=Trustee/O=Trustee CA"
echo '[v3_req]' > /tmp/as-ext.cnf
echo 'subjectKeyIdentifier = hash' >> /tmp/as-ext.cnf
openssl x509 -req -in /tmp/as.csr -CA /tmp/as-ca.pem -CAkey /tmp/as-ca.key -CAcreateserial -out /tmp/as.pem -days 365 -extensions v3_req -extfile /tmp/as-ext.cnf -sha256
cat /tmp/as.pem /tmp/as-ca.pem > /tmp/as-full.pem
