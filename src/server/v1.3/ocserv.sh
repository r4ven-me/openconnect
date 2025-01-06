#!/bin/bash

# Some protection
set -Eeuo pipefail

# Define default server vars if they are not set
SRV_CN="${SRV_CN:=example.com}" 
SRV_CA="${SRV_CA:=Example CA}"

# Ocserv vars (do not modify)
OCSERV_DIR="/etc/ocserv"
CERTS_DIR="${OCSERV_DIR}/certs"
SSL_DIR="${OCSERV_DIR}/ssl"
SECRETS_DIR="${OCSERV_DIR}/secrets"

# Start server if data files exist
if [[ -r "${OCSERV_DIR}"/ocserv.conf ]]; then
    echo "Starting OpenConnect Server"
    exec "$@" || { echo "Starting failed" >&2; exit 1; }
else
    echo "Running OpenConnect Server at first with new certs generation"
fi

# Create certs dirs
if [[ -d $OCSERV_DIR ]]; then
    for sub_dir in "${OCSERV_DIR}"/{"ssl/live/${SRV_CN}","certs","secrets"}; do
        mkdir -p "$sub_dir"
    done
    if [[ -r /usr/share/doc/ocserv/sample.config ]]; then
        cp /usr/share/doc/ocserv/sample.config "${OCSERV_DIR}"/
    fi
fi

# Create ocserv config file
cat << _EOF_ > "${OCSERV_DIR}"/ocserv.conf
auth = "certificate"
#auth = "plain[passwd=${OCSERV_DIR}/ocpasswd]"
#enable-auth = "certificate"
tcp-port = 443
socket-file = /run/ocserv-socket
server-cert = ${SSL_DIR}/live/${SRV_CN}/fullchain.pem
server-key = ${SSL_DIR}/live/${SRV_CN}/privkey.pem
ca-cert = ${CERTS_DIR}/ca-cert.pem
isolate-workers = true
max-clients = 20
max-same-clients = 2
rate-limit-ms = 200
server-stats-reset-time = 604800
keepalive = 10
dpd = 120
mobile-dpd = 1800
switch-to-tcp-timeout = 25
try-mtu-discovery = false
cert-user-oid = 0.9.2342.19200300.100.1.1
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-TLS1.3"
auth-timeout = 1000
min-reauth-time = 300
max-ban-score = 100
ban-reset-time = 1200
cookie-timeout = 600
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
connect-script = ${OCSERV_DIR}/connect.sh
disconnect-script = ${OCSERV_DIR}/disconnect.sh
use-occtl = true
pid-file = /run/ocserv.pid
log-level = 1
device = vpns
predictable-ips = true
default-domain = $SRV_CN
ipv4-network = 10.10.10.0
ipv4-netmask = 255.255.255.0
tunnel-all-dns = true
dns = 8.8.8.8
ping-leases = false
config-per-user = ${OCSERV_DIR}/config-per-user/
cisco-client-compat = true
dtls-legacy = true
client-bypass-protocol = false
crl = /etc/ocserv/certs/crl.pem
_EOF_

# Create template for CA SSL cert
cat << _EOF_ > "${CERTS_DIR}"/ca.tmpl
organization = $SRV_CN
cn = $SRV_CA
serial = 001
expiration_days = -1
ca
signing_key
cert_signing_key
crl_signing_key
_EOF_

# Create template for users SSL certs
cat << _EOF_ > "${CERTS_DIR}"/users.cfg
organization = $SRV_CN
cn = Example User
uid = exampleuser
expiration_days = -1
tls_www_client
signing_key
encryption_key
_EOF_

# Create template for server self-signed SSL cert
cat << _EOF_ > "${SSL_DIR}"/server.tmpl
cn = $SRV_CA
dns_name = $SRV_CN
organization = $SRV_CN
expiration_days = -1
signing_key
encryption_key #only if the generated key is an RSA one
tls_www_server
_EOF_

# Generate empty revoke file
cat << _EOF_ > "${CERTS_DIR}"/crl.tmpl
crl_next_update = 365
crl_number = 1
_EOF_

# Create connect script which runs for every user connection
cat << _EOF_ > "${OCSERV_DIR}"/connect.sh && chmod +x "${OCSERV_DIR}"/connect.sh
#!/bin/bash

set -Eeuo pipefail

echo "\$(date) User \${USERNAME} Connected - Server: \${IP_REAL_LOCAL} VPN IP: \${IP_REMOTE}  Remote IP: \${IP_REAL} Device:\${DEVICE}"
echo "Running iptables MASQUERADE for User \${USERNAME} connected with VPN IP \${IP_REMOTE}"
iptables -t nat  -A POSTROUTING -s \${IP_REMOTE}/32 -o eth0 -j MASQUERADE
_EOF_

# Create disconnect script which runs for every user disconnection
cat << _EOF_ > "${OCSERV_DIR}"/disconnect.sh && chmod +x "${OCSERV_DIR}"/disconnect.sh
#!/bin/bash

set -Eeuo pipefail

echo "\$(date) User \${USERNAME} Disconnected - Bytes In: \${STATS_BYTES_IN} Bytes Out: \${STATS_BYTES_OUT} Duration:\${STATS_DURATION}"
_EOF_

# Create script to create new users
cat << _EOF_ > "${OCSERV_DIR}"/ocuser && chmod +x "${OCSERV_DIR}"/ocuser
#!/bin/bash

set -Eeuo pipefail

# Check and set script params
if [[ \$# -eq 2 ]]; then
    USER_UID="\$1"
    USER_CN="\$2"
elif [[ \$# -eq 3 ]]; then
	if [[ "\$1" == "-A" ]]; then
    		USER_UID="\$2"
    		USER_CN="\$3"
	else
		echo "Use -A key as a first param to generate cert for IOS devices" >&2
        exit 1
	fi
else
    echo "Please run script with two params: username and 'Common Username'" >&2
    echo "Example: ocuser john 'John Doe'" >&2
    echo "For IOS or HarmonyOS devices add -A key as first param in command" >&2
    echo "Example: ocuser -A steve 'Steve Jobs'" >&2
    exit 1
fi

# Modify user cert template and generate user key, cert and protected .p12 file
sed -i -e "s/^organization.*/organization = \$SRV_CN/" -e "s/^cn.*/cn = \$USER_CN/" -e "s/^uid.*/uid = \$USER_UID/g" "\${CERTS_DIR}"/users.cfg
echo "\$(tr -cd "[:alnum:]" < /dev/urandom | head -c 60)" | ocpasswd -c "\${OCSERV_DIR}"/ocpasswd "\$USER_UID"
certtool --generate-privkey --outfile "\${CERTS_DIR}"/"\${USER_UID}"-privkey.pem
certtool --generate-certificate --load-privkey "\${CERTS_DIR}"/"\${USER_UID}"-privkey.pem --load-ca-certificate "\${CERTS_DIR}"/ca-cert.pem --load-ca-privkey "\${CERTS_DIR}"/ca-key.pem --template "\${CERTS_DIR}"/users.cfg --outfile "\${CERTS_DIR}"/"\${USER_UID}"-cert.pem
if [[ "\$1" == "-A" ]]; then
	sleep 1 && certtool --to-p12 --load-certificate "\${CERTS_DIR}"/"\${USER_UID}"-cert.pem --load-privkey "\${CERTS_DIR}"/"\${USER_UID}"-privkey.pem --pkcs-cipher 3des-pkcs12 --hash SHA1 --outder --outfile "\${SECRETS_DIR}"/"\${USER_UID}".p12
else
	sleep 1 && certtool --load-certificate "\${CERTS_DIR}"/"\${USER_UID}"-cert.pem --load-privkey "\${CERTS_DIR}"/"\${USER_UID}"-privkey.pem --pkcs-cipher aes-256 --to-p12 --outder --outfile "\${SECRETS_DIR}"/"\${USER_UID}".p12
fi
_EOF_

# Add revoke script
cat << _EOF_ > "${OCSERV_DIR}"/ocrevoke && chmod +x "${OCSERV_DIR}"/ocrevoke
#!/bin/bash

set -Eeuo pipefail

if [[ ! -e "\${CERTS_DIR}"/crl.tmpl ]]; then
cat << __EOF__ > "\${CERTS_DIR}"/crl.tmpl
crl_next_update = 365
crl_number = 1
__EOF__
fi

if [[ \$# -eq 1 ]]; then
    if [[ "\$1" == "HELP" ]]; then
        echo "Usage:
        CMD to revoke cert of some user: ocrevoke <exist_user> 
        CMD to apply current revoked.pem: ocrevoke RELOAD
        CMD to reset all revokes: ocrevoke RESET
        CMD to print this help: ocrevoke HELP"
    elif [[ "\$1" == "RESET" ]]; then
        certtool --generate-crl --load-ca-privkey "\${CERTS_DIR}"/ca-key.pem --load-ca-certificate "\${CERTS_DIR}"/ca-cert.pem --template "\${CERTS_DIR}"/crl.tmpl --outfile "\${CERTS_DIR}"/crl.pem
        occtl reload
    elif [[ "\$1" == "RELOAD" ]]; then
        certtool --generate-crl --load-ca-privkey "\${CERTS_DIR}"/ca-key.pem --load-ca-certificate "\${CERTS_DIR}"/ca-cert.pem --load-certificate "\${CERTS_DIR}"/revoked.pem --template "\${CERTS_DIR}"/crl.tmpl --outfile "\${CERTS_DIR}"/crl.pem
    else
        USER_UID="\$1"
        cat "\${CERTS_DIR}"/"\${USER_UID}"-cert.pem >> "\${CERTS_DIR}"/revoked.pem
        certtool --generate-crl --load-ca-privkey "\${CERTS_DIR}"/ca-key.pem --load-ca-certificate "\${CERTS_DIR}"/ca-cert.pem --load-certificate "\${CERTS_DIR}"/revoked.pem --template "\${CERTS_DIR}"/crl.tmpl --outfile "\${CERTS_DIR}"/crl.pem
        occtl reload
    fi
else
    echo "Usage:
    CMD to revoke cert of some user: ocrevoke <exist_user> 
    CMD to apply current revoked.pem: ocrevoke RELOAD
    CMD to reset all revokes: ocrevoke RESET
    CMD to print this help: ocrevoke HELP"
fi
_EOF_

# Server certificates generation
certtool --generate-privkey --outfile "${CERTS_DIR}"/ca-key.pem
certtool --generate-self-signed --load-privkey "${CERTS_DIR}"/ca-key.pem --template "${CERTS_DIR}"/ca.tmpl --outfile "${CERTS_DIR}"/ca-cert.pem
certtool --generate-crl --load-ca-privkey "${CERTS_DIR}"/ca-key.pem --load-ca-certificate "${CERTS_DIR}"/ca-cert.pem --template "${CERTS_DIR}"/crl.tmpl --outfile "${CERTS_DIR}"/crl.pem
if [[ ! -e  "${SSL_DIR}"/live/"${SRV_CN}"/privkey.pem && ! -e "${SSL_DIR}"/live/"${SRV_CN}"/fullchain.pem ]]; then
    certtool --generate-privkey --outfile "${SSL_DIR}"/live/"${SRV_CN}"/privkey.pem
    certtool --generate-certificate --load-privkey "${SSL_DIR}"/live/"${SRV_CN}"/privkey.pem --load-ca-certificate "${CERTS_DIR}"/ca-cert.pem --load-ca-privkey "${CERTS_DIR}"/ca-key.pem --template "${SSL_DIR}"/server.tmpl --outfile "${SSL_DIR}"/live/"${SRV_CN}"/fullchain.pem
fi

# Start ocserv service
echo "Starting OpenConnect Server"
exec "$@" || { echo "Starting failed" >&2; exit 1; }