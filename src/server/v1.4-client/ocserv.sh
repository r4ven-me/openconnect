#!/usr/bin/env bash

# Some protection
set -Eeuo pipefail

# Define default server vars if they are not set

# Ocserv
SRV_CN="${SRV_CN:=example.com}" 
SRV_CA="${SRV_CA:=Example CA}"
IPV4_NET="${IPV4_NET:=10.10.10.0}"
IPV4_MASK="${IPV4_MASK:=255.255.255.0}"
DNS1="${DNS1:=8.8.8.8}"
DNS2="${DNS2:=8.8.4.4}"
CAMOUFLAGE="${CAMOUFLAGE:=false}"
CAMOUFLAGE_SECRET="${CAMOUFLAGE_SECRET:=secretword}"
CAMOUFLAGE_REALM="${CAMOUFLAGE_REALM:=Welcome to admin panel}"

# OTP
OTP_ENABLE="${OTP_ENABLE:=false}"
OTP_SEND_BY_EMAIL="${OTP_SEND_BY_EMAIL:=false}"
OTP_SEND_BY_TELEGRAM="${OTP_SEND_BY_TELEGRAM:=false}"
MSMTP_HOST="${MSMTP_HOST:=smtp.example.com}"
MSMTP_PORT="${MSMTP_PORT:=465}"
MSMTP_USER="${MSMTP_USER:=mail@example.com}"
MSMTP_PASSWORD="${MSMTP_PASSWORD:=PaSsw0rD}"
MSMTP_FROM="${MSMTP_FROM:=mail@example.com}"
TG_TOKEN="${TG_TOKEN:=1234567890:QWERTYuio-PA1DFGHJ2_KlzxcVBNmqWEr3t}"

# Ocserv vars (do not modify)
OCSERV_DIR="/etc/ocserv"
CERTS_DIR="${OCSERV_DIR}/certs"
SSL_DIR="${OCSERV_DIR}/ssl"
SECRETS_DIR="${OCSERV_DIR}/secrets"
SCRIPTS_DIR="${OCSERV_DIR}/scripts"

# Occlient
OCCLIENT_ENABLE="${OCCLIENT_ENABLE:=false}"
OCCLIENT_TYPE="${OCCLIENT_TYPE:=dcoker}"

# Dnsmasq
DNSMASQ_ENABLE="${DNSMASQ_ENABLE:=false}"
DNSMASQ_TUNNEL_DNS="${DNSMASQ_TUNNEL_DNS:=flase}"

# Create certs dirs
for sub_dir in "${OCSERV_DIR}"/{"ssl/live/${SRV_CN}","certs","secrets","scripts","config-per-user"}; do
    if [[ ! -d "$sub_dir" ]]; then
        mkdir -p "$sub_dir"
    fi
done

for example_file in ocserv.conf_example env_example; do
    if [[ -r /usr/share/doc/ocserv/"${example_file}" && ! -e "${OCSERV_DIR}"/"${example_file}" ]]; then
        cp /usr/share/doc/ocserv/"${example_file}" "${OCSERV_DIR}"/
    fi
done

# Create ocserv config file
if [[ ! -e "${OCSERV_DIR}"/ocserv.conf ]]; then
cat << _EOF_ > "${OCSERV_DIR}"/ocserv.conf
auth = "certificate"
#auth = "plain[passwd=${OCSERV_DIR}/ocpasswd]"
#auth = "plain[passwd=/etc/ocserv/ocpasswd,otp=/etc/ocserv/secrets/users.oath]"
#enable-auth = "certificate"
#enable-auth = "pam"
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
connect-script = ${SCRIPTS_DIR}/connect
disconnect-script = ${SCRIPTS_DIR}/disconnect
use-occtl = true
pid-file = /run/ocserv.pid
log-level = 1
#   0 default (Same as info)
#   1 basic
#   2 info
#   3 debug
#   4 http
#   8 sensitive
#   9 TLS
device = vpns
predictable-ips = true
default-domain = $SRV_CN
ipv4-network = $IPV4_NET
ipv4-netmask = $IPV4_MASK
tunnel-all-dns = true
dns = $DNS1
dns = $DNS2
ping-leases = false
config-per-user = ${OCSERV_DIR}/config-per-user/
cisco-client-compat = true
dtls-legacy = true
client-bypass-protocol = false
crl = /etc/ocserv/certs/crl.pem
camouflage = $CAMOUFLAGE
camouflage_secret = "$CAMOUFLAGE_SECRET"
camouflage_realm = "$CAMOUFLAGE_REALM"
_EOF_
fi

# Create template for CA SSL cert
if [[ ! -e "${CERTS_DIR}"/ca.tmpl ]]; then
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
fi

# Create template for users SSL certs
if [[ ! -e "${CERTS_DIR}"/users.cfg ]]; then
cat << _EOF_ > "${CERTS_DIR}"/users.cfg
organization = $SRV_CN
cn = Example User
uid = exampleuser
expiration_days = -1
tls_www_client
signing_key
encryption_key
_EOF_
fi

# Create template for server self-signed SSL cert
if [[ ! -e "${SSL_DIR}"/server.tmpl ]]; then
cat << _EOF_ > "${SSL_DIR}"/server.tmpl
cn = $SRV_CA
dns_name = $SRV_CN
organization = $SRV_CN
expiration_days = -1
signing_key
encryption_key #only if the generated key is an RSA one
tls_www_server
_EOF_
fi

# Generate empty revoke file
if [[ ! -e "${CERTS_DIR}"/crl.tmpl ]]; then
cat << _EOF_ > "${CERTS_DIR}"/crl.tmpl
crl_next_update = 365
crl_number = 1
_EOF_
fi

# Create connect script which runs for every user connection
if [[ ! -e "${SCRIPTS_DIR}"/connect ]]; then
cat << '_EOF_' > "${SCRIPTS_DIR}"/connect && chmod +x "${SCRIPTS_DIR}"/connect
#!/usr/bin/env bash

set -Eeuo pipefail

MAIN_IFACE=$(ip route | awk '/default/ {print $5; exit}')

echo "$(date) User ${USERNAME} Connected - Server: ${IP_REAL_LOCAL} VPN IP: ${IP_REMOTE}  Remote IP: ${IP_REAL} Device:${DEVICE}"
echo "Running nftables MASQUERADE for User ${USERNAME} connected with VPN IP ${IP_REMOTE}"

if [[ "$OCCLIENT_ENABLE" == "true" ]] && ip link show "$OCCLIENT_IFACE" &> /dev/null; then
    if [[ "$DNSMASQ_ENABLE" != "true" ]]; then
        ip rule add from "${IP_REMOTE}"/32 table 430 || true
        nft add rule ip oc_nat POSTROUTING ip saddr "${IP_REMOTE}"/32 oifname "$OCCLIENT_IFACE" counter masquerade comment "masq-${IP_REMOTE}" || true
    else
        nft add rule ip oc_nat POSTROUTING ip saddr "${IP_REMOTE}"/32 oifname "$MAIN_IFACE" counter masquerade comment "masq-${IP_REMOTE}" || true
    fi
else
    nft add rule ip oc_nat POSTROUTING ip saddr "${IP_REMOTE}"/32 oifname "$MAIN_IFACE" counter masquerade comment "masq-${IP_REMOTE}" || true
fi
_EOF_
fi

# Create disconnect script which runs for every user disconnection
if [[ ! -e "${SCRIPTS_DIR}"/disconnect ]]; then
cat << '_EOF_' > "${SCRIPTS_DIR}"/disconnect && chmod +x "${SCRIPTS_DIR}"/disconnect
#!/usr/bin/env bash

set -Eeuo pipefail

echo "$(date) User ${USERNAME} Disconnected - Bytes In: ${STATS_BYTES_IN} Bytes Out: ${STATS_BYTES_OUT} Duration:${STATS_DURATION}"

# Delete the exact MASQUERADE rule by comment
if [[ -n "${IP_REMOTE}" ]]; then
    handles=($(nft -a list chain ip oc_nat POSTROUTING 2>/dev/null \
    | grep "comment \"masq-${IP_REMOTE}\"" \
    | grep -o 'handle [0-9]*' \
    | awk '{print $2}'))

    if (( ${#handles[@]} )); then
        for rule in "${handles[@]}"; do
            nft delete rule ip oc_nat POSTROUTING handle "$rule" 2>/dev/null || true
        done
    fi
fi

if [[ "$OCCLIENT_ENABLE" == "true" ]] && ip link show "$OCCLIENT_IFACE" &> /dev/null; then
    if [[ "$DNSMASQ_ENABLE" != "true" ]]; then
        while ip rule del from "${IP_REMOTE}"/32 table 430 &> /dev/null; do sleep 2; done
    fi
fi
_EOF_
fi

# Create script to create new users
if [[ ! -e "${SCRIPTS_DIR}"/ocuser ]]; then
cat << '_EOF_' > "${SCRIPTS_DIR}"/ocuser && chmod +x "${SCRIPTS_DIR}"/ocuser
#!/usr/bin/env bash

set -Eeuo pipefail

# Check and set script params
if [[ $# -eq 2 ]]; then
    USER_UID="$1"
    USER_CN="$2"
elif [[ $# -eq 3 ]]; then
	if [[ "$1" == "-A" ]]; then
    		USER_UID="$2"
    		USER_CN="$3"
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
sed -i -e "s/^organization.*/organization = $SRV_CN/" -e "s/^cn.*/cn = $USER_CN/" -e "s/^uid.*/uid = $USER_UID/g" "${CERTS_DIR}"/users.cfg
echo "$(tr -cd "[:alnum:]" < /dev/urandom | head -c 60)" | ocpasswd -c "${OCSERV_DIR}"/ocpasswd "$USER_UID"
certtool --generate-privkey --outfile "${CERTS_DIR}"/"${USER_UID}"-privkey.pem
certtool --generate-certificate --load-privkey "${CERTS_DIR}"/"${USER_UID}"-privkey.pem --load-ca-certificate "${CERTS_DIR}"/ca-cert.pem --load-ca-privkey "${CERTS_DIR}"/ca-key.pem --template "${CERTS_DIR}"/users.cfg --outfile "${CERTS_DIR}"/"${USER_UID}"-cert.pem
if [[ "$1" == "-A" ]]; then
	sleep 1 && certtool --to-p12 --load-certificate "${CERTS_DIR}"/"${USER_UID}"-cert.pem --load-privkey "${CERTS_DIR}"/"${USER_UID}"-privkey.pem --pkcs-cipher 3des-pkcs12 --hash SHA1 --outder --outfile "${SECRETS_DIR}"/"${USER_UID}".p12
else
	sleep 1 && certtool --load-certificate "${CERTS_DIR}"/"${USER_UID}"-cert.pem --load-privkey "${CERTS_DIR}"/"${USER_UID}"-privkey.pem --pkcs-cipher aes-256 --to-p12 --outder --outfile "${SECRETS_DIR}"/"${USER_UID}".p12
fi
_EOF_
fi

# Add revoke script
if [[ ! -e "${SCRIPTS_DIR}"/ocrevoke ]]; then
cat << '_EOF_' > "${SCRIPTS_DIR}"/ocrevoke && chmod +x "${SCRIPTS_DIR}"/ocrevoke
#!/usr/bin/env bash

set -Eeuo pipefail

if [[ ! -e "${CERTS_DIR}"/crl.tmpl ]]; then
cat << __EOF__ > "${CERTS_DIR}"/crl.tmpl
crl_next_update = 365
crl_number = 1
__EOF__
fi

if [[ $# -eq 1 ]]; then
    if [[ "$1" == "HELP" ]]; then
        echo "Usage:
        CMD to revoke cert of some user: ocrevoke <exist_user> 
        CMD to apply current revoked.pem: ocrevoke RELOAD
        CMD to reset all revokes: ocrevoke RESET
        CMD to print this help: ocrevoke HELP"
    elif [[ "$1" == "RESET" ]]; then
        certtool --generate-crl --load-ca-privkey "${CERTS_DIR}"/ca-key.pem --load-ca-certificate "${CERTS_DIR}"/ca-cert.pem --template "${CERTS_DIR}"/crl.tmpl --outfile "${CERTS_DIR}"/crl.pem
        occtl reload
    elif [[ "$1" == "RELOAD" ]]; then
        certtool --generate-crl --load-ca-privkey "${CERTS_DIR}"/ca-key.pem --load-ca-certificate "${CERTS_DIR}"/ca-cert.pem --load-certificate "${CERTS_DIR}"/revoked.pem --template "${CERTS_DIR}"/crl.tmpl --outfile "${CERTS_DIR}"/crl.pem
    else
        USER_UID="$1"
        cat "${CERTS_DIR}"/"${USER_UID}"-cert.pem >> "${CERTS_DIR}"/revoked.pem
        certtool --generate-crl --load-ca-privkey "${CERTS_DIR}"/ca-key.pem --load-ca-certificate "${CERTS_DIR}"/ca-cert.pem --load-certificate "${CERTS_DIR}"/revoked.pem --template "${CERTS_DIR}"/crl.tmpl --outfile "${CERTS_DIR}"/crl.pem
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
fi

# Add ocuser2fa script
if [[ "$OTP_ENABLE" == "true" && ! -e "${SCRIPTS_DIR}"/ocuser2fa ]]; then
cat << '_EOF_' > "${SCRIPTS_DIR}"/ocuser2fa && chmod +x "${SCRIPTS_DIR}"/ocuser2fa
#!/usr/bin/env bash

set -Eeuo pipefail

if [[ $# -eq 1 ]]; then
    USER_ID="$1"
    OTP_SECRET="$(head -c 16 /dev/urandom | xxd -c 256 -ps)"
    OTP_SECRET_BASE32="$(echo 0x"${OTP_SECRET}" | xxd -r -c 256 | base32)"
    OTP_SECRET_QR="otpauth://totp/$USER_ID?secret=$OTP_SECRET_BASE32&issuer=$SRV_CA&algorithm=SHA1&digits=6&period=30"

    if [[ ! -e "${SECRETS_DIR}"/users.oath ]] || ! grep -qP "(?<!\\S)${USER_ID}(?!\\S)" "${SECRETS_DIR}"/users.oath; then
        echo "HOTP/T30 $USER_ID - $OTP_SECRET" >> "${SECRETS_DIR}"/users.oath
        echo "OTP secret for $USER_ID: $OTP_SECRET"
        echo "OTP secret in base32: $OTP_SECRET_BASE32"
        echo "OTP secret in QR code:"
        qrencode -t ANSIUTF8 "$OTP_SECRET_QR"
        qrencode "$OTP_SECRET_QR" -s 10 -o "${SECRETS_DIR}"/otp_"${USER_ID}".png
        echo "TOTP secret in png image saved at: ${SECRETS_DIR}/otp_${USER_ID}.png"

        send_qr_by_email() {
            EMAIL_REGEX="^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"

            if [[ $USER_ID =~ $EMAIL_REGEX ]]; then
                cat << EOF | msmtp --file="${SCRIPTS_DIR}"/msmtprc "$USER_ID"
Subject: TOTP QR code for OpenConnect auth
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary"

--boundary
Content-Type: text/plain

TOTP secret for OpenConnect (base32):
$OTP_SECRET_BASE32

--boundary
Content-Type: image/png; name="file.png"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="file.png"

$(base64 "${SECRETS_DIR}"/otp_"${USER_ID}".png)
--boundary--
EOF
                echo "[$(date '+%F %T')] - TOTP secret and QR code successfully sent to $USER_ID via Email" | tee -a "${OCSERV_DIR}"/pam.log
            else
                return 0
            fi
        }

        if [[ "$OTP_SEND_BY_EMAIL" == "true" ]]; then send_qr_by_email; fi

        send_qr_by_telegram() {
            TG_REGEX="^[a-zA-Z][a-zA-Z0-9_]{4,31}$"

            if [[ $USER_ID =~ $TG_REGEX ]]; then
                TG_MESSAGE="TOTP secret for OpenConnect (base32):
$OTP_SECRET_BASE32"
                TG_USER_FILE="${SCRIPTS_DIR}/tg_users.txt"
                
                if grep -qP "(?<!\\S)${USER_ID}(?!\\S)" "$TG_USER_FILE" 2> /dev/null; then
                    TG_CHAT_ID=$(grep -P "(?<!\\S)${USER_ID}(?!\\S)" "$TG_USER_FILE" | awk '{print $1}')
                else
                    TG_RESPONSE="$(curl -s "https://api.telegram.org/bot${TG_TOKEN}/getUpdates")"
                    TG_CHAT_ID=$(echo "$TG_RESPONSE" | jq -r --arg USERNAME "$USER_ID" '.result[] | select(.message.from.username == $USERNAME) | .message.chat.id')

                    if [[ -z "$TG_CHAT_ID" ]]; then
                        echo "[$(date '+%F %T')] - User was not found or did not interact with the bot" >> "${OCSERV_DIR}"/pam.log
                        return 0
                    fi
                    echo "$TG_CHAT_ID $USER_ID" >> "$TG_USER_FILE"
                fi

                curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendPhoto" \\
                    -H "Content-Type: multipart/form-data" \\
                    -F "chat_id=$TG_CHAT_ID" \\
                    -F "photo=@${SECRETS_DIR}/otp_${USER_ID}.png" \\
                    -F "caption=$TG_MESSAGE" > /dev/null 2>> "${OCSERV_DIR}"/pam.log

                echo "[$(date '+%F %T')] - TOTP secret and QR code successfully sent to $USER_ID via Telegram" | tee -a "${OCSERV_DIR}"/pam.log
            fi
        }

        if [[ "$OTP_SEND_BY_TELEGRAM" == "true" ]]; then send_qr_by_telegram; fi

    else
        echo "OTP token already exists for $USER_ID in ${SECRETS_DIR}/users.oath"
        exit 1
    fi
else
    echo "Usage: $(basename "$0") <user_id>"
    exit 1
fi
_EOF_
fi

if [[ "$OTP_ENABLE" == "true" && ! -e "${SCRIPTS_DIR}"/otp_sender ]]; then
cat << _EOF_ > "${SCRIPTS_DIR}"/otp_sender && chmod +x "${SCRIPTS_DIR}"/otp_sender
#!/usr/bin/env bash

set -Eeuo pipefail

OCSERV_DIR="$OCSERV_DIR"
SECRETS_DIR="$SECRETS_DIR"
SCRIPTS_DIR="$SCRIPTS_DIR"
OTP_SEND_BY_EMAIL="$OTP_SEND_BY_EMAIL"
OTP_SEND_BY_TELEGRAM="$OTP_SEND_BY_TELEGRAM"
TG_TOKEN="$TG_TOKEN"

echo "[\$(date '+%F %T')] - PAM user \$PAM_USER is trying to connect to ocserv" >> "\${OCSERV_DIR}"/pam.log

otp_sender_by_email() {
    EMAIL_REGEX="^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    if [[ \$PAM_USER =~ \$EMAIL_REGEX ]]; then true; else return 0; fi

    if [[ -e "\${SECRETS_DIR}"/users.oath ]] && grep -qP "(?<!\\S)\${PAM_USER}(?!\\S)" "\${SECRETS_DIR}"/users.oath; then
        OTP_TOKEN="\$(oathtool --totp=SHA1 --time-step-size=30 --digits=6 \$(grep -P "(?<!\\S)\${PAM_USER}(?!\\S)" \${SECRETS_DIR}/users.oath | awk '{print \$4}'))"

        echo -e "Subject: TOTP token for OpenConnect\n\n\${OTP_TOKEN}" | msmtp --file="\${SCRIPTS_DIR}"/msmtprc "\$PAM_USER"
        echo "[\$(date '+%F %T')] - TOTP token successfully sent to \$PAM_USER" >> "\${OCSERV_DIR}"/pam.log
    fi
}

otp_sender_by_telegram() {
    TG_REGEX="^[a-zA-Z][a-zA-Z0-9_]{4,31}\$"
    if [[ \$PAM_USER =~ \$TG_REGEX ]]; then true; else return 0; fi

    if grep -qP "(?<!\\S)\${PAM_USER}(?!\\S)" "\${SECRETS_DIR}"/users.oath 2> /dev/null; then
        OTP_TOKEN="\$(oathtool --totp=SHA1 --time-step-size=30 --digits=6 \$(grep -P "(?<!\\S)\${PAM_USER}(?!\\S)" \${SECRETS_DIR}/users.oath | awk '{print \$4}'))"
        TG_MESSAGE="TOTP token for OpenConnect: \$OTP_TOKEN"
        TG_USER_FILE="\${SCRIPTS_DIR}/tg_users.txt"
        
        if grep -qP "(?<!\\S)\$PAM_USER(?!\\S)" "\$TG_USER_FILE"; then
            TG_CHAT_ID=\$(grep -P "(?<!\\S)\${PAM_USER}(?!\\S)" "\$TG_USER_FILE" | awk '{print \$1}')
        else
            TG_RESPONSE="\$(curl -s "https://api.telegram.org/bot\$TG_TOKEN/getUpdates")"
            TG_CHAT_ID=\$(echo "\$TG_RESPONSE" | jq -r --arg USERNAME "\$PAM_USER" '.result[] | select(.message.from.username == \$USERNAME) | .message.chat.id')
    
            if [[ -z "\$TG_CHAT_ID" ]]; then
                echo "[\$(date '+%F %T')] - User was not found or did not interact with the bot" >> "\${OCSERV_DIR}"/pam.log
                return 0
            fi
            echo "\$TG_CHAT_ID \$PAM_USER" >> "\$TG_USER_FILE"
        fi  
        
        curl -s -X POST "https://api.telegram.org/bot\$TG_TOKEN/sendMessage" -d "chat_id=\$TG_CHAT_ID" -d "text=\$TG_MESSAGE" 2>> "\${OCSERV_DIR}"/pam.log
        echo "[\$(date '+%F %T')] - TOTP token successfully sent to \$PAM_USER" >> "\${OCSERV_DIR}"/pam.log
    fi
}

if [[ "\$OTP_SEND_BY_EMAIL" == "true" ]]; then otp_sender_by_email; fi &

if [[ "\$OTP_SEND_BY_TELEGRAM" == "true" ]]; then otp_sender_by_telegram; fi &
_EOF_
elif [[ "$OTP_ENABLE" == "true" && -e "${SCRIPTS_DIR}"/otp_sender ]]; then
    sed -i "s|OCSERV_DIR=.*|OCSERV_DIR=\"$OCSERV_DIR\"|" "${SCRIPTS_DIR}"/otp_sender
    sed -i "s|SECRETS_DIR=.*|SECRETS_DIR=\"$SECRETS_DIR\"|" "${SCRIPTS_DIR}"/otp_sender
    sed -i "s|SCRIPTS_DIR=.*|SCRIPTS_DIR=\"$SCRIPTS_DIR\"|" "${SCRIPTS_DIR}"/otp_sender
    sed -i "s|OTP_SEND_BY_EMAIL=.*|OTP_SEND_BY_EMAIL=\"$OTP_SEND_BY_EMAIL\"|" "${SCRIPTS_DIR}"/otp_sender
    sed -i "s|OTP_SEND_BY_TELEGRAM=.*|OTP_SEND_BY_TELEGRAM=\"$OTP_SEND_BY_TELEGRAM\"|" "${SCRIPTS_DIR}"/otp_sender
    sed -i "s|TG_TOKEN=.*|TG_TOKEN=\"$TG_TOKEN\"|" "${SCRIPTS_DIR}"/otp_sender
fi

# Add msmtprc config
if [[ "$OTP_ENABLE" == "true" && "$OTP_SEND_BY_EMAIL" == "true" && ! -e "${OCSERV_DIR}"/msmtprc ]]; then
cat << _EOF_ > "${SCRIPTS_DIR}"/msmtprc && chmod 400 "${SCRIPTS_DIR}"/msmtprc
account default
host $MSMTP_HOST
port $MSMTP_PORT
auth on
user $MSMTP_USER
password $MSMTP_PASSWORD
from $MSMTP_FROM
tls on
tls_starttls off
logfile $OCSERV_DIR/pam.log
_EOF_
fi

# Config OTP with PAM
pam_otp() {
    if [[ "$OTP_ENABLE" == "true" ]]; then
        until [[ -e /etc/pam.d/ocserv ]]; do sleep 5; done
        if grep -q 'otp_sender' /etc/pam.d/ocserv && grep -q 'users.oath' /etc/pam.d/ocserv; then return 0; fi
        sleep 3
        echo "auth optional pam_exec.so ${SCRIPTS_DIR}/otp_sender" >> /etc/pam.d/ocserv
        echo "auth requisite pam_oath.so debug usersfile=${SECRETS_DIR}/users.oath window=20" >> /etc/pam.d/ocserv
    fi
}

# Configure nftables for OpenConnect client and Dnsmasq
prepare_nft() {
    echo "Configure tables and chains..."

    if ! nft list table ip oc_nat &> /dev/null; then
        nft add table ip oc_nat
    fi

    if ! nft list set ip oc_nat oc_set &> /dev/null; then
        nft add set ip oc_nat oc_set '{ type ipv4_addr; flags timeout; timeout 86400s; }'
    fi

    if ! nft list chain ip oc_nat PREROUTING &> /dev/null; then
        nft add chain ip oc_nat PREROUTING '{ type filter hook prerouting priority -100; policy accept; }'
    fi

    if ! nft list chain ip oc_nat FORWARD &> /dev/null; then
        nft add chain ip oc_nat FORWARD '{ type filter hook forward priority -1; policy accept; }'
    fi

    if ! nft list chain ip oc_nat OUTPUT &> /dev/null; then
        nft add chain ip oc_nat OUTPUT '{ type filter hook output priority -200; policy accept; }'
    fi

    if ! nft list chain ip oc_nat POSTROUTING &> /dev/null; then
        nft add chain ip oc_nat POSTROUTING '{ type nat hook postrouting priority 100; policy accept; }'
    fi
}

# Setup OpenConnect client
if [[ "$OCCLIENT_ENABLE" == "true" && ! -e "${SCRIPTS_DIR}"/occlient ]]; then
cat << '_EOF_' > "${SCRIPTS_DIR}"/occlient && chmod +x "${SCRIPTS_DIR}"/occlient
#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Error: this script must be run as root (EUID=$EUID)"
    exit 1
fi

export PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"

# ================= CONFIG =================

VPN_IFACE="${OCCLIENT_IFACE:-tun0}"
VPN_BIN="$(command -v openconnect || true)"
VPN_VPNC_SCRIPT="/usr/bin/bash -c 'CISCO_SPLIT_INC=0 INTERNAL_IP4_DNS= exec /usr/share/vpnc-scripts/vpnc-script'"

CHECK_INTERVAL="${OCCLIENT_CHECK_HOST_INTERVAL:-5}" 
CHECK_THRESHOLD="${OCCLIENT_CHECK_HOST_THRESHOLD:-3}"

CHECK_UTILS=("flock" "ping" "timeout")

# ================= LOGGING =================

log_pipe() {
    while IFS= read -r line; do
        local log_line="[occlient] $line"
        echo "$log_line"
    done
}

exec > >(log_pipe) 2>&1

# ==== MULTI VPN SUPPORT ====
VPN_COUNT="${OCCLIENT_COUNT:-1}"
CURRENT_VPN_INDEX=0

load_vpn_profile() {
    local i="$CURRENT_VPN_INDEX"
    local var

    var="OCCLIENT_${i}_SSL_FLAG";    VPN_SSL_FLAG="${!var:-true}"
    var="OCCLIENT_${i}_SERVER";      VPN_ADDRESS="${!var:-}"
    var="OCCLIENT_${i}_SERVER_PORT"; VPN_PORT="${!var:-}"
    var="OCCLIENT_${i}_CERT_FILE";   VPN_CERT_FILE="${!var:-}"
    var="OCCLIENT_${i}_CERT_PASS";   VPN_CERT_PASS="${!var:-}"
    var="OCCLIENT_${i}_CHECK_HOST";  CHECK_HOST="${!var:-}"

    [[ -n "$VPN_ADDRESS" ]] || { echo "Error: VPN_ADDRESS is empty for profile [$i]"; exit 1; }
    [[ -n "$VPN_PORT" ]]    || { echo "Error: VPN_PORT is empty for profile [$i]"; exit 1; }
    [[ -n "$CHECK_HOST" ]]  || { echo "Error: CHECK_HOST is empty for profile [$i]"; exit 1; }

    echo "Using VPN profile [$i]: server=$VPN_ADDRESS:$VPN_PORT, check_host=$CHECK_HOST"
}

next_vpn_profile() {
    (( ++CURRENT_VPN_INDEX ))

    if (( CURRENT_VPN_INDEX >= VPN_COUNT )); then
        CURRENT_VPN_INDEX=0
    fi

    load_vpn_profile
}

kill_vpn_pid() {
    if [[ -n "$VPN_PID" ]] && kill -0 "$VPN_PID" 2> /dev/null; then
        echo "Stopping previous VPN process (PID="$VPN_PID")"
        kill "$VPN_PID" 2> /dev/null || true
        wait "$VPN_PID" 2> /dev/null || true
        while ip link show "$VPN_IFACE" &> /dev/null; do sleep 2; done
        sleep 1
    fi
}

connect_cmd(){
    echo "Connecting to VPN $VPN_ADDRESS:$VPN_PORT (iface=$VPN_IFACE)..."
    
    if [[ "$VPN_SSL_FLAG" == "true" ]]; then
        echo "${VPN_CERT_PASS}" | base64 -d | "$VPN_BIN" -i "$VPN_IFACE" -s "$VPN_VPNC_SCRIPT" -c "$VPN_CERT_FILE" "${VPN_ADDRESS}:${VPN_PORT}" &
    else
        echo -e "$(echo "${VPN_CERT_PASS}" | base64 -d)\nyes" | "$VPN_BIN" -i "$VPN_IFACE" -s "$VPN_VPNC_SCRIPT" -c "$VPN_CERT_FILE" "${VPN_ADDRESS}:${VPN_PORT}" &
    fi

    VPN_PID=$!

    for _ in {1..10}; do
        if ip link show "$VPN_IFACE" &> /dev/null; then
            echo "VPN interface $VPN_IFACE is up"
            sleep 3
            if check_cmd; then
                echo "VPN $VPN_ADDRESS is up"
            fi
            return 0
        fi
        sleep 1
    done

    kill_vpn_pid
    return 1
}

connect_post_up_cmd() {
    if [[ ! -d /etc/iproute2 ]]; then
        mkdir -p /etc/iproute2/
        echo "430 oc_vpn" > /etc/iproute2/rt_tables
    else
        if ! grep -q "430 oc_vpn" /etc/iproute2/rt_tables &> /dev/null; then
            echo "430 oc_vpn" >> /etc/iproute2/rt_tables
        fi
    fi

    sleep 1

    ip route add default dev "$VPN_IFACE" table 430 || true
}

connect_post_down_cmd() {
    ip route del default dev "$VPN_IFACE" table 430 || true
}

check_cmd() {
    if
        ip link show "$VPN_IFACE" &> /dev/null && \
            timeout 6 ping -I "$VPN_IFACE" -c 1 -W 5 "$CHECK_HOST" &> /dev/null
    then
        return 0
    else
        return 1
    fi
}

reconnect_cmd() {
    kill_vpn_pid

    echo "Reconnecting to the same VPN ($VPN_ADDRESS)..."
    if connect_cmd; then
        until ip link show "$VPN_IFACE" &> /dev/null; do sleep 2; done
        connect_post_up_cmd
        sleep 3

        if check_cmd; then
            echo "VPN is actually working"
            return 0
        fi

        kill_vpn_pid

        echo "VPN connected but host $CHECK_HOST unreachable"
    fi

    echo "Switching to next VPN profile..."
    next_vpn_profile

    if connect_cmd; then
        until ip link show "$VPN_IFACE" &> /dev/null; do sleep 2; done
        connect_post_up_cmd
        sleep 3

        if check_cmd; then
            echo "Switched VPN works"
            return 0
        fi
    fi

    kill_vpn_pid

    echo "All reconnection attempts failed (VPN index=$CURRENT_VPN_INDEX)"
    return 1
}

restore_cmd() {
    echo "Connection restored (host $CHECK_HOST reachable again)"
}

# ================= CORE =================

SCRIPT_PID=$$
SCRIPT_LOCK="/tmp/occlient.lock"

cleanup() {
    trap - SIGINT SIGTERM EXIT
    connect_post_down_cmd || true
    rm -f "$SCRIPT_LOCK"
}

monitor_host() {
    local check_count=0
    local is_failed=0

    while true; do
        if check_cmd; then
            if (( is_failed )); then
                restore_cmd || true
                is_failed=0
            fi

            check_count=0
        else
            (( ++check_count ))
            echo "Health check failed ($check_count/$CHECK_THRESHOLD) for host $CHECK_HOST"

            if (( check_count >= CHECK_THRESHOLD )); then
                if (( ! is_failed )); then
                    echo "[$CHECK_HOST]: Switching to FAILED state"
                fi

                is_failed=1

                if reconnect_cmd; then
                    check_count=0
                fi
            fi
        fi

        sleep "$CHECK_INTERVAL"
    done
}

main() {
    [[ -n "$VPN_BIN" ]] || { echo "Error: openconnect not found in PATH"; exit 1; }

    for util in "${CHECK_UTILS[@]}"; do
        command -v "$util" &> /dev/null || {
            echo "Error: required utility not found: $util"
            exit 1
        }
    done

    load_vpn_profile

    if ! connect_cmd; then
        echo "Error: initial VPN connection failed ($VPN_ADDRESS)"
    fi

    connect_post_up_cmd
    sleep 3

    monitor_host
}

start_action() {
    exec 9>"$SCRIPT_LOCK"
    flock -n 9 || { echo "Instance already running (lock file: $SCRIPT_LOCK)"; exit 1; }
    echo "$SCRIPT_PID" > "$SCRIPT_LOCK"
    main
}

stop_action() {
    [[ -f "$SCRIPT_LOCK" ]] || { echo "Service is not running (no lock file found)"; return; }
    kill -TERM "$(cat "$SCRIPT_LOCK")" 2> /dev/null || true
}

status_action() {
    [[ -f "$SCRIPT_LOCK" ]] && echo "Running" || echo "Stopped"
}

trap 'cleanup' SIGINT SIGTERM EXIT

# exec > >(while read -r line; do echo "[occlient] $line"; done) 2>&1

case "${1:-}" in
    start) start_action ;;
    stop) stop_action ;;
    restart) stop_action; sleep 1; start_action ;;
    status) status_action ;;
    *) echo "Usage: $0 {start|stop|restart|status}" ;;
esac
_EOF_
fi

openconnect_client() {
    if [[ "$OCCLIENT_ENABLE" == "true" &&  -e "${SCRIPTS_DIR}"/occlient ]]; then
        if [[ -n "$OCCLIENT_0_SERVER" && -n "$OCCLIENT_0_CERT_PASS" && -n "$OCCLIENT_0_CHECK_HOST" ]]; then
            if [[ "$OCCLIENT_TYPE" == "docker" ]]; then
                until ss -tln | grep -qE '^LISTEN.*:443'; do sleep 5; done
                sleep 2
                "${SCRIPTS_DIR}"/occlient start
            elif [[ "$OCCLIENT_TYPE" == "host" ]]; then
                echo "Using openconnect client in host mode..."
            fi
        else
            echo "Some OCCLIENT_ variables is not defined"
            return 0
        fi
    fi
}

# Setup Dnsmasq
if [[ "$DNSMASQ_ENABLE" == "true" && ! -e "${SCRIPTS_DIR}"/ocdnsmasq ]]; then
cat << '_EOF_' > "${SCRIPTS_DIR}"/ocdnsmasq && chmod +x "${SCRIPTS_DIR}"/ocdnsmasq
#!/usr/bin/env bash

set -Eeuo pipefail

export PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"

VPN_IFACE="${OCCLIENT_IFACE:-tun0}"
VPN_IPV4_NET="${IPV4_NET:-}"

log_pipe() {
    while IFS= read -r line; do
        local log_line="[dnsmasq] $line"
        echo "$log_line"
    done
}

exec > >(log_pipe) 2>&1

convert_domains() {
    local list="/etc/ocserv/domains.txt"
    local conf="/etc/dnsmasq.d/oc_set.conf"
    local tmp

    tmp=$(mktemp)

    while IFS= read -r domain; do
        [[ -z "$domain" || "$domain" =~ ^# ]] && continue
        echo "nftset=/$domain/ip#oc_nat#oc_set"
    done < "$list" > "$tmp"

    mv "$tmp" "$conf"
}

update_domains() {
    local list="/etc/ocserv/domains.txt"

    [[ -e "$list" ]] || touch "$list"
    convert_domains

    while true; do
        inotifywait -e modify -e close_write -e delete_self "$list" 2> /dev/null
        sleep 0.1
        if [[ -f "$list" ]]; then
            convert_domains
            kill -TERM $(< /var/run/dnsmasq.pid) 2> /dev/null
        fi
    done
}

echo "Using VPN interface: $VPN_IFACE"

if ! ip link show "$VPN_IFACE" &> /dev/null; then
    echo "Warning: interface $VPN_IFACE not found (routes may fail)"
fi

if [[ ! -d /etc/iproute2 ]]; then mkdir -p /etc/iproute2/; fi

if ! grep -q "431 dnsmasq" /etc/iproute2/rt_tables &> /dev/null; then
    echo "431 dnsmasq" >> /etc/iproute2/rt_tables
fi

DNS_IP=$(ip -4 addr show "$VPN_IFACE" | grep -o 'inet [0-9.]*' | cut -d' ' -f2 || echo "")

if [[ -n "$DNS_IP" ]]; then
    if grep -q '^dns' "$OCSERV_DIR/ocserv.conf"; then
        sed -i "s|^dns.*=.*|dns = $DNS_IP|" "$OCSERV_DIR/ocserv.conf"
    else
        echo "dns = $DNS_IP" >> "$OCSERV_DIR/ocserv.conf"
    fi
    
    occtl reload &> /dev/null
    echo "listen-address=${DNS_IP}" > /etc/dnsmasq.conf
else
    echo "Warning: could not determine main IP on $MAIN_IFACE"
fi

echo "Configuring nftables rules..."

for chain in PREROUTING OUTPUT; do
    if ! nft list chain ip oc_nat "$chain" 2> /dev/null | grep -q "oc_set"; then
        nft add rule ip oc_nat "$chain" ip daddr @oc_set ct mark set 0x1 meta mark set ct mark
    fi
done

if ! nft list chain ip oc_nat POSTROUTING 2> /dev/null | grep -q "0x00000001"; then
    nft add rule ip oc_nat POSTROUTING meta mark 0x1 oifname "$VPN_IFACE" counter masquerade
fi

for target in saddr daddr; do
    if ! nft list chain ip oc_nat FORWARD 2> /dev/null | grep -q "$target ${VPN_IPV4_NET}/24 accept"; then
        nft add rule ip oc_nat FORWARD ip "$target" "${VPN_IPV4_NET}"/24 accept
    fi
done

if nft list table ip filter &> /dev/null; then
    for target in saddr daddr; do
        if ! nft list chain ip filter DOCKER-USER 2> /dev/null | grep -q "$target ${VPN_IPV4_NET}/24 accept"; then
            nft add rule ip filter DOCKER-USER ip "$target" "${VPN_IPV4_NET}"/24 accept
        fi
    done
fi

echo "Configuring routing rules..."

if ! ip rule show | grep -q "fwmark 0x1 lookup dnsmasq"; then
    ip rule add fwmark 0x1 table 431 priority 100 || true
fi

if ! ip route show table 431 default 2> /dev/null | grep -q "$VPN_IFACE"; then
    ip route add default dev "$VPN_IFACE" table 431 || true
fi

if [[ "$DNSMASQ_TUNNEL_DNS" == "true" ]]; then
    echo "All DNS requests will be tunneling to $VPN_IFACE"

    for dns in "$DNS1" "$DNS2"; do
        if [[ -n "$dns" ]]; then
            if ! ip route show | grep -q "$dns.*dev.*$VPN_IFACE"; then
                ip route add "$dns" dev "$VPN_IFACE" || true
            fi
        else
            echo "Error: DNS1 or DNS2 variable is not defined"
        fi
    done
else
    for dns in "$DNS1" "$DNS2"; do
        if [[ -n "$dns" ]]; then
            if ip route show | grep -q "$dns.*dev.*$VPN_IFACE"; then
                ip route delete "$dns" dev "$VPN_IFACE" || true
            fi
        fi
    done
fi

# ================= RUN =================

echo "Watching /etc/ocserv/domains.txt for updates..."
update_domains &

sleep 1

printf "conf-dir=/etc/dnsmasq.d\nserver=%s\nserver=%s\n" "${DNS1:-8.8.8.8}" "${DNS2:-8.8.4.4}" >> /etc/dnsmasq.conf

if [[ -n "$DNSMASQ_LIST" ]]; then
    echo "$DNSMASQ_LIST" | \
        grep -v '^[[:space:]]*$' | \
        while read -r domain; do
            domain=$(echo "$domain" | xargs)
            [[ -n "$domain" ]] && printf "nftset=/%s/4#ip#oc_nat#oc_set\n" "$domain"
        done >> /etc/dnsmasq.conf
fi

echo "Starting dnsmasq in foreground..."

while true; do dnsmasq --conf-file=/etc/dnsmasq.conf --bind-interfaces --interface="$VPN_IFACE" --port=53 --no-resolv --local-service --domain="$SRV_CN" --keep-in-foreground --log-facility=-; done
_EOF_
fi

dnsmasq_service() {
    #if [[ "$DNSMASQ_ENABLE" == "true" && "$OCCLIENT_ENABLE" == "true" ]]; then
    if [[ "$DNSMASQ_ENABLE" == "true" ]]; then
        if [[ -e "${SCRIPTS_DIR}"/ocdnsmasq && -n "$DNSMASQ_LIST" ]]; then
            until ip link show "$OCCLIENT_IFACE" &> /dev/null; do sleep 5; done
            sleep 5
            "${SCRIPTS_DIR}"/ocdnsmasq
        else
            echo "Varibale DNSMASQ_LIST is not defined or dnsmasq script not exists"
        fi
    fi
}

# Start ocserv service
if [[ -e "${SSL_DIR}"/live/"${SRV_CN}"/privkey.pem && -e "${SSL_DIR}"/live/"${SRV_CN}"/fullchain.pem && -e "${CERTS_DIR}"/ca-key.pem && -e "${CERTS_DIR}"/ca-cert.pem ]]; then
    sed -i '/^dns\s*=.*/d' "${OCSERV_DIR}/ocserv.conf"
    {
        echo "dns = $DNS1"
        [[ -n "${DNS2:-}" ]] && echo "dns = $DNS2"
    } >> "${OCSERV_DIR}/ocserv.conf"
    pam_otp &> /proc/1/fd/1
    prepare_nft &> /proc/1/fd/1
    openconnect_client &> /proc/1/fd/1 &
    dnsmasq_service &> /proc/1/fd/1 &
    echo "Starting OpenConnect Server"
    exec "$@" || { echo "Starting failed" >&2; exit 1; }
else
    # Server certificates generation
    certtool --generate-privkey --outfile "${CERTS_DIR}"/ca-key.pem
    certtool --generate-self-signed --load-privkey "${CERTS_DIR}"/ca-key.pem --template "${CERTS_DIR}"/ca.tmpl --outfile "${CERTS_DIR}"/ca-cert.pem
    certtool --generate-crl --load-ca-privkey "${CERTS_DIR}"/ca-key.pem --load-ca-certificate "${CERTS_DIR}"/ca-cert.pem --template "${CERTS_DIR}"/crl.tmpl --outfile "${CERTS_DIR}"/crl.pem
    if [[ ! -e "${SSL_DIR}"/live/"${SRV_CN}"/privkey.pem && ! -e "${SSL_DIR}"/live/"${SRV_CN}"/fullchain.pem ]]; then
        certtool --generate-privkey --outfile "${SSL_DIR}"/live/"${SRV_CN}"/privkey.pem
        certtool --generate-certificate --load-privkey "${SSL_DIR}"/live/"${SRV_CN}"/privkey.pem --load-ca-certificate "${CERTS_DIR}"/ca-cert.pem --load-ca-privkey "${CERTS_DIR}"/ca-key.pem --template "${SSL_DIR}"/server.tmpl --outfile "${SSL_DIR}"/live/"${SRV_CN}"/fullchain.pem
    fi
    sed -i "s/^dns.*=.*/dns = $DNS1/" "${OCSERV_DIR}"/ocserv.conf
    pam_otp &> /proc/1/fd/1 &
    prepare_nft &> /proc/1/fd/1
    openconnect_client &> /proc/1/fd/1 &
    dnsmasq_service &> /proc/1/fd/1 &
    echo "Starting OpenConnect Server"
    exec "$@" || { echo "Starting failed" >&2; exit 1; }
fi
