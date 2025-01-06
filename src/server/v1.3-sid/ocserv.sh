#!/bin/bash

# Some protection
set -Eeuo pipefail

# Define default server vars if they are not set
SRV_CN="${SRV_CN:=example.com}" 
SRV_CA="${SRV_CA:=Example CA}"
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

# Create certs dirs
for sub_dir in "${OCSERV_DIR}"/{"ssl/live/${SRV_CN}","certs","secrets","scripts"}; do
    if [[ ! -d "$sub_dir" ]]; then
        mkdir -p "$sub_dir"
    fi
done

if [[ -r /usr/share/doc/ocserv/sample.config && ! -e "${OCSERV_DIR}"/sample.config ]]; then
    cp /usr/share/doc/ocserv/sample.config "${OCSERV_DIR}"/
fi

# Create ocserv config file
if [[ ! -e "${OCSERV_DIR}"/ocserv.conf ]]; then
cat << _EOF_ > "${OCSERV_DIR}"/ocserv.conf
auth = "certificate"
#auth = "plain[passwd=${OCSERV_DIR}/ocpasswd]"
#auth = "plain[passwd=/etc/ocserv/passwd,otp=/etc/ocserv/secrets/users.oath]"
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
cat << _EOF_ > "${SCRIPTS_DIR}"/connect && chmod +x "${SCRIPTS_DIR}"/connect
#!/bin/bash

set -Eeuo pipefail

echo "\$(date) User \${USERNAME} Connected - Server: \${IP_REAL_LOCAL} VPN IP: \${IP_REMOTE}  Remote IP: \${IP_REAL} Device:\${DEVICE}"
echo "Running iptables MASQUERADE for User \${USERNAME} connected with VPN IP \${IP_REMOTE}"
iptables -t nat -A POSTROUTING -s "\${IP_REMOTE}"/32 -o eth0 -j MASQUERADE
_EOF_
fi

# Create disconnect script which runs for every user disconnection
if [[ ! -e "${SCRIPTS_DIR}"/disconnect ]]; then
cat << _EOF_ > "${SCRIPTS_DIR}"/disconnect && chmod +x "${SCRIPTS_DIR}"/disconnect
#!/bin/bash

set -Eeuo pipefail

echo "\$(date) User \${USERNAME} Disconnected - Bytes In: \${STATS_BYTES_IN} Bytes Out: \${STATS_BYTES_OUT} Duration:\${STATS_DURATION}"
iptables -t nat -D POSTROUTING -s "\${IP_REMOTE}"/32 -o eth0 -j MASQUERADE
_EOF_
fi

# Create script to create new users
if [[ ! -e "${SCRIPTS_DIR}"/ocuser ]]; then
cat << _EOF_ > "${SCRIPTS_DIR}"/ocuser && chmod +x "${SCRIPTS_DIR}"/ocuser
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
fi

# Add revoke script
if [[ ! -e "${SCRIPTS_DIR}"/ocrevoke ]]; then
cat << _EOF_ > "${SCRIPTS_DIR}"/ocrevoke && chmod +x "${SCRIPTS_DIR}"/ocrevoke
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
fi

# Add ocuser2fa script
if [[ "$OTP_ENABLE" == "true" && ! -e "${SCRIPTS_DIR}"/ocuser2fa ]]; then
cat << _EOF_ > "${SCRIPTS_DIR}"/ocuser2fa && chmod +x "${SCRIPTS_DIR}"/ocuser2fa
#!/bin/bash

set -Eeuo pipefail

if [[ \$# -eq 1 ]]; then
    USER_ID="\$1"
    OTP_SECRET="\$(head -c 16 /dev/urandom | xxd -c 256 -ps)"
    OTP_SECRET_BASE32="\$(echo 0x"\${OTP_SECRET}" | xxd -r -c 256 | base32)"
    OTP_SECRET_QR="otpauth://totp/\$USER_ID?secret=\$OTP_SECRET_BASE32&issuer=$SRV_CA&counter=1"

    if [[ ! -e "\${SECRETS_DIR}"/users.oath ]] || ! grep -qP "(?<!\\S)\${USER_ID}(?!\\S)" "\${SECRETS_DIR}"/users.oath; then
        echo "HOTP/T30 \$USER_ID - \$OTP_SECRET" >> "\${SECRETS_DIR}"/users.oath
        echo "OTP secret for \$USER_ID: \$OTP_SECRET"
        echo "OTP secret in base32: \$OTP_SECRET_BASE32"
        echo "OTP secret in QR code:"
        qrencode -t ANSIUTF8 "\$OTP_SECRET_QR"
        qrencode "\$OTP_SECRET_QR" -s 10 -o "\${SECRETS_DIR}"/otp_"\${USER_ID}".png
        echo "TOTP secret in png image saved at: \${SECRETS_DIR}/otp_\${USER_ID}.png"

        send_qr_by_email() {
            EMAIL_REGEX="^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

            if [[ \$USER_ID =~ \$EMAIL_REGEX ]]; then
                cat << EOF | msmtp --file="\${SCRIPTS_DIR}"/msmtprc "\$USER_ID"
Subject: TOTP QR code for OpenConnect auth
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary"

--boundary
Content-Type: text/plain

TOTP secret for OpenConnect (base32):
\$OTP_SECRET_BASE32

--boundary
Content-Type: image/png; name="file.png"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="file.png"

\$(base64 "\${SECRETS_DIR}"/otp_"\${USER_ID}".png)
--boundary--
EOF
                echo "[\$(date '+%F %T')] - TOTP secret and QR code successfully sent to \$USER_ID via Email" | tee -a "\${OCSERV_DIR}"/pam.log
            else
                return 0
            fi
        }

        if [[ "\$OTP_SEND_BY_EMAIL" == "true" ]]; then send_qr_by_email; fi

        send_qr_by_telegram() {
            if [[ -e "\${SECRETS_DIR}"/users.oath ]] && grep -qP "(?<!\\S)\${USER_ID}(?!\\S)" "\${SECRETS_DIR}"/users.oath; then
                TG_MESSAGE="TOTP secret for OpenConnect (base32):
\$OTP_SECRET_BASE32"
                TG_USER_FILE="\${SCRIPTS_DIR}/tg_users.txt"
                TG_RESPONSE="\$(curl -s "https://api.telegram.org/bot\$TG_TOKEN/getUpdates")"
                
                if grep -qP "(?<!\\S)\${USER_ID}(?!\\S)" "\$TG_USER_FILE" 2> /dev/null; then
                    TG_CHAT_ID=\$(grep -P "(?<!\\S)\${USER_ID}(?!\\S)" "\$TG_USER_FILE" | awk '{print \$1}')
                else
                    TG_CHAT_ID=\$(echo "\$TG_RESPONSE" | jq -r --arg USERNAME "\$USER_ID" '.result[] | select(.message.from.username == \$USERNAME) | .message.chat.id')

                    if [[ -z "\$TG_CHAT_ID" ]]; then
                        echo "[\$(date '+%F %T')] - User was not found or did not interact with the bot" >> "\${OCSERV_DIR}"/pam.log
                        return 0
                    fi
                    echo "\$TG_CHAT_ID \$USER_ID" >> "\$TG_USER_FILE"
                fi
            fi

            curl -s -X POST "https://api.telegram.org/bot\$TG_TOKEN/sendPhoto" \\
                -H "Content-Type: multipart/form-data" \\
                -F "chat_id=\$TG_CHAT_ID" \\
                -F "photo=@\${SECRETS_DIR}/otp_\${USER_ID}.png" \\
                -F "caption=\$TG_MESSAGE" > /dev/null 2>> "\${OCSERV_DIR}"/pam.log

            echo "[\$(date '+%F %T')] - TOTP secret and QR code successfully sent to \$USER_ID via Telegram" | tee -a "\${OCSERV_DIR}"/pam.log
        }

        if [[ "\$OTP_SEND_BY_TELEGRAM" == "true" ]]; then send_qr_by_telegram; fi

    else
        echo "OTP token already exists for \$USER_ID in \${SECRETS_DIR}/users.oath"
        exit 1
    fi
else
    echo "Usage: \$(basename "\$0") <user_id>"
    exit 1
fi
_EOF_
fi

if [[ "$OTP_ENABLE" == "true" && ! -e "${SCRIPTS_DIR}"/otp_sender ]]; then
cat << _EOF_ > "${SCRIPTS_DIR}"/otp_sender && chmod +x "${SCRIPTS_DIR}"/otp_sender
#!/bin/bash

set -Eeuo pipefail

OCSERV_DIR="$OCSERV_DIR"
SECRETS_DIR="$SECRETS_DIR"
SCRIPTS_DIR="$SCRIPTS_DIR"
OTP_SEND_BY_EMAIL="$OTP_SEND_BY_EMAIL"
OTP_SEND_BY_TELEGRAM="$OTP_SEND_BY_TELEGRAM"
TG_TOKEN="$TG_TOKEN"

echo "[\$(date '+%F %T')] - PAM user \$PAM_USER is trying to connect to ocserv" >> "\${OCSERV_DIR}"/pam.log

otp_sender_by_email() {
   if [[ -e "\${SECRETS_DIR}"/users.oath ]] && grep -qP "(?<!\\S)\${PAM_USER}(?!\\S)" "\${SECRETS_DIR}"/users.oath; then
        OTP_TOKEN="\$(oathtool --totp \$(grep -P "(?<!\\S)\${PAM_USER}(?!\\S)" \${SECRETS_DIR}/users.oath | awk '{print \$4}'))"
        EMAIL_REGEX="^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

        if [[ \$PAM_USER =~ \$EMAIL_REGEX ]]; then
            echo -e "Subject: TOTP token for OpenConnect\n\n\${OTP_TOKEN}" | msmtp --file="\${SCRIPTS_DIR}"/msmtprc "\$PAM_USER"
            echo "[\$(date '+%F %T')] - TOTP token successfully sent to \$PAM_USER" >> "\${OCSERV_DIR}"/pam.log
        else
            return 0
        fi
   fi
}

otp_sender_by_telegram() {
    if grep -qP "(?<!\\S)\${PAM_USER}(?!\\S)" "\${SECRETS_DIR}"/users.oath 2> /dev/null; then
        OTP_TOKEN="\$(oathtool --totp \$(grep -P "(?<!\\S)\${PAM_USER}(?!\\S)" \${SECRETS_DIR}/users.oath | awk '{print \$4}'))"
        TG_MESSAGE="TOTP token for OpenConnect: \$OTP_TOKEN"
        TG_USER_FILE="\${SCRIPTS_DIR}/tg_users.txt"
        TG_RESPONSE="\$(curl -s "https://api.telegram.org/bot\$TG_TOKEN/getUpdates")"
        
        if grep -qP "(?<!\\S)\$PAM_USER(?!\\S)" "\$TG_USER_FILE"; then
            TG_CHAT_ID=\$(grep -P "(?<!\\S)\${PAM_USER}(?!\\S)" "\$TG_USER_FILE" | awk '{print \$1}')
        else
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
    if [[ $OTP_ENABLE == "true" ]]; then
        until [[ -e /etc/pam.d/ocserv ]]; do sleep 5; done
        if grep -q 'otp_sender' /etc/pam.d/ocserv && grep -q 'users.oath' /etc/pam.d/ocserv; then return 0; fi
        sleep 3
        echo "auth optional pam_exec.so ${SCRIPTS_DIR}/otp_sender" >> /etc/pam.d/ocserv
        echo "auth requisite pam_oath.so debug usersfile=${SECRETS_DIR}/users.oath window=20" >> /etc/pam.d/ocserv
    fi
}

# Start ocserv service
if [[ -e "${SSL_DIR}"/live/"${SRV_CN}"/privkey.pem && -e "${SSL_DIR}"/live/"${SRV_CN}"/fullchain.pem && -e "${CERTS_DIR}"/ca-key.pem && -e "${CERTS_DIR}"/ca-cert.pem ]]; then
    pam_otp &
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
    
    pam_otp &
    echo "Starting OpenConnect Server"
    exec "$@" || { echo "Starting failed" >&2; exit 1; }
fi

