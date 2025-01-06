#!/usr/bin/env bash

## Enhanced error handling
set -Eeuo pipefail

## Var that defines working directory of script
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd -P)

## Custom vars
CERT_FILE="/path/to/exampleuser.p12"
CERT_PASS="examplepassword"
VPN_ADDRESS="vpn.example.com"
VPN_PORT="43443"
VPN_GATEWAY="10.10.10.1"
SSL_FLAG="1"

## System vars
OC_BIN="$(which openconnect)"
VPN_COMMAND="$OC_BIN -c $CERT_FILE $VPN_ADDRESS:$VPN_PORT"
CHECK_INTERVAL=10
TIMEOUT=30
RETRY_COUNT=3

## Function to print message
msg() {
    echo -e "[$(date '+%F %T')] ${1-}" >&2
}

## Function to terminate VPN command process
terminate_vpn() {
    msg "Terminating VPN connection" 
    pkill -SIGINT -f "${VPN_COMMAND}"
    exit 1
}

## Function to check availability of VPN gateway
check_gateway() {
    if ping -c 1 -W $TIMEOUT $VPN_GATEWAY &> /dev/null; then
        # msg "Gateway $VPN_GATEWAY is reachable."
        return 0
    else
        msg "Gateway $VPN_GATEWAY is not reachable."
        return 1
    fi
}

## Connecting to VPN
msg "Connecting to VPN..."
if [[ "$SSL_FLAG" == "1" ]]; then
    "$OC_BIN" -c "$CERT_FILE" "${VPN_ADDRESS}":"${VPN_PORT}" <<< "$(echo ${CERT_PASS}$'\n')" &
else
    "$OC_BIN" -c "$CERT_FILE" "${VPN_ADDRESS}":"${VPN_PORT}" <<< "$(echo ${CERT_PASS}$'\n'yes$'\n')" &
fi
# VPN_PID=$!

sleep 5

## Checking availability of gateway and exiting if there is no connection
while true; do
    FAILED_COUNT=0
    for (( i=0; i<RETRY_COUNT; i++ )); do
        if check_gateway; then
            break
        else
            FAILED_COUNT=$((FAILED_COUNT+1))
        fi
        if [[ $FAILED_COUNT -ge $RETRY_COUNT ]]; then
            msg "Gateway $VPN_GATEWAY unreachable after $RETRY_COUNT attempts."
            msg "Terminating VPN connection..."
            terminate_vpn
        fi
        sleep $CHECK_INTERVAL
    done
    sleep $CHECK_INTERVAL
done

