#!/usr/bin/env bash

set -e

WORK_DIR="/opt/openconnect"
CONTAINER_NAME="openconnect"

to_log () {
    local text="$1"
    echo "[$(date '+%F %T')] ${text}"
}

cd "$WORK_DIR" || exit 1

if [[ -r ./docker-compose.yml ]]; then
    to_log "Run certbot service container"
    docker compose up certbot
    sleep 3
    to_log "Reload ocserv config"
    docker exec "$CONTAINER_NAME" occtl reload
    to_log "Delete all unused docker images"
    docker system prune -af
fi

# docker exec openconnect 'kill -HUP "$(pidof ocserv-main)"'

