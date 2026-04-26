# ========STAGE 1: BUILD========

FROM debian:13-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV OCSERV_VERSION="1.4.0"
ENV DEBIAN_VERSION="13"
ENV DEBIAN_VERSION_ID="trixie"

LABEL maintainer="Ivan Cherniy <kar-kar@r4ven.me>"

SHELL ["/bin/bash", "-Eeuo", "pipefail", "-c"]

# Keep downloaded packages between builds (Docker BuildKit cache)
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

# Все build-зависимости + компиляция в одном слое + cache-mounts
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    --mount=type=tmpfs,target=/var/log \
    --mount=type=tmpfs,target=/var/tmp \
    --mount=type=tmpfs,target=/var/cache/debconf \
    --mount=type=tmpfs,target=/run \
    --mount=type=tmpfs,target=/tmp \
    set -x && \
    echo "deb http://deb.debian.org/debian ${DEBIAN_VERSION_ID} main" >> /etc/apt/sources.list && \
    apt update && \
    apt upgrade --yes && \
    apt install --yes --no-install-recommends --no-install-suggests \
        curl build-essential pkg-config fakeroot devscripts \
        iputils-ping ruby-ronn openconnect libuid-wrapper \
        libnss-wrapper libsocket-wrapper gss-ntlmssp git-core make autoconf \
        libtool autopoint gettext automake nettle-dev libwrap0-dev \
        libpam0g-dev liblz4-dev libseccomp-dev libreadline-dev libnl-route-3-dev \
        libkrb5-dev liboath-dev libradcli-dev libprotobuf-c-dev libtalloc-dev libllhttp-dev \
        libhttp-parser-dev protobuf-c-compiler gperf liblockfile-bin \
        nuttcp libpam-oath libev-dev libgnutls28-dev gnutls-bin haproxy \
        yajl-tools libcurl4-gnutls-dev libcjose-dev libjansson-dev libssl-dev \
        iproute2 libpam-wrapper tcpdump libopenconnect-dev iperf3 lcov ipcalc \
        freeradius libfreeradius-dev gawk jq && \
    curl -fLO https://www.infradead.org/ocserv/download/ocserv-"${OCSERV_VERSION}".tar.xz && \
    tar -xvf ./ocserv-"${OCSERV_VERSION}".tar.xz && \
    cd ./ocserv-"${OCSERV_VERSION}"/ && \
    ./configure --enable-oidc-auth && make && \
    cp -r ./doc/ /usr/share/doc/ocserv

WORKDIR /ocserv-"${OCSERV_VERSION}"

# ========STAGE 2: RUNTIME========

FROM debian:13-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV OCSERV_VERSION="1.4.0"
ENV DEBIAN_VERSION="13"
ENV DEBIAN_VERSION_ID="trixie"

LABEL maintainer="Ivan Cherniy <kar-kar@r4ven.me>"

STOPSIGNAL SIGTERM

# Keep downloaded packages between builds
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

# Все runtime-пакеты + копирование бинарников из builder в одном слое + cache-mounts
RUN --mount=type=bind,target=/src,source=./ \
    --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    --mount=type=tmpfs,target=/var/log \
    --mount=type=tmpfs,target=/var/tmp \
    --mount=type=tmpfs,target=/var/cache/debconf \
    --mount=type=tmpfs,target=/run \
    --mount=type=tmpfs,target=/tmp \
    set -x && \
    apt update && \
    apt install --yes --no-install-recommends --no-install-suggests \
        adduser \
        ssl-cert \
        libc6 \
        libcrypt1 \
        libev4t64 \
        libgnutls30t64 \
        libgssapi-krb5-2 \
        liblz4-1 \
        libmaxminddb0 \
        libnettle8t64 \
        libnl-3-200 \
        liboath0t64 \
        libpam0g \
        libreadline8t64 \
        libseccomp2 \
        libsystemd0 \
        libtasn1-6 \
        libllhttp9.2 \
        libtalloc2 \
        libradcli4 \
        liboath0 \
        libev4 \
        libprotobuf-c1 \
        libreadline8 \
        libnl-route-3-200 \
        libcurl3-gnutls \
        libcjose0 \
        tini \
        gnutls-bin \
        iptables \
        iproute2 \
        iputils-ping \
        less \
        ca-certificates \
        xxd \
        libpam-oath \
        oathtool \
        qrencode \
        curl \
        jq \
        msmtp \
        nftables \
        dnsmasq \
        openconnect \
        inotify-tools && \
    apt autoremove --yes && \
    apt clean --yes && \
    rm -rf /var/lib/{apt,dpkg,cache,log}/*

COPY --from=builder ["/ocserv-${OCSERV_VERSION}/src/occtl/occtl", "/usr/local/bin"]
COPY --from=builder ["/ocserv-${OCSERV_VERSION}/src/ocpasswd/ocpasswd", "/usr/local/bin"]
COPY --from=builder ["/ocserv-${OCSERV_VERSION}/src/ocserv-fw", "/usr/local/libexec"]
COPY --from=builder ["/ocserv-${OCSERV_VERSION}/src/ocserv", "/usr/local/sbin"]
COPY --from=builder ["/ocserv-${OCSERV_VERSION}/src/ocserv-worker", "/usr/local/sbin"]
COPY --from=builder ["/usr/share/doc/ocserv", "/usr/share/doc/ocserv"]

COPY ./ocserv.sh /

ENV OCSERV_DIR="/etc/ocserv"
ENV CERTS_DIR="${OCSERV_DIR}/certs"
ENV SSL_DIR="${OCSERV_DIR}/ssl"
ENV SECRETS_DIR="${OCSERV_DIR}/secrets"
ENV SCRIPTS_DIR="${OCSERV_DIR}/scripts"
ENV PATH="${SCRIPTS_DIR}:${PATH}"
ENV SRV_CN="example.com" 
ENV SRV_CA="Example CA"
ENV IPV4_NET="10.10.10.0"
ENV IPV4_MASK="255.255.255.0"
ENV DNS1="8.8.8.8"
ENV DNS2="8.8.4.4"
ENV OTP_ENABLE="false"
ENV OTP_SEND_BY_EMAIL="false"
ENV OTP_SEND_BY_TELEGRAM="false"
ENV MSMTP_HOST="smtp.example.com"
ENV MSMTP_PORT="465"
ENV MSMTP_USER="mail@example.com"
ENV MSMTP_PASSWORD="PaSsw0rD"
ENV MSMTP_FROM="mail@example.com"
ENV TG_TOKEN="1234567890:QWERTYuio-PA1DFGHJ2_KlzxcVBNmqWEr3t"
ENV OCCLIENT_ENABLE=false
ENV OCCLIENT_TYPE="dcoker"
ENV DNSMASQ_ENABLE=false
ENV DNSMASQ_TUNNEL_DNS=false

WORKDIR $OCSERV_DIR

ENTRYPOINT ["/ocserv.sh"]

CMD ["/usr/bin/tini", "--", "/usr/local/sbin/ocserv", "--config", "/etc/ocserv/ocserv.conf", "--foreground"]

HEALTHCHECK --interval=5m --timeout=3s \
    CMD curl -k https://localhost:443/ || exit 1
