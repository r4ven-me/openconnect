FROM openconnect-build:v1.4 AS builder

FROM debian:13

ENV OCSERV_VERSION="1.4.0"
ENV DEBIAN_VERSION="13"
ENV DEBIAN_VERSION_ID="trixie"

LABEL maintainer="Ivan Cherniy <kar-kar@r4ven.me>"

STOPSIGNAL SIGTERM

COPY --from=builder ["/ocserv-${OCSERV_VERSION}/src/occtl/occtl", "/usr/bin"]
COPY --from=builder ["/ocserv-${OCSERV_VERSION}/src/ocpasswd/ocpasswd", "/usr/bin"]
COPY --from=builder ["/ocserv-${OCSERV_VERSION}/src/ocserv-fw", "/usr/libexec"]
COPY --from=builder ["/ocserv-${OCSERV_VERSION}/src/ocserv", "/usr/sbin"]
COPY --from=builder ["/ocserv-${OCSERV_VERSION}/src/ocserv-worker", "/usr/sbin"]
COPY --from=builder ["/usr/share/doc/ocserv", "/usr/share/doc/ocserv"]

ENV OCSERV_DIR="/etc/ocserv"
ENV CERTS_DIR="${OCSERV_DIR}/certs"
ENV SSL_DIR="${OCSERV_DIR}/ssl"
ENV SECRETS_DIR="${OCSERV_DIR}/secrets"
ENV SCRIPTS_DIR="${OCSERV_DIR}/scripts"
ENV PATH="${SCRIPTS_DIR}:${PATH}"
ENV SRV_CN="example.com" 
ENV SRV_CA="Example CA"
ENV OTP_ENABLE="false"
ENV OTP_SEND_BY_EMAIL="false"
ENV OTP_SEND_BY_TELEGRAM="false"
ENV MSMTP_HOST="smtp.example.com"
ENV MSMTP_PORT="465"
ENV MSMTP_USER="mail@example.com"
ENV MSMTP_PASSWORD="PaSsw0rD"
ENV MSMTP_FROM="mail@example.com"
ENV TG_TOKEN="1234567890:QWERTYuio-PA1DFGHJ2_KlzxcVBNmqWEr3t"

WORKDIR $OCSERV_DIR

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update && \
    apt install --yes --no-install-recommends \
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
        msmtp && \
    apt autoremove --yes && \
    apt clean --yes && \
    rm -rf /var/lib/{apt,dpkg,cache,log}/*

COPY ./ocserv.sh /

ENTRYPOINT ["/ocserv.sh"]

CMD ["/usr/bin/tini", "--", "/usr/sbin/ocserv", "--config", "/etc/ocserv/ocserv.conf", "--foreground"]

HEALTHCHECK --interval=5m --timeout=3s \
    CMD curl -k https://localhost:443/ || exit 1
