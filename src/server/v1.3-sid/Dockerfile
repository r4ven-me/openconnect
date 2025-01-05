FROM debian:sid

LABEL maintainer="Ivan Cherniy <kar-kar@r4ven.me>"

ENV OCSERV_DIR="/etc/ocserv"
ENV CERTS_DIR="${OCSERV_DIR}/certs"
ENV SSL_DIR="${OCSERV_DIR}/ssl"
ENV SECRETS_DIR="${OCSERV_DIR}/secrets"
ENV BIN_DIR="${OCSERV_DIR}/bin"
ENV PATH="${BIN_DIR}:${PATH}"

WORKDIR $OCSERV_DIR

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update && \
    apt install --yes --no-install-recommends \
        tini \
        ocserv \
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
