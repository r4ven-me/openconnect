FROM debian:sid

LABEL maintainer="Ivan Cherniy <kar-kar@r4ven.me>"

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
