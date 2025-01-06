FROM openconnect-build:v1.3 AS builder

FROM debian:12

LABEL maintainer="Ivan Cherniy <kar-kar@r4ven.me>"

STOPSIGNAL SIGTERM

COPY --from=builder ["/ocserv-1.3.0/src/occtl/occtl", "/usr/bin"]
COPY --from=builder ["/ocserv-1.3.0/src/ocpasswd/ocpasswd", "/usr/bin"]
COPY --from=builder ["/ocserv-1.3.0/src/ocserv-fw", "/usr/libexec"]
COPY --from=builder ["/ocserv-1.3.0/src/ocserv", "/usr/sbin"]
COPY --from=builder ["/ocserv-1.3.0/src/ocserv-worker", "/usr/sbin"]
COPY --from=builder ["/usr/share/doc/ocserv", "/usr/share/doc/ocserv"]

ENV OCSERV_DIR="/etc/ocserv"
ENV CERTS_DIR="${OCSERV_DIR}/certs"
ENV SSL_DIR="${OCSERV_DIR}/ssl"
ENV SECRETS_DIR="${OCSERV_DIR}/secrets"
ENV PATH="${OCSERV_DIR}:${PATH}"

ARG DEBIAN_FRONTEND=noninteractive

RUN echo "deb http://deb.debian.org/debian sid main" >> /etc/apt/sources.list && \
    apt update && \
    apt install -y --no-install-recommends \
        libllhttp9.1 \ 
        libtalloc2 \
        libradcli4 \
        liboath0 \
        libpcl1 \
        libev4 \
        libprotobuf-c1 \
        libreadline8 \
        libnl-route-3-200 \
        libcurl3-gnutls \
        libcjose0 \
        less \
        gnutls-bin \
        iptables \
        iproute2 \
        iputils-ping && \
    mkdir /etc/ocserv/ && \
    apt autoremove --yes && \
    apt clean -y && \
    rm -rf /var/lib/{apt,dpkg,cache,log}/*

COPY ./ocserv.sh /

ENTRYPOINT ["/ocserv.sh"]

CMD ["ocserv", "--config", "/etc/ocserv/ocserv.conf", "--foreground"]

HEALTHCHECK --interval=5m --timeout=3s \
  CMD  pidof -q ocserv || exit 1