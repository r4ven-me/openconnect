FROM r4venme/openconnect:v1.4

ENV OCSERV_VERSION="1.4.0"
ENV DEBIAN_VERSION="13"
ENV DEBIAN_VERSION_ID="trixie"

LABEL maintainer="Ivan Cherniy <kar-kar@r4ven.me>"

STOPSIGNAL SIGTERM

ARG DEBIAN_FRONTEND=noninteractive

ENV OCCLIENT_ENABLE=false
ENV DNSMASQ_ENABLE=false

RUN apt update && \
    apt install --yes --no-install-recommends \
        ipset \
        dnsmasq \
        openconnect && \
    apt autoremove --yes && \
    apt clean --yes && \
    rm -rf /var/lib/{apt,dpkg,cache,log}/*

COPY ./ocserv.sh /

ENTRYPOINT ["/ocserv.sh"]

CMD ["/usr/bin/tini", "--", "/usr/sbin/ocserv", "--config", "/etc/ocserv/ocserv.conf", "--foreground"]

HEALTHCHECK --interval=5m --timeout=3s \
    CMD curl -k https://localhost:443/ || exit 1
