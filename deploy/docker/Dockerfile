FROM ubuntu:24.04

ARG FPTN_SERVER_PATH
ARG FPTN_PASSWD_PATH

EXPOSE 443/tcp

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y dnsmasq iproute2 iptables supervisor dnsutils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/supervisor/conf.d

# Copy binaries
COPY "${FPTN_SERVER_PATH}" /usr/local/bin/fptn-server
COPY "${FPTN_PASSWD_PATH}" /usr/local/bin/fptn-passwd
RUN chmod +x /usr/local/bin/fptn-server && \
    chmod +x /usr/local/bin/fptn-passwd

# Copy configuration files
COPY deploy/docker/config/supervisord.conf /etc/supervisor/supervisord.conf
COPY deploy/docker/config/supervisor/*.conf /etc/supervisor/conf.d/

# Copy scripts
COPY deploy/docker/scripts/check-dns.sh /usr/local/bin/check-dns.sh
COPY deploy/docker/scripts/start-fptn.sh /usr/local/bin/start-fptn.sh
COPY deploy/docker/scripts/start-dnsmasq.sh /usr/local/bin/start-dnsmasq.sh
COPY deploy/docker/scripts/token-generator.py /usr/local/bin/token-generator
RUN chmod +x /usr/local/bin/check-dns.sh && \
    chmod +x /usr/local/bin/start-fptn.sh && \
    chmod +x /usr/local/bin/start-dnsmasq.sh && \
    chmod +x /usr/local/bin/token-generator

CMD ["/usr/bin/supervisord", "--nodaemon", "-c", "/etc/supervisor/supervisord.conf"]
