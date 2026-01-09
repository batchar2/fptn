FROM ubuntu:24.04

ARG FPTN_SERVER_PATH
ARG FPTN_PASSWD_PATH

EXPOSE 443/tcp

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y dnsmasq iproute2 iptables supervisor && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/supervisor/conf.d

# Copy binaries
COPY "${FPTN_SERVER_PATH}" /usr/local/bin/fptn-server
COPY "${FPTN_PASSWD_PATH}" /usr/local/bin/fptn-passwd
RUN chmod +x /usr/local/bin/fptn-server && \
    chmod +x /usr/local/bin/fptn-passwd

# Setup dnsmasq
RUN echo "server=8.8.8.8" > /etc/dnsmasq.conf && \
    echo "server=8.8.4.4" >> /etc/dnsmasq.conf && \
    echo "server=2001:4860:4860::8888" >> /etc/dnsmasq.conf && \
    echo "server=2001:4860:4860::8844" >> /etc/dnsmasq.conf

RUN cat > /etc/supervisor/supervisord.conf << 'EOF'
[supervisord]
user=root
nodaemon=true
logfile=/dev/stdout
logfile_maxbytes=0
pidfile=/var/run/supervisord.pid

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[unix_http_server]
file=/var/run/supervisor.sock
chmod=0700
user=root

[supervisorctl]
serverurl=unix:///var/run/supervisor.sock

[include]
files = /etc/supervisor/conf.d/*.conf
EOF


RUN cat > /etc/supervisor/conf.d/dnsmasq.conf << 'EOF'
[program:dnsmasq]
command=/usr/sbin/dnsmasq --no-daemon
autostart=true
autorestart=true
startretries=3
startsecs=2
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
redirect_stderr=true
user=root
EOF

# Setup fptn-server
RUN cat > /usr/local/bin/start-fptn.sh << 'EOF'
#!/bin/bash
export OUT_NETWORK_INTERFACE=$(ip -o -4 route show to default | awk '{print $5}')
echo "[FPTN] Using network interface: $OUT_NETWORK_INTERFACE"
exec /usr/local/bin/fptn-server \
    --server-key=/etc/fptn/server.key \
    --server-crt=/etc/fptn/server.crt \
    --out-network-interface=$OUT_NETWORK_INTERFACE \
    --server-port=443 \
    --enable-detect-probing=$ENABLE_DETECT_PROBING \
    --tun-interface-name=fptn0 \
    --disable-bittorrent=$DISABLE_BITTORRENT \
    --prometheus-access-key=$PROMETHEUS_SECRET_ACCESS_KEY \
    --use-remote-server-auth=$USE_REMOTE_SERVER_AUTH \
    --remote-server-auth-host=$REMOTE_SERVER_AUTH_HOST \
    --remote-server-auth-port=$REMOTE_SERVER_AUTH_PORT \
    --max-active-sessions-per-user=$MAX_ACTIVE_SESSIONS_PER_USER
EOF

RUN chmod +x /usr/local/bin/start-fptn.sh

RUN cat > /etc/supervisor/conf.d/fptn-server.conf << 'EOF'
[program:fptn-server]
command=/usr/local/bin/start-fptn.sh
autostart=true
autorestart=true
startretries=3
startsecs=5
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
redirect_stderr=true
user=root
EOF

CMD ["/usr/bin/supervisord", "--nodaemon", "-c", "/etc/supervisor/supervisord.conf"]
