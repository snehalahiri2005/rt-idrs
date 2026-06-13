FROM jasonish/suricata:7.0

# Copy custom configuration and rules
COPY suricata.yaml /etc/suricata/suricata.yaml
COPY rules/local.rules /etc/suricata/rules/local.rules

# Ensure log directory exists
RUN mkdir -p /var/log/suricata

# Suricata needs NET_ADMIN/NET_RAW capabilities and host networking
# at runtime (set in docker-compose.yml)
ENTRYPOINT ["suricata"]
CMD ["-c", "/etc/suricata/suricata.yaml", "-i", "eth0"]
