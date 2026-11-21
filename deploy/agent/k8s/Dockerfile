# acme-agent for Kubernetes (docs/agent-fleet.md "Kubernetes"): the agent's own program
# (acme_agent.py, the same as on a server) and its Kubernetes side, Python's standard library and
# openssl - nothing else. Build it from the folder deploy/agent of acme (the context):
#
#   docker build -f k8s/Dockerfile --build-arg ACME_VERSION=1.0.138 \
#     -t registry.example.net/acme-agent-k8s:1.0.138 .
#
# It runs as an account of its own (10001), never root, on a read-only root file system; its
# state is the volume /var/lib/acme-agent, its policy the ConfigMap at /etc/acme-agent-k8s.
FROM python:3.12-alpine

RUN apk add --no-cache openssl ca-certificates \
 && addgroup -S -g 10001 acme-agent \
 && adduser -S -D -H -u 10001 -G acme-agent -s /sbin/nologin acme-agent \
 && mkdir -p /opt/acme-agent /var/lib/acme-agent /run/acme-agent /etc/acme-agent-k8s \
 && chown 10001:10001 /var/lib/acme-agent /run/acme-agent

COPY acme_agent.py /opt/acme-agent/acme_agent.py
COPY k8s/acme_k8s_agent.py /opt/acme-agent/acme_k8s_agent.py
# the version of acme this agent comes with (acme compares it with its own)
ARG ACME_VERSION=
RUN if [ -n "$ACME_VERSION" ]; then echo "$ACME_VERSION" > /opt/acme-agent/release; fi

ENV ACME_K8S_STATE=/var/lib/acme-agent \
    ACME_K8S_RUN=/run/acme-agent \
    ACME_K8S_POLICY=/etc/acme-agent-k8s/policy \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001
EXPOSE 8446
VOLUME ["/var/lib/acme-agent"]
ENTRYPOINT ["python3", "-I", "/opt/acme-agent/acme_k8s_agent.py"]
CMD ["serve"]
