# unified-scan as an internal HTTP scanner service (http_wrapper.py).
#
#   docker build -t unified-scan contrib/unified-scan
#
# Tool versions are pinned via build args - bump them deliberately.
# Runtime hardening (read-only rootfs, noexec tmpfs, no capabilities, ...): see README.md.
FROM python:3.12-slim-bookworm

ARG BEARER_VERSION=2.1.1
ARG TRUFFLEHOG_VERSION=3.97.9
ARG TRIVY_VERSION=0.74.0
ARG CHECKOV_VERSION=3.3.19
ARG GUARDDOG_VERSION=3.2.0
ARG PY7ZR_VERSION=1.1.3
ARG OLETOOLS_VERSION=0.60.2
# Bearer's default rules are normally downloaded at scan time - but that download is tied to the
# version check, which we switch off (no phone-home). Without rules bearer finds nothing and
# says so only in a log line, so the rules are baked in instead.
ARG BEARER_RULES_VERSION=v0.48.4
# 1 = bake the trivy vulnerability DB into the image (scan works without egress to the DB
# mirror; image must be rebuilt regularly to stay current). 0 = trivy downloads at runtime.
ARG TRIVY_BAKE_DB=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    cd /tmp; \
    curl -fsSL -o bearer.tgz "https://github.com/Bearer/bearer/releases/download/v${BEARER_VERSION}/bearer_${BEARER_VERSION}_linux_amd64.tar.gz"; \
    curl -fsSL -o trufflehog.tgz "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz"; \
    curl -fsSL -o trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    tar -xzf bearer.tgz bearer && tar -xzf trufflehog.tgz trufflehog && tar -xzf trivy.tgz trivy; \
    install -m 0755 bearer trufflehog trivy /usr/local/bin/; \
    rm -f /tmp/*

# checkov and guarddog each get their own venv - their dependency trees clash.
RUN python -m venv /opt/venvs/checkov \
    && /opt/venvs/checkov/bin/pip install --no-cache-dir "checkov==${CHECKOV_VERSION}" \
    && ln -s /opt/venvs/checkov/bin/checkov /usr/local/bin/checkov \
    && python -m venv /opt/venvs/guarddog \
    && /opt/venvs/guarddog/bin/pip install --no-cache-dir "guarddog==${GUARDDOG_VERSION}" \
    && ln -s /opt/venvs/guarddog/bin/guarddog /usr/local/bin/guarddog \
    && python -m venv /opt/venvs/oletools \
    && /opt/venvs/oletools/bin/pip install --no-cache-dir "oletools==${OLETOOLS_VERSION}" \
    && ln -s /opt/venvs/oletools/bin/olevba /usr/local/bin/olevba \
    && pip install --no-cache-dir "py7zr==${PY7ZR_VERSION}"

RUN set -eux; \
    for lang in go java javascript php python ruby; do \
        mkdir -p "/opt/bearer-rules/$lang"; \
        curl -fsSL "https://github.com/Bearer/bearer-rules/releases/download/${BEARER_RULES_VERSION}/${lang}.tar.gz" \
            | tar -xz -C "/opt/bearer-rules/$lang"; \
    done; \
    chmod -R a+rX /opt/bearer-rules; \
    test "$(find /opt/bearer-rules -name '*.yml' | wc -l)" -gt 100

ENV TRIVY_CACHE_DIR=/opt/trivy-cache
RUN if [ "$TRIVY_BAKE_DB" = "1" ]; then trivy image --download-db-only --cache-dir /opt/trivy-cache; fi \
    && mkdir -p /opt/trivy-cache && chmod -R a+rX /opt/trivy-cache

RUN useradd --create-home --uid 10001 scanner
WORKDIR /opt/unified-scan
COPY unified_scan.py safe_extract.py http_wrapper.py entrypoint.sh ./
RUN chmod 0755 /opt/unified-scan/entrypoint.sh

# Read-only rootfs at runtime: everything the tools write (bearer/checkov caches, jobs) goes
# to the /tmp tmpfs.
ENV HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    UNIFIED_SCAN_WORKDIR=/tmp \
    BEARER_DISABLE_VERSION_CHECK=true \
    BEARER_EXTERNAL_RULE_DIR=/opt/bearer-rules \
    BEARER_DISABLE_DEFAULT_RULES=true \
    GUARDDOG_TOP_PACKAGES_CACHE_LOCATION=/tmp/guarddog-cache \
    GUARDDOG_PARALLELISM=1 \
    BC_SKIP_MAPPING=TRUE \
    TRIVY_DISABLE_TELEMETRY=true \
    DO_NOT_TRACK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# With a baked DB, don't try to update it at runtime. The DB stays in the read-only image
# (too big for the tmpfs); trivy's scan cache is kept in memory instead of the cache dir.
ENV TRIVY_SKIP_DB_UPDATE=${TRIVY_BAKE_DB} \
    TRIVY_CACHE_BACKEND=memory

USER scanner
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)"
CMD ["/opt/unified-scan/entrypoint.sh"]
