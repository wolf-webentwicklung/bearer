#!/bin/sh
# Rebuilds the scanner image with fresh data and only promotes it when the self-test passes.
#
#   contrib/unified-scan/rebuild.sh [image-name]        (default: unified-scan)
#
# What a rebuild refreshes:
#   - trivy vulnerability DB (baked in at build time)
#   - OSV index of known malicious PyPI/npm packages (build_osv_index.py)
#   - Debian security updates of the base image (--pull)
#   - bearer-rules: ONLY if BEARER_RULES_VERSION is set (e.g. BEARER_RULES_VERSION=latest or
#     v0.49.0). Default is the version pinned in the Dockerfile - a rules bump can rename rules,
#     so it is a deliberate step; the self-test below catches renamed/dropped rules.
#   - Tool versions (bearer, trivy, guarddog ...) stay pinned in the Dockerfile.
#
# Tags: <image>:candidate while testing, then <image>:current; the previous :current becomes
# <image>:previous (rollback: docker tag <image>:previous <image>:current, restart the service).
# The service should use <image>:current. Weekly via cron/systemd timer, e.g.
#   0 3 * * 1  /opt/<checkout>/contrib/unified-scan/rebuild.sh gvintra-scanner >> /var/log/scanner-rebuild.log 2>&1
set -eu

IMAGE="${1:-unified-scan}"
HERE="$(cd "$(dirname "$0")" && pwd)"
STAMP="$(date -u +%Y%m%d%H%M)"
BUILD_ARGS="--build-arg DATA_STAMP=${STAMP}"

if [ -n "${BEARER_RULES_VERSION:-}" ]; then
    RULES="$BEARER_RULES_VERSION"
    if [ "$RULES" = "latest" ]; then
        RULES="$(curl -fsSL https://api.github.com/repos/Bearer/bearer-rules/releases/latest \
                 | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
    fi
    echo "[rebuild] bearer-rules ${RULES}"
    BUILD_ARGS="${BUILD_ARGS} --build-arg BEARER_RULES_VERSION=${RULES}"
fi

echo "[rebuild] building ${IMAGE}:candidate (data stamp ${STAMP})"
# DATA_STAMP busts the cache from the data layers on (trivy DB, OSV index); --pull refreshes
# the base image. Tool install layers above stay cached.
# shellcheck disable=SC2086
nice -n 10 docker build --pull ${BUILD_ARGS} -t "${IMAGE}:candidate" "$HERE"

echo "[rebuild] self-test in the new image"
docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=512m \
    -e UNIFIED_SCAN_IMAGE_TEST=1 -e BEARER_RULES_DIR=/opt/bearer-rules \
    --entrypoint python "${IMAGE}:candidate" -m pytest -q -p no:cacheprovider \
    /opt/unified-scan/tests/test_corpus_real_bearer.py /opt/unified-scan/tests/test_policy_globs.py

if docker image inspect "${IMAGE}:current" >/dev/null 2>&1; then
    docker tag "${IMAGE}:current" "${IMAGE}:previous"
fi
docker tag "${IMAGE}:candidate" "${IMAGE}:current"
docker rmi "${IMAGE}:candidate" >/dev/null
echo "[rebuild] ${IMAGE}:current updated - restart the scanner service to use it"
