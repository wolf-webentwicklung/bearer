#!/bin/sh
# GuardDog refreshes its bundled "top packages" lists (typosquatting check) when they are older
# than 30 days and writes them back next to its own code - on a read-only rootfs that write
# crashes guarddog. GUARDDOG_TOP_PACKAGES_CACHE_LOCATION points it at the /tmp tmpfs instead;
# seed it with the bundled lists (a refresh then goes through the egress proxy; if blocked,
# guarddog keeps using the bundled copy).
set -e
if [ -n "$GUARDDOG_TOP_PACKAGES_CACHE_LOCATION" ]; then
    mkdir -p "$GUARDDOG_TOP_PACKAGES_CACHE_LOCATION"
    # Locate the bundled lists by path, not via `import guarddog`: importing already loads the
    # typosquatting detectors, which fail while the cache is still empty - the seed would then
    # never happen and every later guarddog run crashes the same way.
    for res in /opt/venvs/guarddog/lib/python3*/site-packages/guarddog/analyzer/metadata/resources; do
        if [ -d "$res" ]; then
            cp -n "$res"/* "$GUARDDOG_TOP_PACKAGES_CACHE_LOCATION"/ 2>/dev/null || true
        fi
    done
fi
exec python /opt/unified-scan/http_wrapper.py
