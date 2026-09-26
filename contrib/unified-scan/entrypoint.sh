#!/bin/sh
# GuardDog refreshes its bundled "top packages" lists (typosquatting check) when they are older
# than 30 days and writes them back next to its own code - on a read-only rootfs that write
# crashes guarddog. GUARDDOG_TOP_PACKAGES_CACHE_LOCATION points it at the /tmp tmpfs instead;
# seed it with the bundled lists (a refresh then goes through the egress proxy; if blocked,
# guarddog keeps using the bundled copy).
set -e
if [ -n "$GUARDDOG_TOP_PACKAGES_CACHE_LOCATION" ]; then
    mkdir -p "$GUARDDOG_TOP_PACKAGES_CACHE_LOCATION"
    res="$(/opt/venvs/guarddog/bin/python -c 'import os, guarddog; print(os.path.join(os.path.dirname(guarddog.__file__), "analyzer", "metadata", "resources"))' 2>/dev/null || true)"
    if [ -n "$res" ] && [ -d "$res" ]; then
        cp -n "$res"/* "$GUARDDOG_TOP_PACKAGES_CACHE_LOCATION"/ 2>/dev/null || true
    fi
fi
exec python /opt/unified-scan/http_wrapper.py
