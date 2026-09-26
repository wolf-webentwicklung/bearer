import csv
import logging
import sys

log = logging.getLogger(__name__)


def export(users, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        for u in users:
            w.writerow([u["name"], u["email"]])
            log.info("exported user %s", u["email"])


if __name__ == "__main__":
    export([{"name": "Max Muster", "email": "max@example.com"}], sys.argv[1])
