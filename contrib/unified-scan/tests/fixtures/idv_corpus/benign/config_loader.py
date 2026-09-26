import json
import logging

import yaml

log = logging.getLogger("tool")


def load(path):
    with open(path, encoding="utf-8") as fh:
        if path.endswith((".yml", ".yaml")):
            cfg = yaml.safe_load(fh)
        else:
            cfg = json.load(fh)
    log.info("config loaded: %s", cfg)
    return cfg
