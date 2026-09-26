import yaml


def load(path):
    with open(path) as fh:
        return yaml.safe_load(fh)


def load2(text):
    return yaml.load(text, Loader=yaml.SafeLoader)
