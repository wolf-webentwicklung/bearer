import yaml


def load(path):
    with open(path) as fh:
        return yaml.load(fh, Loader=yaml.Loader)


def load2(text):
    return yaml.unsafe_load(text)


def load3(text):
    return yaml.load(text)
