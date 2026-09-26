import sys

import yaml


def load(path):
    with open(path) as fh:
        return yaml.load(fh, Loader=yaml.Loader)


if __name__ == "__main__":
    print(load(sys.argv[1]))
