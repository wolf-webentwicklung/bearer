import os
import shutil
import sys


def rename_all(folder, prefix):
    for name in os.listdir(folder):
        src = os.path.join(folder, name)
        dst = os.path.join(folder, prefix + name)
        shutil.move(src, dst)
        print("renamed", src, "->", dst)


def read_config(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


if __name__ == "__main__":
    rename_all(sys.argv[1], sys.argv[2])
