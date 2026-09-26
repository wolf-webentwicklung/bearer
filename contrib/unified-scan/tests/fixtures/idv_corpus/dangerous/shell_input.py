import subprocess
import sys


def ping(host):
    return subprocess.run("ping -c 1 " + host, shell=True, capture_output=True).stdout


if __name__ == "__main__":
    print(ping(sys.argv[1]))
