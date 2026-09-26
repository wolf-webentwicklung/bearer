import sys


def calc(expr):
    return eval(expr)


if __name__ == "__main__":
    print(calc(sys.argv[1]))
