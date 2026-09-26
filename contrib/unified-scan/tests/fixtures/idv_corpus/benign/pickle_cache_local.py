import os
import pickle

CACHE = os.path.join(os.path.dirname(__file__), "cache.pkl")


def save(obj):
    with open(CACHE, "wb") as fh:
        pickle.dump(obj, fh)


def load():
    if not os.path.exists(CACHE):
        return None
    with open(CACHE, "rb") as fh:
        return pickle.load(fh)
