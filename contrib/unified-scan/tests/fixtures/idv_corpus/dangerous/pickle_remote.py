import pickle

import requests


def load_remote(url):
    r = requests.get(url, timeout=10)
    return pickle.loads(r.content)
