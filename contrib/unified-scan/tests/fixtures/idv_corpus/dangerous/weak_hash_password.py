import hashlib


def store_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()
