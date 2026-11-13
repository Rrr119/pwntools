import os

path = os.path.dirname(__file__)


def get(name):
    return os.path.join(path, name)
