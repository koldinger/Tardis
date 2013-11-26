import os
import os.path
import socket
import logging

class CacheDir:
    def __init__(self, root, parts=2, partsize=2):
        logger.debug("Creating CacheDir: path={}, parts={}, partsize={})".format(root, parts, partsize))
        self.root = os.path.abspath(root)
        self.parts = parts
        self.partsize = partsize

    def comps(self, name):
        return [name[(i * self.partsize):((i + 1) * self.partsize)] for i in range(0, self.parts)]

    def dir(self, name):
        return reduce(os.path.join, self.comps(name), self.root)

    def path(self, name):
        return os.path.join(self.dir(name), name)

    def exists(self, name):
        return os.path.exists(self.path(name))

    def mkdir(self, name):
        dir = self.dir(name)
        if not os.path.isdir(dir):
            os.makedirs(dir)

    def open(self, name, mode):
        if mode.startswith("w"):
            dir = self.dir(name)
            if not os.path.isdir(dir):
                os.makedirs(dir)
        return open(self.path(name), mode)

logger = logging.getLogger("CacheDir")

if __name__ == "__main__":
    test = "abcdefghijklmnop"
    path = os.path.join("cache", socket.gethostname())
    c = CacheDir(path, 4, 2)
    print c.comps(test)
    print c.dir(test)
    print c.path(test)
    print c.exists(test)

    try:
        c.open(test, "r")
    except IOError as ex:
        print "Caught IOError"

    with c.open(test, "w") as fd:
        fd.write("I'm henry the 8'th I am\n")
        fd.write("Henry the 8th, I am I am\n")

    with c.open(test, "r") as fd:
        for line in fd:
            print line,
    print c.exists(test)


