import os.path

class CacheDir:
    def __init__(self, root, parts, partsize):
        self.root = os.path.abspath(root)
        self.parts = parts
        self.partsize = partsize

    def comps(self, file):
        return [file[(i * self.partsize):((i + 1) * self.partsize)] for i in range(0, self.parts)]

    def dir(self, file):
        path = self.root
        for dir in self.comps(file):
            path = os.path.join(path, dir)
        return path

    def path(self, file):
        return os.path.join(self.dir(file), file)

if __name__ == "__main__":
    test = "abcdefghijklmnop"
    c = CacheDir("var", 2, 4)
    print c.comps(test)
    print c.dir(test)
    print c.path(test)
