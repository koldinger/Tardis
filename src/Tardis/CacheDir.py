# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2025, Eric Koldinger, All Rights Reserved.
# kolding@washington.edu
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import configparser
import logging
import shutil
import socket
from pathlib import Path

from . import Defaults

logger = logging.getLogger("CacheDir")

class CacheDirDoesNotExist(Exception):
    pass

PARTSIZE    = "partsize"
PARTS       = "parts"
CONFIGFILE  = ".cachedir"

class CacheDir:
    def __init__(self, root: Path, parts=2, partsize=2, create=True, skipFile=None):
        self.root = root.absolute()
        self.skipFile = skipFile or Defaults.getDefault("TARDIS_SKIP")

        if not self.root.is_dir():
            if create:
                self.root.mkdir(parents=True)
                if skipFile:
                    Path(self.root, self.skipFile).touch()
            else:
                raise CacheDirDoesNotExist(f"CacheDir does not exist: {root}")

        # Read a config file if it exists, create it if not
        defaults = {"parts": str(parts), "partsize": str(partsize) }
        section = "CacheDir"

        config_file = Path(self.root, CONFIGFILE)
        config = configparser.ConfigParser(defaults)
        config.add_section(section)
        config.read(config_file)

        self.parts    = config.getint(section, PARTS)
        self.partsize = config.getint(section, PARTSIZE)

        if create:
            config.set(section, PARTS,    str(self.parts))
            config.set(section, PARTSIZE, str(self.partsize))
            try:
                with config_file.open("w", encoding="utf8") as f:
                    config.write(f)
            except Exception as e:
                logger.warning("Could not write configpration file: %s: %s", config_file, str(e))

    def comps(self, name):
        return [name[(i * self.partsize):((i + 1) * self.partsize)] for i in range(0, self.parts)]

    def dirPath(self, name):
        return Path(self.root, *self.comps(name))


    def path(self, name):
        return Path(self.dirPath(name), name)

    def exists(self, name):
        return self.path(name).exists()

    def size(self, name):
        try:
            return self.path(name).stat().st_size
        except Exception:
            return 0

    def mkdir(self, name):
        directory = self.dirPath(name)
        if not directory.is_dir():
            directory.mkdir(parents=True)

    def open(self, name, mode, streaming=True):
        if mode.startswith(("w", "a")):
            self.mkdir(name)
        path = self.path(name)
        f = open(path, mode)
        return f

    def insert(self, name, source, link=False):
        self.mkdir(name)
        path = self.path(name)
        if link:
            source.hardlink_to(path)
        else:
            shutil.move(source, path)

    def link(self, source, dest, soft=True):
        self.mkdir(dest)
        dstpath = self.path(dest)
        if soft:
            srcpath = self.path(source).relative_to(self.dirPath(dest), walk_up=True)
            dstpath.hardlink_to(srcpath)
        else:
            srcpath = self.path(source)
            dstpath.hardlink_to(srcpath)
        return True

    def remove(self, name):
        try:
            self.path(name).unlink()
            return True
        except OSError:
            return False

    def removeSuffixes(self, name, suffixes):
        deleted = 0
        for suffix in suffixes:
            if self.remove(name + suffix):
                deleted += 1
        return deleted

    def move(self, oldname, newname):
        try:
            self.mkdir(newname)
            shutil.move(self.path(oldname), self.path(newname))
            return True
        except OSError:
            return False

    def enumerateDirs(self):
        root = Path(self.root)
        yield from self._enumerateDirs(self.parts, root)

    def _enumerateDirs(self, parts, root):
        for i in root.iterdir():
            if i.is_dir() and len(i.name) == self.partsize:
                if parts > 1:
                    yield from self._enumerateDirs(parts - 1, i)
                else:
                    yield i

    def enumerateFiles(self):
        for i in self.enumerateDirs():
            yield from i.iterdir()

if __name__ == "__main__":
    test = "abcdefghijklmnop"
    testPath = Path("cache", socket.gethostname())
    c = CacheDir(testPath, 4, 2, True)
    print(c.comps(test))
    print(c.dirPath(test))
    print(c.path(test))
    print(c.exists(test))

    try:
        c.open(test, "r")
    except OSError:
        print("Caught IOError")

    with c.open(test, "w") as fd:
        fd.write("I'm henry the 8'th I am\n")
        fd.write("Henry the 8th, I am I am\n")

    with c.open(test, "r") as fd:
        for line in fd:
            print(line, end=" ")
    print(c.exists(test))
