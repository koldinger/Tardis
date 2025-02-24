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

import os
import os.path
import socket
import logging
import shutil
import configparser

from functools import reduce
from pathlib import Path

from . import Defaults

logger = logging.getLogger("CacheDir")

class CacheDirDoesNotExist(Exception):
    pass

PARTSIZE    = "partsize"
PARTS       = "parts"
CONFIGFILE  = ".cachedir"

class CacheDir:
    def __init__(self, root, parts=2, partsize=2, create=True, user=None, group=None, skipFile=Defaults.getDefault("TARDIS_SKIP")):
        self.root = os.path.abspath(root)
        self.user  = user if user else -1
        self.group = group if group else -1
        self.chown = user or group

        if not os.path.isdir(self.root):
            if create:
                os.makedirs(self.root)
                if self.chown:
                    os.chown(self.root, self.user, self.group)
                if skipFile:
                    with open(os.path.join(self.root, skipFile), 'a', encoding='utf8'):
                        pass
            else:
                raise CacheDirDoesNotExist("CacheDir does not exist: " + root)

        # Read a config file if it exists, create it if not
        defaults = {"parts": str(parts), "partsize": str(partsize) }
        section = "CacheDir"

        configFile = os.path.join(self.root, CONFIGFILE)
        config = configparser.ConfigParser(defaults)
        config.add_section(section)
        config.read(configFile)

        try:
            self.parts = int(config.get(section, PARTS))
            self.partsize = int(config.get(section, PARTSIZE))
        except ValueError:
            logger.error("Invalid configuration.  Using defaults")
            self.parts    = defaults[PARTS]
            self.partsize = defaults[PARTSIZE]

        config.set(section, PARTS,    str(self.parts))
        config.set(section, PARTSIZE, str(self.partsize))
        if create:
            try:
                with open(configFile, "w", encoding="utf8") as f:
                    config.write(f)
            except Exception as e:
                logger.warning("Could not write configpration file: %s: %s", configFile, str(e))

    def comps(self, name):
        return [name[(i * self.partsize):((i + 1) * self.partsize)] for i in range(0, self.parts)]

    def dirPath(self, name):
        return reduce(os.path.join, self.comps(name), self.root)

    def path(self, name):
        return os.path.join(self.dirPath(name), name)

    def exists(self, name):
        return os.path.lexists(self.path(name))

    def size(self, name):
        try:
            s = os.stat(self.path(name))
            return s.st_size
        except Exception:
            return 0

    def mkdir(self, name):
        directory = self.dirPath(name)
        if not os.path.isdir(directory):
            os.makedirs(directory)
            if self.chown:
                path = self.root
                for i in self.comps(name):
                    path = os.path.join(path, i)
                    os.chown(path, self.user, self.group)

    def open(self, name, mode, streaming=True):
        iswrite = mode.startswith('w') or mode.startswith('a')
        if iswrite:
            self.mkdir(name)
        path = self.path(name)
        f = open(path, mode)
        if iswrite and self.chown:
            os.fchown(f.fileno(), self.user, self.group)
        return f

    def insert(self, name, source, link=False):
        self.mkdir(name)
        path = self.path(name)
        if link:
            os.link(source, path)
        else:
            shutil.move(source, path)
        if self.chown:
            os.chown(path, self.user, self.group)

    def link(self, source, dest, soft=True):
        self.mkdir(dest)
        dstpath = self.path(dest)
        if soft:
            srcpath = os.path.relpath(self.path(source), self.dirPath(dest))
            os.symlink(srcpath, dstpath)
        else:
            srcpath = self.path(source)
            os.link(srcpath, dstpath)
        return True

    def remove(self, name):
        try:
            os.remove(self.path(name))
            return True
        except OSError:
            return False

    def removeSuffixes(self, name, suffixes):
        deleted = 0
        for suffix in suffixes:
            if self.remove(name + suffix):
                #logger.debug("Removed %s", name + suffix)
                deleted += 1
        return deleted

    def move(self, oldname, newname):
        try:
            self.mkdir(newname)
            os.rename(self.path(oldname), self.path(newname))
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
    testPath = os.path.join("cache", socket.gethostname())
    c = CacheDir(testPath, 4, 2, True)
    print(c.comps(test))
    print(c.dirPath(test))
    print(c.path(test))
    print(c.exists(test))

    try:
        c.open(test, "r")
    except IOError:
        print("Caught IOError")

    with c.open(test, "w") as fd:
        fd.write("I'm henry the 8'th I am\n")
        fd.write("Henry the 8th, I am I am\n")

    with c.open(test, "r") as fd:
        for line in fd:
            print(line, end=' ')
    print(c.exists(test))
