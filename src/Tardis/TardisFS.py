#! /usr/bin/python
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


from ast import increment_lineno
import os      # for filesystem modes (O_RDONLY, etc)
import os.path
import errno   # for error number codes (ENOENT, etc)

import sys
import argparse
import tempfile
import json
import base64
import time
import stat    # for file properties
import functools
import pwd
import grp
from enum import IntEnum, auto

from enum import IntEnum, auto

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn

import Tardis
from . import CacheDir
from . import Regenerator
from . import Util
from . import Cache
from . import Defaults
from . import TardisDB
from . import Config

# from icecream import ic 
# ic.configureOutput(includeContext=True)

class CacheKeys(IntEnum):
    BackupSetInfo = auto()
    LastBackupSet = auto()
    DirInfo       = auto()
    DirContents   = auto()
    LinkContents  = auto()

_infoEnabled    = True

logger = None

def getDepth(path):
    """
    Return the depth of a given path, zero-based from root ('/')
    """
    logger.debug("getDepth: %s", path)
    if path == '/':
        return 0

    return path.count('/')

def getParts(path):
    """
    Return the slash-separated parts of a given path as a list
    Namely, the backupset and the path within the set
    """
    if path == '/':
        return [['/']]
    return path.strip("/").split('/', 1)

class TardisFS(LoggingMixIn, Operations):
    """
    FUSE filesystem to read data from a Tardis Backup Database
    """
    # Disable pylint complaints about "could me a function" and "unused argument" as lots of required FUSE functions
    # just return "read-only FS" status
    # pragma pylint: disable=nused-argument
    fsencoding = sys.getfilesystemencoding()
    name = "TardisFS"

    current  = Defaults.getDefault('TARDIS_RECENT_SET')

    rootVId = Util.hashPath("/")

    def __init__(self, db, cache, crypto, args):
        self.cacheDir = cache
        self.crypt = crypto
        self.tardis = db

        # Create a regenerator.
        self.regenerator = Regenerator.Regenerator(self.cacheDir, self.tardis, crypt=self.crypt)
        self.files = {}

        # Set up some caches.
        self.cachetime  = 60

        self.cache      = Cache.Cache(0, float(self.cachetime))
        self.fileCache  = Cache.Cache(0, float(self.cachetime), 'FileCache')

        self.authenticate = True

    def __del__(self):
        if self.tardis:
            self.tardis.close()

    def __repr__(self):
        return self.name

    def fsEncodeName(self, name):
        return name

    def getBackupSetInfo(self, b):
        key = (CacheKeys.BackupSetInfo, b)
        info = self.cache.retrieve(key)
        if info:
            return info
        info = self.tardis.getBackupSetInfo(b)
        self.cache.insert(key, info)
        return info

    def lastBackupSet(self, completed):
        key = (CacheKeys.LastBackupSet, completed)
        backupset = self.cache.retrieve(key)
        if backupset:
            return backupset
        backupset = self.tardis.lastBackupSet(completed=completed)
        self.cache.insert(key, backupset)
        return backupset

    def getDirInfo(self, path):
        """ Return the inode and backupset of a directory """
        key = (CacheKeys.DirInfo, path)
        info = self.cache.retrieve(key)
        if info:
            return info

        parts = getParts(path)
        bsInfo = self.getBackupSetInfo(parts[0])
        if len(parts) == 2:
            # Why is this here?
            # subpath = self.crypt.encryptPath(parts[1])
            fInfo = self.getFileInfoByPath(path)
            info = (bsInfo, fInfo)
        else:
            fInfo = {'inode': 0, 'device': self.rootVId, 'dir': 1}
            info = (bsInfo, fInfo)

        if info:
            self.cache.insert(key, info)
        return info

    def getFileInfoByPath(self, path):
        # First, check the cache
        f = self.fileCache.retrieve(path)
        if f:
            return f

        # Not in the cache, look things up
        (head, tail) = os.path.split(path)
        data = self.getDirInfo(head)
        if data:
            bsInfo, dInfo = data
        else:
            return None

        if bsInfo:
            tail = self.crypt.encryptPath(tail)
            f = self.tardis.getFileInfoByName(tail, (dInfo['inode'], dInfo['device']), bsInfo['backupset'])
        else:
            parts = getParts(path)
            b = self.getBackupSetInfo(parts[0])
            subpath = self.crypt.encryptPath(parts[1])
            f = self.tardis.getFileInfoByPath(subpath, b['backupset'])
        # Cache it.
        self.fileCache.insert(path, f)
        # Return it
        return f

    @functools.lru_cache
    def getGroupId(self, name):
        gInfo = grp.getgrnam(self.crypt.decryptName(name))
        if gInfo:
            return gInfo.gr_gid
        return -1

    @functools.lru_cache
    def getUserId(self, name):
        uInfo = pwd.getpwnam(self.crypt.decryptName(name))
        if uInfo:
            return uInfo.pw_uid
        return -1

    def getattr(self, path, fh=None):
        """
        - st_mode (protection bits)
        - st_ino (inode number)
        - st_dev (device)
        - st_nlink (number of hard links)
        - st_uid (user ID of owner)
        - st_gid (group ID of owner)
        - st_size (size of file, in bytes)
        - st_atime (time of most recent access)
        - st_mtime (time of most recent content modification)
        - st_ctime (platform dependent; time of most recent metadata change on Unix,
                    or the time of creation on Windows).
        """

        path = self.fsEncodeName(path)

        depth = getDepth(path)  # depth of path, zero-based from root
        if depth == 0:
            # Fake the root
            target = self.lastBackupSet(False)
            timestamp = float(target['starttime'])
            st = {
                'st_mode': stat.S_IFDIR | 0o555,
                'st_ino': 0,
                'st_dev': 0,
                'st_nlink': 32,
                'st_uid': 0,
                'st_gid': 0,
                'st_size': 4096,
                'st_atime': timestamp,
                'st_mtime': timestamp,
                'st_ctime': timestamp,
            }
            return st
        if depth == 1:
            # Root directory contents
            lead = getParts(path)
            if lead[0] == self.current:
                target = self.lastBackupSet(True)
                timestamp = float(target['endtime'])
                st = {
                    'st_mode': stat.S_IFLNK | 0o755,
                    'st_ino': 1,
                    'st_dev': 0,
                    'st_nlink': 1,
                    'st_uid': 0,
                    'st_gid': 0,
                    'st_size': 4096,
                    'st_atime': timestamp,
                    'st_mtime': timestamp,
                    'st_ctime': timestamp
                }
                return st
            f = self.getBackupSetInfo(lead[0])
            if f:
                timestamp = float(f['starttime'])
                st = {
                    'st_mode': stat.S_IFDIR | 0o555,
                    'st_ino': int(float(f['starttime'])),
                    'st_dev': 0,
                    'st_nlink': 2,
                    'st_uid': 0,
                    'st_gid': 0,
                    'st_size': 4096,
                    'st_atime': timestamp,
                    'st_mtime': timestamp,
                    'st_ctime': timestamp
                }
                return st
        else:
            f = self.getFileInfoByPath(path)
            if f:
                st = {
                    'st_mode': f["mode"],
                    'st_ino': f["inode"],
                    'st_dev': 0,
                    'st_nlink': f["nlinks"],
                    'st_uid': Util.getUserId(self.crypt.decryptName(f["username"])),
                    'st_gid': Util.getGroupId(self.crypt.decryptName(f["groupname"])),
                    'st_atime': f["mtime"],
                    'st_mtime': f["mtime"],
                    'st_ctime': f["ctime"]
                }
                if f["size"] is not None:
                    st['st_size'] = int(f["size"])
                elif f["dir"]:
                    st['st_size'] = 4096       # Arbitrary number
                else:
                    st['st_size'] = 0
                return st
        logger.debug("File not found: %s", path)
        raise FuseOSError(errno.ENOENT)

    def readdir(self, path, fh):
        parent = None

        path = self.fsEncodeName(path)

        key = (CacheKeys.DirContents, path)
        dirents = self.cache.retrieve(key)
        if not dirents:
            dirents = ['.', '..']
            depth = getDepth(path)
            if depth == 0:
                dirents.append(self.current)
                entries = self.tardis.listBackupSets()
                dirents.extend([y['name'] for y in entries])
            else:
                parts = getParts(path)
                if depth == 1:
                    b = self.getBackupSetInfo(parts[0])
                    entries = self.tardis.readDirectory((0, self.rootVId), b['backupset'])
                else:
                    (b, parent) = self.getDirInfo(path)
                    entries = self.tardis.readDirectory((parent["inode"], parent["device"]), b['backupset'])

                # For each entry, cache it, so a later getattr() call can use it.
                # Get attr will typically be called promptly after a call to
                now = time.time()
                for e in entries:
                    name = self.fsEncodeName(self.crypt.decryptName(e['name']))
                    p = os.path.join(path, name)
                    self.fileCache.insert(p, e, now=now)
                    dirents.append(name)
            self.cache.insert(key, dirents)

        # Now, return each entry in the list.
        yield from dirents

    def chmod(self, path, mode):
        raise FuseOSError(errno.EROFS)

    def chown(self, path, uid, gid):
        raise FuseOSError(errno.EROFS)

    def fsync(self, path, datasync, fh):
        raise FuseOSError(errno.EROFS)

    def link(self, target, source):
        raise FuseOSError(errno.EROFS)

    def mkdir(self, path, mode):
        raise FuseOSError(errno.EROFS)

    def mknod(self, path, mode, dev):
        raise FuseOSError(errno.EROFS)

    def open(self, path, flags):
        path = self.fsEncodeName(path)

        depth = getDepth(path)  # depth of path, zero-based from root

        if depth < 2:
            raise FuseOSError(errno.ENOENT)

        # TODO: Lock this
        if path in self.files:
            self.files[path]["opens"] += 1
            return 0

        parts = getParts(path)
        b = self.getBackupSetInfo(parts[0])
        if b:
            subpath = parts[1]
            if self.crypt:
                subpath = self.crypt.encryptPath(subpath)
            f = self.regenerator.recoverFile(subpath, b['backupset'], nameEncrypted=True, authenticate=self.authenticate)
            if f:
                logger.debug("Opened file %s", path)
                try:
                    f.flush()
                    f.seek(0)
                except (AttributeError, IOError) as e:
                    logger.exception(e)
                    bytesCopied = 0
                    logger.debug("Copying file to tempfile")
                    temp = tempfile.TemporaryFile()
                    chunk = f.read(65536)
                    while chunk:
                        bytesCopied = bytesCopied + len(chunk)
                        temp.write(chunk)
                        chunk = f.read(65536)
                    f.close()
                    logger.debug("Copied %d bytes to tempfile", bytesCopied)
                    temp.flush()
                    temp.seek(0)
                    f = temp

                self.files[path] = {"file": f, "opens": 1}
                logger.debug("Set files[%s] => %s", path, str(self.files[path]))
                return 0
        # Otherwise.....
        raise FuseOSError(errno.ENOENT)

    def read(self, path, size, offset, fh):
        path = self.fsEncodeName(path)
        f = self.files[path]["file"]
        if f:
            f.seek(offset)
            data = f.read(size)
            logger.debug("Actually read %d bytes of %s", len(data), type(data))
            return data
        logger.warning("No file for path %s", path)
        raise FuseOSError(errno.EINVAL)

    def readlink(self, path):
        path = self.fsEncodeName(path)

        key = (CacheKeys.LinkContents, path)
        link = self.cache.retrieve(key)
        if link:
            return link
        if path == '/' + self.current:
            target = self.lastBackupSet(True)
            logger.debug("Path: %s Target: %s %s", path, target['name'], target['backupset'])
            link = str(target['name'])
            self.cache.insert(key, link)
            return link

        if getDepth(path) > 1:
            parts = getParts(path)
            b = self.getBackupSetInfo(parts[0])
            if b:
                subpath = parts[1]
                if self.crypt:
                    subpath = self.crypt.encryptPath(subpath)
                f = self.regenerator.recoverFile(subpath, b['backupset'], nameEncrypted=True, authenticate=self.authenticate)
                f.flush()
                link = f.readline().decode(self.fsencoding, errors='backslashreplace')
                f.close()
                self.cache.insert(key, link)
                return link
        raise FuseOSError(errno.ENOENT)

    def release(self, path, fh):
        path = self.fsEncodeName(path)

        if self.files[path]:
            self.files[path]["opens"] -= 1
            if self.files[path]["opens"] == 0:
                self.files[path]["file"].close()
                del self.files[path]
            return 0
        raise FuseOSError(errno.EINVAL)

    def rename(self, old, new):
        raise FuseOSError(errno.EROFS)

    def rmdir(self, path):
        raise FuseOSError(errno.EROFS)

    def statfs(self, path):
        if isinstance(self.cacheDir, CacheDir.CacheDir):
            fs = os.statvfs(self.cacheDir.root)

            return dict((key, getattr(fs, key)) for key in (
                'f_bavail', 'f_bfree', 'f_blocks', 'f_bsize', 'f_favail',
                'f_ffree', 'f_files', 'f_flag', 'f_frsize', 'f_namemax'))
        raise FuseOSError(errno.EINVAL)

    def symlink(self, target, source):
        raise FuseOSError(errno.EROFS)

    def truncate(self, path, length, fh):
        raise FuseOSError(errno.EROFS)

    def unlink(self, path):
        raise FuseOSError(errno.EROFS)

    def write(self, path, data, offset, fh):
        raise FuseOSError(errno.EROFS)

    # Map extrenal attribute names for the top level directories to backupset info names
    attrMap = {
        'user.priority' : 'priority',
        'user.complete' : 'completed',
        'user.backupset': 'backupset',
        'user.session'  : 'session'
    }

    def listxattr(self, path):
        path = self.fsEncodeName(path)
        if getDepth(path) == 1:
            parts = getParts(path)
            b = self.getBackupSetInfo(parts[0])
            if b:
                return list(self.attrMap.keys())

        if getDepth(path) > 1:
            parts = getParts(path)
            b = self.getBackupSetInfo(parts[0])
            if b:
                subpath = parts[1]
                if self.crypt:
                    subpath = self.crypt.encryptPath(subpath)
                info = self.tardis.getFileInfoByPath(subpath, b['backupset'])
                if info:
                    attrs = ['user.tardis_checksum', 'user.tardis_since', 'user.tardis_chain']
                    logger.info("xattrs: %s", info['xattrs'])
                    if info['xattrs']:
                        f = self.regenerator.recoverChecksum(info['xattrs'], authenticate=self.authenticate)
                        xattrs = json.loads(f.read())
                        logger.debug("Xattrs: %s", str(xattrs))
                        attrs += list(map(str, list(xattrs.keys())))
                        logger.debug("Adding xattrs: %s", list(xattrs.keys()))
                        logger.info("Xattrs: %s", str(attrs))
                        logger.info("Returning: %s", str(attrs))

                    return attrs

        return None

    def getxattr(self, path, name, position=0):
        path = self.fsEncodeName(path)
        attr = str(name)

        depth = getDepth(path)

        if depth == 1:
            if attr in self.attrMap:
                parts = getParts(path)
                b = self.getBackupSetInfo(parts[0])
                if self.attrMap[attr] in list(b.keys()):
                    return bytes(str(b[self.attrMap[attr]]), 'utf-8')

        if depth > 1:
            parts = getParts(path)
            b = self.getBackupSetInfo(parts[0])

            subpath = parts[1]
            if self.crypt:
                subpath = self.crypt.encryptPath(subpath)
            if attr == 'user.tardis_checksum':
                if b:
                    checksum = self.tardis.getChecksumByPath(subpath, b['backupset'])
                    if checksum:
                        return bytes(str(checksum), 'utf-8')
            elif attr == 'user.tardis_since':
                if b:
                    since = self.tardis.getFirstBackupSet(subpath, b['backupset'])
                    if since:
                        return bytes(str(since), 'utf-8')
            elif attr == 'user.tardis_chain':
                info = self.tardis.getChecksumInfoByPath(subpath, b['backupset'])
                if info:
                    chain = info['chainlength']
                    return bytes(str(chain), 'utf-8')
            else:
                # Must be an imported value.  Let's generate it.
                info = self.getFileInfoByPath(path)
                if info['xattrs']:
                    f = self.regenerator.recoverChecksum(info['xattrs'], authenticate=self.authenticate)
                    xattrs = json.loads(f.read())
                    if attr in xattrs:
                        value = base64.b64decode(xattrs[attr])
                        return bytes(str(value), 'utf-8')

        return bytes('', 'utf-8')

def processMountOpts(mountopts):
    kwargs = {}
    if mountopts:
        for i in mountopts:
            opts = i.split(',')
            for j in opts:
                x = j.split('=', 1)
                if len(x) == 1:
                    kwargs[x[0]] = True
                else:
                    kwargs[x[0]] = x[1]
    return kwargs

def processArgs():
    parser = argparse.ArgumentParser(description='Mount a FUSE filesystem containing tardis backup data', add_help=False, fromfile_prefix_chars='@')

    (_, remaining) = Config.parseConfigOptions(parser)
    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser)

    parser.add_argument('-o',               dest='mountopts', action='append', help='Standard mount -o options')
    parser.add_argument('-d',               dest='debug', action='store_true', default=False, help='Run in FUSE debug mode')
    parser.add_argument('-f',               dest='foreground', action='store_true', default=False, help='Remain in foreground')

    parser.add_argument('--verbose', '-v',  dest='verbose', action='count', default=0, help="Increase verbosity")
    parser.add_argument('--version',            action='version', version='%(prog)s ' + Tardis.__versionstring__,    help='Show the version')
    parser.add_argument('--help', '-h',     action='help')

    parser.add_argument('mountpoint',       nargs=1, help="List of directories to sync")

    Util.addGenCompletions(parser)

    args = parser.parse_args(remaining)

    return args

def delTardisKeys(kwargs):
    keys = ['password', 'pwfile', 'pwprog', 'repository', 'keys']
    for i in keys:
        kwargs.pop(i, None)

def main():
    global logger
    args = processArgs()
    kwargs = processMountOpts(args.mountopts)
    logger = Util.setupLogging(args.verbose)

    try:
        argsDict = vars(args)

        def getarg(name):
            """ Extract a value from either the kwargs, or the regular args """
            return kwargs.get(name) or argsDict.get(name)

        # Extract the password file and program, if they exist.  Names differ, so getarg doesn't work.
        pwfile = kwargs.get('pwfile') or argsDict.get('passwordfile')
        pwprog = kwargs.get('pwprog') or argsDict.get('passwordprog')

        password = Util.getPassword(getarg('password'), pwfile, pwprog, prompt=f"Password:")
        args.password = None
        (tardis, cache, crypt, _) = Util.setupDataConnection(getarg('database'), password, getarg('keys'))
    except TardisDB.AuthenticationException:
        logger.error("Authentication failed.  Incorrect password")
        sys.exit(1)
    except Exception as e:
        logger.error("Repository Connection failed: %s", e)
        sys.exit(1)

    delTardisKeys(kwargs)

    fs = TardisFS(tardis, cache, crypt, args)
    FUSE(fs, args.mountpoint[0], debug=args.debug, nothreads=True, foreground=args.foreground, **kwargs)

if __name__ == "__main__":
    main()
