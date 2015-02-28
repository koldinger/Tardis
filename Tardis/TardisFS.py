#! /usr/bin/python
# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2015, Eric Koldinger, All Rights Reserved.
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

import fuse

fuse.fuse_python_api = (0, 2)

from time import time

import stat    # for file properties
import os      # for filesystem modes (O_RDONLY, etc)
import errno   # for error number codes (ENOENT, etc)
               # - note: these must be returned as negatives
import sys
import os.path
import logging
import tempfile
import socket
import urlparse

import TardisDB
import RemoteDB
import CacheDir
import Regenerate
import TardisCrypto
import Util
import Cache
import Defaults

_BackupSetInfo = 0
_LastBackupSet = 1
_DirInfo       = 2
_DirContents   = 3
_FileDetails   = 4
_LinkContents  = 5

_infoEnabled    = True

logger = logging.getLogger("Tracer: ")

def tracer(func):
    def trace(*args, **kwargs):
        if _infoEnabled:
            logger.info("CALL %s:(%s %s)", func.__name__, str(args)[1:-1], str(kwargs)[1:-1])
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error("CALL %s:(%s %s)", func.__name__, str(args)[1:-1], str(kwargs)[1:-1])
            logger.error("%s raised exception %s: %s", func.__name__, e.__class__.__name__, str(e))
            logger.exception(e)
            raise e
    return trace

def getDepth(path):
    """
    Return the depth of a given path, zero-based from root ('/')
    """
    if path ==  '/':
        return 0
    else:
        return path.count('/')

def getParts(path):
    """
    Return the slash-separated parts of a given path as a list
    """
    if path == '/':
        return [['/']]
    else:
        return path.strip("/").split('/', 1)

class TardisFS(fuse.Fuse):
    """
    """
    backupsets = {}
    dirInfo = {}
    fsencoding = sys.getfilesystemencoding()

    def __init__(self, *args, **kw):
        super(TardisFS, self).__init__(*args, **kw)

        try:
            client   = Defaults.getDefault('TARDIS_CLIENT')
            database = Defaults.getDefault('TARDIS_DB')
            dbname   = Defaults.getDefault('TARDIS_DBNAME')
            current  = Defaults.getDefault('TARDIS_RECENT_SET')

            # Parameters
            self.database   = database
            self.client     = client
            self.repoint    = False
            self.password   = None
            self.pwfile     = None
            self.pwurl      = None
            self.pwprog     = None
            self.dbname     = dbname
            self.cachetime  = 60
            self.nocrypt    = True
            self.current    = current

            self.crypt      = None
            #logging.basicConfig(level=logging.INFO)
            self.log = logging.getLogger("TardisFS")

            self.parser.add_option(mountopt="database",     help="Path to the Tardis database directory")
            self.parser.add_option(mountopt="client",       help="Client to load database for")
            self.parser.add_option(mountopt="password",     help="Password for this archive (use '-o password=' to prompt for password)")
            self.parser.add_option(mountopt="pwfile",       help="Read password for this archive from the file")
            self.parser.add_option(mountopt="pwurl",        help="Read password from the specified URL")
            self.parser.add_option(mountopt="pwprog",       help="Use the specified program to generate the password on stdout")
            self.parser.add_option(mountopt="repoint",      help="Make absolute links relative to backupset")
            self.parser.add_option(mountopt="dbname",       help="Database Name")
            self.parser.add_option(mountopt="cachetime",    help="Lifetime of cached elements in seconds")
            self.parser.add_option(mountopt='nocrypt',      help="Disable encryption")
            self.parser.add_option(mountopt='current',      help="Name to use for most recent complete backup")

            res = self.parse(values=self, errex=1)

            self.mountpoint = res.mountpoint

            self.log.info("Database: %s", self.database)
            self.log.info("Client: %s", self.client)
            self.log.info("Repoint Links: %s", self.repoint)
            self.log.info("MountPoint: %s", self.mountpoint)
            self.log.info("DBName: %s", self.dbname)

            self.name = "TardisFS:<{}/{}>".format(self.database, self.client)

            password = Util.getPassword(self.password, self.pwfile, self.pwurl, self.pwprog, prompt="Password for %s: " % (self.client))
            self.password = None

            self.cache      = Cache.Cache(0, float(self.cachetime))
            self.fileCache  = Cache.Cache(0, float(self.cachetime))

            if password:
                self.crypt = TardisCrypto.TardisCrypto(password, self.client)
            password = None

            token = None
            if self.crypt:
                token = self.crypt.createToken()

            # Remove the crypto object if not encyrpting files.
            if self.nocrypt is None:
                self.crypt = None

            try:
                loc = urlparse.urlparse(self.database)
                if (loc.scheme == 'http') or (loc.scheme == 'https'):
                    self.tardis = RemoteDB.RemoteDB(self.database, self.client, token=token)
                    self.cacheDir = self.tardis
                    self.path = None
                else:
                   self.path = os.path.join(loc.path, self.client)
                   self.cacheDir = CacheDir.CacheDir(self.path, create=False)
                   dbPath = os.path.join(self.path, self.dbname)
                   self.tardis = TardisDB.TardisDB(dbPath, token=token)

                self.regenerator = Regenerate.Regenerator(self.cacheDir, self.tardis, crypt=self.crypt)
                self.files = {}
            except Exception as e:
                self.log.critical("Could not initialize: %s", str(e))
                self.log.exception(e)
                sys.exit(1)

            self.log.debug('Init complete.')
        except Exception as e:
            self.log.exception(e)
            sys.exit(2)

    def __repr__(self):
        return self.name

    def fsEncodeName(self, name):
        if isinstance(name, bytes):
            return name
        else:
            return name.encode(self.fsencoding)

    def getBackupSetInfo(self, b, requestTime = None):
        key = (_BackupSetInfo, b)
        info = self.cache.retrieve(key)
        if info:
            return info
        info = self.tardis.getBackupSetInfo(b)
        self.cache.insert(key, info)
        return info

    def lastBackupSet(self, completed):
        key = (_LastBackupSet, completed)
        backupset = self.cache.retrieve(key)
        if backupset:
            return backupset
        backupset = self.tardis.lastBackupSet(completed=completed)
        self.cache.insert(key, backupset)
        return backupset

    def decryptNames(self, files):
        outfiles = []
        for x in files:
            y = dict(zip(x.keys(), x))
            y['name'] = self.crypt.decryptFilename(x['name'])
            outfiles.append(y)

        return outfiles

    def getDirInfo(self, path):
        """ Return the inode and backupset of a directory """
        #self.log.info("getDirInfo: %s", path)
        key = (_DirInfo, path)
        info = self.cache.retrieve(key)
        if info:
            return info

        #self.log.debug("No cache info available for %s", path)
        parts = getParts(path)
        bsInfo = self.getBackupSetInfo(parts[0])
        if len(parts) == 2:
            subpath = parts[1]
            if self.crypt:
                subpath = self.crypt.encryptPath(subpath)
            #fInfo = self.getFileInfoByPath(subpath, bsInfo['backupset'])
            fInfo = self.getFileInfoByPath(path)
            #self.log.info("fInfo %s %s %s", parts[1], "**", str(fInfo))
            info = (bsInfo, fInfo)
        else:
            fInfo = {'inode': 0, 'device': 0, 'dir': 1}
            info = (bsInfo, fInfo)

        if info:
            self.cache.insert(key, info)
        return info
            
    def getFileInfoByPath(self, path):
        #self.log.info("getFileInfoByPath: %s", path)

        # First, check the cache
        f = self.fileCache.retrieve(path)
        if f:
            #self.log.debug("getFileInfoByPath: %s found in cache", path)
            return f

        # Not in the cache, look things up
        #self.log.debug("File info for %s not in cache", path)
        (head, tail) = os.path.split(path)
        data = (bsInfo, dInfo) = self.getDirInfo(head)
        if data:
            bsInfo, dInfo = data
        else:
            return None

        if bsInfo:
            if self.crypt:
                tail = self.crypt.encryptPath(tail)
            #self.log.debug(str(dInfo))
            f = self.tardis.getFileInfoByName(tail, (dInfo['inode'], dInfo['device']), bsInfo['backupset'])
        else:
            parts = getParts(path)
            b = self.getBackupSetInfo(parts[0])
            subpath = parts[1]
            if self.crypt:
                subpath = self.crypt.encryptPath(subpath)
            #self.log.debug("getFileInfoByPath: %s=>%s", parts[1], subpath)
            f = self.tardis.getFileInfoByPath(subpath, b['backupset'])
        # Cache it.
        self.fileCache.insert(path, f)
        # Return it
        return f

    @tracer
    def fsinit(self):
        global _infoEnabled
        _infoEnabled = logger.isEnabledFor(logging.INFO)
        pass

    @tracer
    def getattr(self, path):
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

        #self.log.info("CALL getattr: %s",  path)
        path = self.fsEncodeName(path)

        depth = getDepth(path) # depth of path, zero-based from root
        if depth == 0:
            # Fake the root
            target = self.lastBackupSet(False)
            timestamp = float(target['starttime'])
            st = fuse.Stat()
            st.st_mode = stat.S_IFDIR | 0555
            st.st_ino = 0
            st.st_dev = 0
            st.st_nlink = 32
            st.st_uid = 0
            st.st_gid = 0
            st.st_size = 4096
            st.st_atime = timestamp
            st.st_mtime = timestamp
            st.st_ctime = timestamp
            return st
        elif depth == 1:
            # Root directory contents
            lead = getParts(path)
            st = fuse.Stat()
            if (lead[0] == self.current):
                target = self.lastBackupSet(True)
                timestamp = float(target['endtime'])
                st.st_mode = stat.S_IFLNK | 0755
                st.st_ino = 1
                st.st_dev = 0
                st.st_nlink = 1
                st.st_uid = 0
                st.st_gid = 0
                st.st_size = 4096
                st.st_atime = timestamp
                st.st_mtime = timestamp
                st.st_ctime = timestamp
                return st
            else:
                f = self.getBackupSetInfo(lead[0])
                #self.log.debug("Got backupset info for %s: %s", lead[0], str(f))
                if f:
                    st = fuse.Stat()
                    timestamp = float(f['starttime'])
                    st.st_mode = stat.S_IFDIR | 0555
                    st.st_ino = int(float(f['starttime']))
                    st.st_dev = 0
                    st.st_nlink = 2
                    st.st_uid = 0
                    st.st_gid = 0
                    st.st_size = 4096
                    st.st_atime = timestamp
                    st.st_mtime = timestamp
                    st.st_ctime = timestamp
                    return st
        else:
            f = self.getFileInfoByPath(path)
            if f:
                st = fuse.Stat()
                st.st_mode = f["mode"]
                st.st_ino = f["inode"]
                st.st_dev = 0
                st.st_nlink = f["nlinks"]
                st.st_uid = f["uid"]
                st.st_gid = f["gid"]
                if f["size"] is not None:
                    st.st_size = int(f["size"])
                elif f["dir"]:
                    st.st_size = 4096       # Arbitrary number
                else:
                    st.st_size = 0
                st.st_atime = f["mtime"]
                st.st_mtime = f["mtime"]
                st.st_ctime = f["ctime"]
                return st
        return -errno.ENOENT


    @tracer
    def getdir(self, path):
        """
        return: [[('file1', 0), ('file2', 0), ... ]]
        """
        #self.log.info('CALL getdir {}'.format(path))
        return -errno.ENOSYS

    @tracer
    def readdir(self, path, offset):
        #self.log.info("CALL readdir %s Offset: %d", path, offset)
        inodes = {}
        parent = None

        path = self.fsEncodeName(path)

        key = (_DirContents, path)
        dirents = self.cache.retrieve(key)
        if not dirents:
            dirents = [('.', stat.S_IFDIR), ('..', stat.S_IFDIR)]
            depth = getDepth(path)
            if depth == 0:
                dirents.append((self.current, stat.S_IFLNK))
                entries = self.tardis.listBackupSets()
                dirents.extend([(y['name'], stat.S_IFDIR) for y in entries])
            else:
                parts = getParts(path)
                if depth == 1:
                    b = self.getBackupSetInfo(parts[0])
                    entries = self.tardis.readDirectory((0, 0), b['backupset'])
                else:
                    (b, parent) = self.getDirInfo(path)
                    entries = self.tardis.readDirectory((parent["inode"], parent["device"]), b['backupset'])
                if self.crypt:
                    entries = self.decryptNames(entries)

                # For each entry, cache it, so a later getattr() call can use it.
                # Get attr will typically be called promptly after a call to 
                now = time()
                for e in entries:
                    name = self.fsEncodeName(e['name'])
                    p = os.path.join(path, name)
                    self.fileCache.insert(p, e, now=now)
                    dirents.append((name, e['mode']))
            self.cache.insert(key, dirents)

        #self.log.debug("Direntries: %s", str(dirents))

        # Now, return each entry in the list.
        for e in dirents:
            (name, mode) = e
            #self.log.debug("readdir %s yielding dir entry for %s", path, e)
            yield fuse.Direntry(name, type=stat.S_IFMT(mode))

    @tracer
    def mythread ( self ):
        #self.log.info('mythread')
        return -errno.ENOSYS

    @tracer
    def chmod ( self, path, mode ):
        #self.log.info('CALL chmod {} {}'.format(path, oct(mode)))
        return -errno.EROFS

    @tracer
    def chown ( self, path, uid, gid ):
        #self.log.info( 'CALL chown {} {} {}'.format(path, uid, gid))
        return -errno.EROFS

    @tracer
    def fsync ( self, path, isFsyncFile ):
        #self.log.info( 'CALL fsync {} {}'.format(path, isFsyncFile))
        return -errno.EROFS

    @tracer
    def link ( self, targetPath, linkPath ):
        #self.log.info( 'CALL link {} {}'.format(targetPath, linkPath))
        return -errno.EROFS

    @tracer
    def mkdir ( self, path, mode ):
        #self.log.info( 'CALL mkdir {} {}'.format(path, oct(mode)))
        return -errno.EROFS

    @tracer
    def mknod ( self, path, mode, dev ):
        #self.log.info( 'CALL mknod {} {} {}'.format(path, oct(mode), dev))
        return -errno.EROFS

    @tracer
    def open ( self, path, flags ):
        #self.log.info('CALL open {} {})'.format(path, flags))
        path = self.fsEncodeName(path)

        depth = getDepth(path) # depth of path, zero-based from root

        if (depth < 2):
            return -errno.ENOENT

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
            f = self.regenerator.recoverFile(subpath, b['backupset'], True)
            if f:
                try:
                    f.flush()
                    f.seek(0)
                except AttributeError, IOError:
                    bytesCopied = 0
                    self.log.debug("Copying file to tempfile")
                    temp = tempfile.TemporaryFile()
                    chunk = f.read(65536)
                    while chunk:
                        bytesCopied = bytesCopied + len(chunk)
                        temp.write(chunk)
                        chunk = f.read(65536)
                    f.close()
                    self.log.debug("Copied %d bytes to tempfile", bytesCopied)
                    temp.flush()
                    temp.seek(0)
                    f = temp

                self.files[path] = {"file": f, "opens": 1}
                return 0
        # Otherwise.....
        return -errno.ENOENT


    @tracer
    def read ( self, path, length, offset ):
        #self.log.info('CALL read {} {} {}'.format(path, length, offset))
        f = self.files[path]["file"]
        if f:
            f.seek(offset)
            return f.read(length)
        return -errno.EINVAL

    @tracer
    def readlink ( self, path ):
        #self.log.info('CALL readlink {}'.format(path))
        path = self.fsEncodeName(path)

        key = (_LinkContents, path)
        link = self.cache.retrieve(key)
        if link:
            return link
        if path == '/' + self.current:
            target = self.lastBackupSet(True)
            self.log.debug("Path: {} Target: {} {}".format(path, target['name'], target['backupset']))
            link = str(target['name'])
            self.cache.insert(key, link)
            return link
        elif getDepth(path) > 1:
            parts = getParts(path)
            b = self.getBackupSetInfo(parts[0])
            if b:
                f = self.regenerator.recoverFile(parts[1], b['backupset'], True)
                f.flush()
                link = f.readline()
                f.close()
                if self.repoint:
                    if os.path.isabs(link):
                        link = os.path.join(self.mountpoint, parts[0], os.path.relpath(link, "/"))
                self.cache.insert(key, link)
                return link
        return -errno.ENOENT

    @tracer
    def release ( self, path, flags ):
        path = self.fsEncodeName(path)

        if self.files[path]:
            self.files[path]["opens"] -= 1;
            if self.files[path]["opens"] == 0:
                self.files[path]["file"].close()
                del self.files[path]
            return 0
        return -errno.EINVAL

    @tracer
    def rename ( self, oldPath, newPath ):
        #self.log.info('CALL rename {} {}'.format(oldPath, newPath))
        return -errno.EROFS

    @tracer
    def rmdir ( self, path ):
        #self.log.info('CALL rmdir {}'.format(path))
        return -errno.EROFS

    @tracer
    def statfs ( self ):
        """ StatFS """
        #self.log.info('CALL statfs')
        if self.path:
            fs = os.statvfs(self.path)

            st = fuse.Stat()
            st.f_bsize   = fs.f_bsize
            st.f_frsize  = fs.f_frsize
            st.f_blocks  = fs.f_blocks
            st.f_bfree   = fs.f_bfree
            st.f_bavail  = fs.f_bavail
            st.f_files   = fs.f_files
            st.f_ffree   = fs.f_ffree
            st.f_favail  = fs.f_favail
            st.f_flag    = fs.f_flag
            st.f_namemax = fs.f_namemax
            return st
        else:
            return -errorno.EINVAL

    def symlink ( self, targetPath, linkPath ):
        #self.log.info('CALL symlink {} {}'.format(path, linkPath))
        return -errno.EROFS

    def truncate ( self, path, size ):
        #self.log.info('CALL truncate {} {}'.format(path, size))
        return -errno.EROFS

    def unlink ( self, path ):
        #self.log.info('CALL unlink {}'.format(path))
        return -errno.EROFS

    def utime ( self, path, times ):
        #self.log.info('CALL utime {} {} '.format(path, str(times)))
        return -errno.EROFS

    def write ( self, path, buf, offset ):
        #self.log.info('CALL write {} {} {}'.format(path, offset, len(buf)))
        return -errno.EROFS

    # Map extrenal attribute names for the top level directories to backupset info names
    attrMap = {
        'user.priority' : 'priority',
        'user.complete' : 'completed',
        'user.backupset': 'backupset',
        'user.session'  : 'session'
    }

    @tracer
    def listxattr ( self, path, size ):
        path = self.fsEncodeName(path)
        #self.log.info('CALL listxattr {} {}'.format(path, size))
        if size == 0:
            retFunc = lambda x: len("".join(x)) + len(str(x))
        else:
            retFunc = lambda x: x

        if (getDepth(path) == 1):
            parts = getParts(path)
            b = self.getBackupSetInfo(parts[0])
            if b:
                return retFunc(self.attrMap.keys())

        if (getDepth(path) > 1):
            parts = getParts(path)
            b = self.getBackupSetInfo(parts[0])
            if b:
                subpath = parts[1]
                if self.crypt:
                    subpath = self.crypt.encryptPath(subpath)
                checksum = self.tardis.getChecksumByPath(subpath, b['backupset'])
                if checksum:
                    return retFunc(['user.checksum', 'user.since', 'user.chain'])

        return None

    @tracer
    def getxattr (self, path, attr, size):
        path = self.fsEncodeName(path)
        #self.log.info('CALL getxattr: %s %s %s', path, attr, size)
        if size == 0:
            retFunc = lambda x: len(str(x))
        else:
            retFunc = lambda x: str(x)

        depth = getDepth(path)

        if depth == 1:
            if attr in self.attrMap:
                parts = getParts(path)
                b = self.getBackupSetInfo(parts[0])
                if self.attrMap[attr] in b.keys():
                    return retFunc(b[self.attrMap[attr]])

        if depth > 1:
            parts = getParts(path)
            b = self.getBackupSetInfo(parts[0])

            subpath = parts[1]
            if self.crypt:
                subpath = self.crypt.encryptPath(subpath)
            if attr == 'user.checksum':
                if b:
                    checksum = self.tardis.getChecksumByPath(subpath, b['backupset'])
                    #self.log.debug(str(checksum))
                    if checksum:
                        return retFunc(checksum)
            elif attr == 'user.since':
                if b: 
                    since = self.tardis.getFirstBackupSet(subpath, b['backupset'])
                    #self.log.debug(str(since))
                    if since:
                        return retFunc(since)
            elif attr == 'user.chain':
                    info = self.tardis.getChecksumInfoByPath(subpath, b['backupset'])
                    #self.log.debug(str(checksum))
                    if info:
                        chain = str(info['chainlength'])
                        self.log.debug(str(chain))
                        return retFunc(chain)
        return 0

def main():
    #logging.basicConfig()
    logger = logging.getLogger('')
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s : %(name)s : %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    try:
        fs = TardisFS()
    except:
        sys.exit(1)

    fs.flags = 0
    fs.multithreaded = 0
    try:
        fs.main()
    except Exception:
        pass

if __name__ == "__main__":
    main()
