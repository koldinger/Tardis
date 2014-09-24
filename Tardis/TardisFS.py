#! /usr/bin/python
# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2014, Eric Koldinger, All Rights Reserved.
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

import TardisDB
import CacheDir
import Regenerate
import TardisCrypto

def dirFromList(list):
    """
    Return a properly formatted list of items suitable to a directory listing.
    [['a', 'b', 'c']] => [[('a', 0), ('b', 0), ('c', 0)]]
    """
    return [[(x, 0) for x in list]]

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
    cacheTime = None

    def __init__(self, *args, **kw):
        fuse.Fuse.__init__(self, *args, **kw)
        self.path=None
        self.repoint = False
        self.password = None
        self.passwordfile = None
        self.dbname = "tardis.db"
        self.crypt = None
        logging.basicConfig(level=logging.DEBUG)
        self.log = logging.getLogger("TardisFS")

        self.parser.add_option(mountopt="password",     help="Password for this archive")
        self.parser.add_option(mountopt="passwordfile", help="Read password for this archive from the file")
        self.parser.add_option(mountopt="path",     help="Path to the directory containing the database for this filesystem")
        self.parser.add_option(mountopt="repoint",  help="Make absolute links relative to backupset")
        self.parser.add_option(mountopt="dbname", help="Database Name")

        res = self.parse(values=self, errex=1)

        self.mountpoint = res.mountpoint
        if self.path is None:
            self.log.error("Must specify path")
            sys.exit(1)

        self.log.info("Dir: %s", self.path)
        self.log.info("Repoint Links: %s", self.repoint)
        self.log.info("MountPoint: %s", self.mountpoint)

        password = self.password
        self.password = None
        if self.passwordfile:
            with open(self.passwordfile, "r") as f:
                password = f.readline()

        if password:
            self.crypt = TardisCrypto.TardisCrypto(password)
        password = None

        self.cache = CacheDir.CacheDir(self.path)
        dbPath = os.path.join(self.path, self.dbname)
        self.tardis = TardisDB.TardisDB(dbPath, backup=False)

        self.regenerator = Regenerate.Regenerator(self.cache, self.tardis, crypt=self.crypt)
        self.files = {}

        self.log.debug('Init complete.')

    def checkFlush(self, requestTime = None):
        if requestTime == None:
            requestTime = time()
        if self.cacheTime < requestTime - 30.0:
            self.log.info("Flushing caches")
            self.dirInfo = {} 
            self.backupsets = {}
            self.cacheTime = None
        return requestTime
 
    def getBackupSetInfo(self, b, requestTime = None):
        requestTime = self.checkFlush(requestTime)
        if b in self.backupsets:
            return self.backupsets[b]
        else:
            i = self.tardis.getBackupSetInfo(b)
            if i:
                self.backupsets[b] = i
                if self.cacheTime == None:
                    self.cacheTime = requestTime
            return i

    def decryptNames(self, files):
        outfiles = []
        for x in files:
            x['name'] = self.crypt.decryptFilename(x['name'])
            outfiles.append(x)

        return outfiles

    def getCachedDirInfo(self, path, requestTime=None):
        """ Return the inode and backupset of a directory """
        self.log.info("getCachedDirInfo: %s", path)
        requestTime = self.checkFlush(requestTime)
        if path in self.dirInfo:
            return self.dirInfo[path]
        else:
            parts = getParts(path)
            bsInfo = self.getBackupSetInfo(parts[0])
            if len(parts) == 2:
                subpath = parts[1]
                if self.crypt:
                    subpath = self.crypt.encryptPath(subpath)
                fInfo = self.tardis.getFileInfoByPath(subpath, bsInfo['backupset'])
                self.log.info("fInfo %s %s %s", parts[1], "**", str(fInfo))
                if bsInfo and fInfo and fInfo['dir']:
                    self.dirInfo[path] = (bsInfo, fInfo)
                    if self.cacheTime == None:
                        self.cacheTime = requestTime
            else:
                fInfo = {'inode': 0, 'device': 0}
            return (bsInfo, fInfo)
            
    def getFileInfoByPath(self, path):
        self.log.info("getFileInfoByPath: %s", path)
        (head, tail) = os.path.split(path)
        (bsInfo, dInfo) = self.getCachedDirInfo(head)
        if bsInfo:
            if self.crypt:
                tail = self.crypt.encryptPath(tail)
            self.log.debug(str(dInfo))
            f = self.tardis.getFileInfoByName(tail, (dInfo['inode'], dInfo['device']), bsInfo['backupset'])
        else:
            parts = getParts(path)
            b = self.getBackupSetInfo(parts[0])
            subpath = parts[1]
            if self.crypt:
                subpath = self.crypt.encryptPath(subpath)
            self.log.debug("getFileInfoByPath: %s=>%s", parts[1], subpath)
            f = self.tardis.getFileInfoByPath(subpath, b['backupset'])
        return f

    def fsinit(self):
        self.log.debug("fsinit")

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

        self.log.info("CALL getattr: %s",  path)
        path = unicode(path.decode('utf-8'))
        depth = getDepth(path) # depth of path, zero-based from root

        if depth == 0:
            # Fake the root
            target = self.tardis.lastBackupSet(completed=False)
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
            if (lead[0] == 'Current'):
                target = self.tardis.lastBackupSet()
                timestamp = float(target['starttime'])
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


    def getdir(self, path):
        """
        return: [[('file1', 0), ('file2', 0), ... ]]
        """
        self.log.info('CALL getdir {}'.format(path))
        return -errno.ENOSYS

    def readdir(self, path, offset):
        self.log.info("CALL readdir %s Offset: %d", path, offset)
        inodes = {}
        dirents = ['.', '..']
        parent = None

        depth = getDepth(path)
        if depth == 0:
            dirents.append("Current")
            entries = self.tardis.listBackupSets()
        else:
            parts = getParts(path)
            if depth == 1:
                b = self.getBackupSetInfo(parts[0])
                entries = self.tardis.readDirectory((0, 0), b['backupset'])
            else:
                #parent = self.tardis.getFileInfoByPath(parts[1], b['backupset'])
                (b, parent) = self.getCachedDirInfo(path)
                entries = self.tardis.readDirectory((parent["inode"], parent["device"]), b['backupset'])
            if self.crypt:
                entries = self.decryptNames(entries)

        dirents.extend([y["name"] for y in entries])
        self.log.debug("Direntries: %s", str(dirents))

        for e in dirents:
            yield fuse.Direntry(e)

    def mythread ( self ):
        self.log.info('mythread')
        return -errno.ENOSYS

    def chmod ( self, path, mode ):
        self.log.info('chmod {} {}'.format(path, oct(mode)))
        return -errno.EROFS

    def chown ( self, path, uid, gid ):
        self.log.info( 'chown {} {} {}'.format(path, uid, gid))
        return -errno.EROFS

    def fsync ( self, path, isFsyncFile ):
        self.log.info( 'fsync {} {}'.format(path, isFsyncFile))
        return -errno.EROFS

    def link ( self, targetPath, linkPath ):
        self.log.info( 'link {} {}'.format(targetPath, linkPath))
        return -errno.EROFS

    def mkdir ( self, path, mode ):
        self.log.info( 'mkdir {} {}'.format(path, oct(mode)))
        return -errno.EROFS

    def mknod ( self, path, mode, dev ):
        self.log.info( 'mknod {} {} {}'.format(path, oct(mode), dev))
        return -errno.EROFS

    def open ( self, path, flags ):
        self.log.info('open'.format(path, flags))
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
                    f.seek(0)
                except AttributeError, IOError:
                    self.log.debug("Copying file to tempfile")
                    temp = tempfile.TemporaryFile()
                    chunk = f.read(65536)
                    while chunk:
                        temp.write(chunk)
                        chunk = f.read(65536)
                    f.close()
                    f = temp
                    temp.seek(0)

                self.files[path] = {"file": f, "opens": 1}
                return 0
        # Otherwise.....
        return -errno.ENOENT


    def read ( self, path, length, offset ):
        self.log.info('read {} {} {}'.format(path, length, offset))
        f = self.files[path]["file"]
        if f:
            f.seek(offset)
            return f.read(length)
        return -errno.EINVAL

    def readlink ( self, path ):
        self.log.info('readlink {}'.format(path))
        if path == '/Current':
            target = self.tardis.lastBackupSet()
            self.log.debug("Path: {} Target: {} {}".format(path, target['name'], target['backupset']))
            return str(target['name'])
        elif getDepth(path) > 1:
            parts = getParts(path)
            b = self.getBackupSetInfo(parts[0])
            if b:
                f = self.regenerator.recoverFile(parts[1], b['backupset'], True)
                link = f.readline()
                f.close()
                if self.repoint:
                    if os.path.isabs(link):
                        link = os.path.join(self.mountpoint, parts[0], os.path.relpath(link, "/"))
                return link
        return -errno.ENOENT

    def release ( self, path, flags ):
        if self.files[path]:
            self.files[path]["opens"] -= 1;
            if self.files[path]["opens"] == 0:
                self.files[path]["file"].close()
                del self.files[path]
            return 0
        return -errno.EINVAL

    def rename ( self, oldPath, newPath ):
        return -errno.EROFS

    def rmdir ( self, path ):
        return -errno.EROFS

    def statfs ( self ):
        """ StatFS """
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
        print st
        return st

    def symlink ( self, targetPath, linkPath ):
        return -errno.EROFS

    def truncate ( self, path, size ):
        return -errno.EROFS

    def unlink ( self, path ):
        return -errno.EROFS

    def utime ( self, path, times ):
        return -errno.EROFS

    def write ( self, path, buf, offset ):
        return -errno.EROFS

    attrMap = {
        'user.priority' : 'priority',
        'user.complete' : 'completed',
        'user.backupset': 'backupset',
        'user.session'  : 'session'
    }

    def listxattr ( self, path, size ):
        self.log.info('listxattr {} {}'.format(path, size))
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
                checksum = self.tardis.getChecksumByPath(parts[1], b['backupset'])
                if checksum:
                    return retFunc(['user.checksum', 'user.since', 'user.chain'])

        return None

    def getxattr (self, path, attr, size):
        self.log.info('CALL getxattr: %s %s %s', path, attr, size)
        if size == 0:
            retFunc = lambda x: len(str(x))
        else:
            retFunc = lambda x: str(x)

        if getDepth(path) == 1:
            if attr in self.attrMap:
                parts = getParts(path)
                b = self.getBackupSetInfo(parts[0])
                if self.attrMap[attr] in b:
                    return retFunc(b[self.attrMap[attr]])

        if getDepth(path) > 1:
            parts = getParts(path)
            b = self.getBackupSetInfo(parts[0])

            if attr == 'user.checksum':
                if b:
                    checksum = self.tardis.getChecksumByPath(parts[1], b['backupset'])
                    self.log.debug(str(checksum))
                    if checksum:
                        return retFunc(checksum)
            elif attr == 'user.since':
                if b: 
                    since = self.tardis.getFirstBackupSet(parts[1], b['backupset'])
                    self.log.debug(str(since))
                    if since:
                        return retFunc(since)
            elif attr == 'user.chain':
                    checksum = self.tardis.getChecksumByPath(parts[1], b['backupset'])
                    self.log.debug(str(checksum))
                    if checksum:
                        chain = self.tardis.getChainLength(checksum)
                        self.log.debug(str(chain))
                        return retFunc(chain)
        return 0

def main():
    logger = logging.getLogger('')
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s : %(name)s : %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    fs = TardisFS()
    fs.flags = 0
    fs.multithreaded = 0
    try:
        fs.main()
    except Exception:
        pass

if __name__ == "__main__":
    main()
