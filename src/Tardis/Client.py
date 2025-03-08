# vi: set et sw=4 sts=4 fileencoding=utf-8
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

import sys
import os
import os.path
import logging
import logging.handlers
import glob
import re
import itertools
import json
import argparse
import configparser
import time
import datetime
import base64
import tempfile
import io
import shlex
import urllib.parse
import functools
import stat
import uuid
import errno
import unicodedata
import pprint
import traceback
import threading
import socket
import pwd
import grp
import concurrent.futures

from collections import defaultdict, deque
from binascii import hexlify
from dataclasses import dataclass

import magic
import pid
import parsedatetime
import srp
import colorlog

import Tardis
from . import TardisCrypto
from . import CompressedBuffer
from . import Connection
from . import Util
from . import Defaults
from . import librsync
from . import MultiFormatter
from . import StatusBar
from . import Backend
from . import ThreadedScheduler
from . import Protocol
from . import Messenger
from . import log

# from icecream import ic
# ic.configureOutput(includeContext=True)
# ic.disable()

import faulthandler
import signal
faulthandler.register(signal.SIGUSR1)

features = Tardis.check_features()
support_xattr = 'xattr' in features
support_acl   = 'pylibacl' in features

if support_xattr:
    import xattr
if support_acl:
    import posix1e

globalExcludeFile   = Defaults.getDefault('TARDIS_GLOBAL_EXCLUDES')

local_config = Defaults.getDefault('TARDIS_LOCAL_CONFIG')
if not os.path.exists(local_config):
    local_config = Defaults.getDefault('TARDIS_DAEMON_CONFIG')

basePathChoices = ["none", "common", "full"]
msgCompressionChoices = ["none", "zlib", "zlib-stream", "snappy"]
reportChoices = ["all", "dirs", "none"]

configDefaults = {
    # Remote Socket connectionk params
    'Server':               Defaults.getDefault('TARDIS_SERVER'),
    'Port':                 Defaults.getDefault('TARDIS_PORT'),
    # Local Direct connect params
    'BaseDir':              Defaults.getDefault('TARDIS_DB'),

    'Local':                '',

    'Client':               Defaults.getDefault('TARDIS_CLIENT'),
    'Force':                str(False),
    'Full':                 str(False),
    'Timeout':              str(300.0),
    'Password':             None,
    'PasswordFile':         Defaults.getDefault('TARDIS_PWFILE'),
    'PasswordProg':         None,
    'Crypt':                str(True),
    'KeyFile':              Defaults.getDefault('TARDIS_KEYFILE'),
    'ValidateCerts':        Defaults.getDefault('TARDIS_VALIDATE_CERTS'),
    'SendClientConfig':     Defaults.getDefault('TARDIS_SEND_CONFIG'),
    'CompressData':         'none',
    'CompressMin':          str(4096),
    'NoCompressFile':       Defaults.getDefault('TARDIS_NOCOMPRESS'),
    'NoCompress':           '',
    'CompressMsgs':         'none',
    'Purge':                str(False),
    'IgnoreCVS':            str(False),
    'SkipCaches':           str(False),
    'SendSig':              str(False),
    'ExcludePatterns':      '',
    'ExcludeDirs':          '',
    'GlobalExcludeFileName':Defaults.getDefault('TARDIS_GLOBAL_EXCLUDES'),
    'ExcludeFileName':      Defaults.getDefault('TARDIS_EXCLUDES'),
    'LocalExcludeFileName': Defaults.getDefault('TARDIS_LOCAL_EXCLUDES'),
    'SkipFileName':         Defaults.getDefault('TARDIS_SKIP'),
    'ExcludeNoAccess':      str(True),
    'LogFiles':             '',
    'Verbosity':            str(0),
    'Stats':                str(False),
    'Report':               'none',
    'BasePath':             '',
    'Directories':          '.',
    # Backend parameters
    'Formats':              'Monthly-%Y-%m, Weekly-%Y-%U, Daily-%Y-%m-%d',
    'Priorities':           '40, 30, 20',
    'KeepDays':             '0, 180, 30',
    'ForceFull':            '0, 0, 0',
    'Umask':                '027',
    'User':                 '',
    'Group':                '',
    'CksContent':           '65536',
    'AutoPurge':            str(False),
    'SaveConfig':           str(True),
    'AllowClientOverrides': str(True),
    'AllowSchemaUpgrades':  str(False),
    'SaveFull':             str(False),
    'MaxDeltaChain':        '5',
    'MaxChangePercent':     '50',
    'DBBackups':            '0',
    'LinkBasis':            str(False),
    'RequirePassword':      str(False)
}

excludeDirs         = []

starttime           = None

encoding            = None

systemencoding      = sys.getfilesystemencoding()


purgePriority       = None
purgeTime           = None

globalExcludes      = set()
cvsExcludes         = ["RCS", "SCCS", "CVS", "CVS.adm", "RCSLOG", "cvslog.*", "tags", "TAGS", ".make.state", ".nse_depinfo",
                       "*~", "#*", ".#*", ",*", "_$*", "*$", "*.old", "*.bak", "*.BAK", "*.orig", "*.rej", ".del-*", "*.a",
                       "*.olb", "*.o", "*.obj", "*.so", "*.exe", "*.Z", "*.elc", "*.ln", "core", ".*.swp", ".*.swo",
                       ".svn", ".git", ".hg", ".bzr"]
verbosity           = 0

conn:       Connection.ProtocolConnection
messenger:  Messenger.Messenger
args:       argparse.Namespace

directoryQueue      = deque()

cloneDirs           = []
cloneContents       = {}
# A cache of metadata.  Since many files can have the same metadata, we check that
# that we haven't sent it yet.
metaCache           = {}
# When we encounter new metadata, keep it here until we flush it to the server.
newmeta             = []

noCompTypes         = []

crypt: TardisCrypto.CryptoScheme
logger: logging.Logger
exceptionLogger: Util.ExceptionLogger

srpUsr              = None

lastTimestamp       = None

# Stats block.
# dirs/files/links  == Number of directories/files/links backed up total
# new/delta         == Number of new/delta files sent
# backed            == Total size of data represented by the backup.
# dataSent          == Number of data bytes sent this run (not including messages)
# dataBacked        == Number of bytes backed up this run
# Example: If you have 100 files, and 99 of them are already backed up (ie, one new), backed would be 100, but new would be 1.
# dataSent is the compressed and encrypted size of the files (or deltas) sent in this run, but dataBacked is the total size of
# the files.
stats = { 'dirs': 0, 'files': 0, 'links': 0, 'backed': 0, 'dataSent': 0, 'dataBacked': 0, 'new': 0, 'delta': 0, 'gone': 0, 'denied': 0 }

report = {}

class InodeEntry:
    """
    Dataclass to hold inodes, so we can determine which files they correspond to
    """
    def __init__(self):
        self.paths = []
        self.numEntries = 0
        self.finfo = None

class InodeDB:
    """
    Database of inodes that we currently care about.
    """

    def __init__(self):
        self.db = defaultdict(InodeEntry)

    def insert(self, inode, finfo, path):
        entry = self.db[inode]
        entry.numEntries += 1
        entry.paths.append(path)
        entry.finfo = finfo

    def get(self, inode, num=0):
        if inode not in self.db:
            return (None, None)
        entry = self.db[inode]
        if num >= len(entry.paths):
            return (entry.finfo, None)
        return (entry.finfo, entry.paths[num])

    def delete(self, inode, path=None):
        if inode in self.db:
            entry = self.db[inode]
            entry.numEntries -= 1
            if entry.numEntries == 0:
                self.db.pop(inode)
            if path:
                entry.paths.remove(path)
            else:
                entry.paths.pop(0)

inodeDB             = InodeDB()
dirHashes           = {}

def getInodeDBName(inode):
    (_, name) = inodeDB.get(inode)
    if name:
        return name
    return "Unknown"


class CustomArgumentParser(argparse.ArgumentParser):
    """
    A custom argument parser to nicely handle argument files, and strip out any blank lines or commented lines
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def convert_arg_line_to_args(self, arg_line):
        for arg in arg_line.split():
            if not arg.strip():
                continue
            if arg[0] == '#':
                break
            yield arg

class ShortPathStatusBar(StatusBar.StatusBar):
    """
    Extend the status bar class so that it shorten's pathnames into a pathname field
    """
    def processTrailer(self, length, string):
        return Util.shortPath(string, length)

class ProtocolError(Exception):
    """
    Communications protocol error
    """

class AuthenticationFailed(Exception):
    """
    Authentication failure
    """

class InitFailedException(Exception):
    """
    Initialization error
    """

class ExitRecursionException(Exception):
    def __init__(self, rootException):
        self.rootException = rootException

@dataclass
class DirectoryJob:
    subdir: str
    top: bool
    newdepth: int
    subexcludes: list[str]

@dataclass
class FakeDirEntry:
    dirname: str
    name: str

    @property
    def path(self):
        return os.path.join(self.dirname, self.name)

    def stat(self, follow_symlinks=True):
        if follow_symlinks:
            return os.stat(self.path)
        return os.lstat(self.path)

    def is_dir(self):
        return os.path.isdir(self.path)

def findMountPoint(path):
    if path:
        if os.path.ismount(path):
            return path
        return findMountPoint(os.path.dirname(path))
    return "/"

_deviceCache = {}
def virtualDev(device, path):
    try:
        return _deviceCache[device]
    except KeyError:
        mp = findMountPoint(path)
        h = crypt.getHash()
        h.update(fs_encode(mp))
        digest =  h.hexdigest()
        _deviceCache[device] = digest
        return digest


def setEncoder(fmt):
    global encoder, encoding, decoder
    if fmt == 'base64':
        encoding = "base64"
        encoder  = base64.b64encode
        decoder  = base64.b64decode
    elif fmt == 'bin':
        encoding = "bin"
        encoder = lambda x: x
        decoder = lambda x: x

def fs_encode(val) -> bytes:
    """ Turn filenames into str's (ie, series of bytes) rather than Unicode things """
    if not isinstance(val, bytes):
        return val.encode(systemencoding)
    return val

def checkMessage(message, expected):
    """ Check that a message is of the expected type.  Throw an exception if not """
    if not message['message'] == expected:
        logger.critical(f"Expected {expected} message, received {message['message']}")
        raise ProtocolError(f"Expected {expected} message, received {message['message']}")

def filelist(dirname, excludes, skipfile):
    """ List the files in a directory, except those that match something in a set of patterns """
    if excludes:
        excludeObj = compileExcludes(excludes)
        files = itertools.filterfalse(lambda x: excludeObj.match(x.path), os.scandir(dirname))
    else:
        files = os.scandir(dirname)
    for f in files:
        # if it's a directory, and there's a skipfile in it, then just skip the directory
        if f.is_dir() and os.path.lexists(os.path.join(f, skipfile)):
            continue
        yield f

def msgInfo(resp=None):
    if resp is None:
        resp = currentResponse
    respId = resp['respid']
    respType = resp['message']
    return (respId, respType)

pool = concurrent.futures.ThreadPoolExecutor()

def genChecksum(inode):
    checksum = None
    try:
        (_, pathname) = inodeDB.get(inode)
        setProgress("File [C]:", pathname)

        m = crypt.getHash()
        s = os.lstat(pathname)
        mode = s.st_mode
        if stat.S_ISLNK(mode):
            m.update(fs_encode(os.readlink(pathname)))
        else:
            try:
                with open(pathname, "rb") as f:
                    for chunk in iter(functools.partial(f.read, args.chunksize), b''):
                        if chunk:
                            m.update(chunk)
                        else:
                            break
                    checksum = m.hexdigest()
                    # files.append({ "inode": inode, "checksum": checksum })
            except IOError as e:
                logger.error("Unable to generate checksum for %s: %s", pathname, str(e))
                exceptionLogger.log(e)
                # TODO: Add an error response?
    except KeyError as e:
        (rId, rType) = msgInfo()
        logger.error("Unable to process checksum for %s, not found in inodeDB (%s, %s)", str(inode), rId, rType)
        exceptionLogger.log(e)
    except FileNotFoundError as e:
        logger.error("Unable to stat %s.  File not found", pathname)
        exceptionLogger.log(e)
        # TODO: Add an error response?

    return inode, checksum

def processChecksums(inodes):
    """ Generate checksums for requested checksum files """
    files = []
    jobs = pool.map(genChecksum, inodes)
    for job in jobs:
        inode, checksum = job
        files.append({ "inode": inode, "checksum": checksum })
    message = {
        "message": Protocol.Commands.CKS,
        "files": files
    }

    sendMessage(message)

def logFileInfo(i, c):
    (x, name) = inodeDB.get(i)
    if name:
        size = x.get('size', 0)
        size = Util.fmtSize(size, suffixes=['', 'KB', 'MB', 'GB', 'TB', 'PB'])
        logger.log(log.FILES, "[%c]: %s (%s)", c, Util.shortPath(name), size)
        cname = crypt.encryptPath(name)
        logger.debug("Filename: %s => %s", Util.shortPath(name), Util.shortPath(cname))

def handleAckSum(response):
    checkMessage(response, Protocol.Responses.ACKSUM)
    logfiles = logger.isEnabledFor(log.FILES)

    done    = response.setdefault('done', {})
    content = response.setdefault('content', {})
    delta   = response.setdefault('delta', {})

    # First, delete all the files which are "done", ie, matched
    for i in [tuple(x) for x in done]:
        if logfiles:
            (_, name) = inodeDB.get(i)
            if name:
                logger.log(log.FILES, "[C]: %s", Util.shortPath(name))
        inodeDB.delete(i)

    # First, then send content for any files which don't
    for i in [tuple(x) for x in content]:
        if logfiles:
            logFileInfo(i, 'n')
        sendContent(i, 'Full')
        inodeDB.delete(i)

    for i, cksum in delta:
        inode = tuple(i)
        if logfiles:
            logFileInfo(inode, 'd')
        processDelta(inode, cksum)

def makeEncryptor():
    iv = crypt.getIV()
    encryptor = crypt.getContentEncryptor(iv)
    return (encryptor, iv)

def processDelta(inode, cksum):
    """ Generate a delta and send it.   Requests a signature if it's not available already. """
    if verbosity > 3:
        logger.debug("ProcessDelta: %s %s", inode, getInodeDBName(inode))

    try:
        (_, pathname) = inodeDB.get(inode)

        logger.debug("Requesting checksum for %s:: %s", str(inode), pathname)
        path = crypt.encryptPath(pathname)
        message = {
            "message" : "SGR",
            "inode" : tuple([inode, cksum]),        # FIXME: TODO: Break out checksum into it's own field.
            "path"  : path
        }
        sendMessage(message)
    except KeyError as e:
        logger.error("ProcessDelta: No inode entry for %s", str(inode))
        exceptionLogger.log(e)

def handleSig(response):
    inode = tuple(response['inode'])
    (_, pathname) = inodeDB.get(inode)
    cksum = response['checksum']

    if response['status'] == 'OK':
        logger.debug("Receiving sig file %s: %s", inode, pathname)
        sigfile = io.BytesIO()
        Util.receiveData(messenger, sigfile, log=args.logmessages)
        sigfile.seek(0)
        processSig(inode, sigfile, cksum)
    else:
        logger.warning("No signature file for %s", inode)
        sendContent(inode, 'Full')

def processSig(inode, sigfile, oldchksum):
    def fakeseek(x, y=0):
        return 0

    """ Generate a delta and send it """
    if verbosity > 3:
        logger.debug("processSig: %s %s", inode, getInodeDBName(inode))

    try:
        (_, pathname) = inodeDB.get(inode)
        setProgress("File [D]:", pathname)

        logger.debug("Ready to send Delta: %s -- %s", inode, sigfile)
        if sigfile is not None:
            try:
                newsig = None
                # If we're encrypted, we need to generate a new signature, and send it along
                makeSig = crypt.encrypting() or args.signature

                logger.debug("Generating delta for %s", pathname)

                # Create a buffered reader object, which can generate the checksum and an actual filesize while
                # reading the file.  And, if we need it, the signature
                with open(pathname, "rb") as input:
                    reader = CompressedBuffer.BufferedReader(input, hasher=crypt.getHash(), signature=makeSig)
                    # HACK: Monkeypatch the reader object to have a seek function to keep librsync happy.  Never gets called
                    reader.seek = fakeseek

                    # Generate the delta file
                    delta = librsync.delta(reader, sigfile)

                    # get the auxiliary info
                    checksum = reader.checksum()
                    filesize = reader.size()
                    newsig = reader.signatureFile()

                # Figure out the size of the delta file.  Seek to the end, do a tell, and go back to the start
                # Ugly.
                delta.seek(0, 2)
                deltasize = delta.tell()
                delta.seek(0)
            except librsync.LibrsyncError as e:
                logger.error("Unable able to generate delta stuffs for %s: %s", pathname, str(e))
                logger.error("Cksum: %s -- size %s", oldchksum, sigfile.tell())
                exceptionLogger.log(e)
                sendContent(inode, 'Full')
                return
            except Exception as e:
                logger.warning("Unable to process signature.  Sending full file: %s: %s", pathname, str(e))
                exceptionLogger.log(e)
                sendContent(inode, 'Full')
                return
            finally:
                sigfile.close()

            if deltasize < (filesize * float(args.deltathreshold) / 100.0):
                encrypt, iv = makeEncryptor()
                Util.accumulateStat(stats, 'delta')
                message = {
                    "message": Protocol.Commands.DEL,
                    "inode": inode,
                    "size": filesize,
                    "checksum": checksum,
                    "basis": oldchksum,
                    "encoding": encoding,
                    "encrypted": bool(iv)
                }
                sendMessage(message)
                compress = args.compress if (args.compress and (filesize > args.mincompsize)) else None
                (sent, _, _) = Util.sendData(messenger, delta, encrypt, chunksize=args.chunksize, compress=compress, stats=stats, log=args.logmessages)
                delta.close()

                # If we have a signature, send it.
                sigsize = 0
                if newsig:
                    message = {
                        "message" : "SIG",
                        "checksum": checksum
                    }
                    sendMessage(message)
                    # Send the signature, generated above
                    (sigsize, _, _) = Util.sendData(messenger, newsig, TardisCrypto.NullEncryptor(), chunksize=args.chunksize, compress=False, stats=stats, log=args.logmessages) # Don't bother to encrypt the signature
                    newsig.close()

                if args.report != 'none':
                    x = {
                        'type': 'Delta',
                        'size': sent,
                        'sigsize': sigsize
                    }
                    # Convert to Unicode, and normalize any characters, so lengths become reasonable
                    name = unicodedata.normalize('NFD', pathname)
                    report[os.path.split(name)] = x
                logger.debug("Completed %s -- Checksum %s -- %s bytes, %s signature bytes", Util.shortPath(pathname), checksum, sent, sigsize)
            else:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("Delta size for %s is too large.  Sending full content: Delta: %d File: %d", Util.shortPath(pathname, 40), deltasize, filesize)
                sendContent(inode, 'Full')
        else:
            sendContent(inode, 'Full')
    except KeyError as e:
        logger.error("ProcessDelta: No inode entry for %s", inode)
        logger.debug(repr(traceback.format_stack()))
        exceptionLogger.log(e)

def sendContent(inode, reportType):
    """ Send the content of a file.  Compress and encrypt, as specified by the options. """

    if verbosity > 3:
        logger.debug("SendContent: %s %s %s", inode, reportType, getInodeDBName(inode))
    try:
        checksum = None
        (fileInfo, pathname) = inodeDB.get(inode)
        if pathname:
            mode = fileInfo["mode"]
            filesize = fileInfo["size"]

            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Sending content for %s (%s) -- %s", inode, Util.fmtSize(filesize), Util.shortPath(pathname, 60))

            setProgress("File [N]:", pathname)

            if stat.S_ISDIR(mode):
                return
            encrypt, iv = makeEncryptor()
            message = {
                "message":      Protocol.Commands.CON,
                "inode":        inode,
                "encoding":     encoding,
                "encrypted":    bool(iv)
            }

            # Attempt to open the data source
            # Punt out if unsuccessful
            try:
                if stat.S_ISLNK(mode):
                    # It's a link.  Send the contents of readlink
                    data = io.BytesIO(fs_encode(os.readlink(pathname)))
                else:
                    data = open(pathname, "rb")
            except IOError as e:
                if e.errno == errno.ENOENT:
                    logger.warning("%s disappeared.  Not backed up", pathname)
                    Util.accumulateStat(stats, 'gone')
                elif e.errno == errno.EACCES:
                    logger.warning("Permission denied opening: %s.  Not backed up", pathname)
                    Util.accumulateStat(stats, 'denied')
                else:
                    logger.warning("Unable to open %s: %s", pathname, e.strerror)
                    Util.accumulateStat(stats, 'denied')
                return

            # Attempt to send the data.
            sig = None
            sigsize = 0
            try:
                compress = args.compress if (args.compress and (filesize > args.mincompsize)) else None
                # Check if it's a file type we don't want to compress
                if compress and noCompTypes:
                    mimeType = magic.from_buffer(data.read(128), mime=True)
                    data.seek(0)
                    if mimeType in noCompTypes:
                        logger.debug("Not compressing %s.  Type %s", pathname, mimeType)
                        compress = False
                makeSig = crypt.encrypting() or args.signature
                sendMessage(message)
                (size, checksum, sig) = Util.sendData(messenger, data,
                                                      encrypt,
                                                      hasher=crypt.getHash(),
                                                      chunksize=args.chunksize,
                                                      compress=compress,
                                                      signature=makeSig,
                                                      stats=stats,
                                                      log=args.logmessages)

                if sig:
                    sig.seek(0)
                    message = {
                        "message" : "SIG",
                        "checksum": checksum
                    }
                    sendMessage(message)
                    # Don't bother to encrypt the signature data.   It's not hugely useful
                    # Don't compress.   Signature's don't compress at all.   They're basically random
                    (sigsize, _, _) = Util.sendData(messenger, sig,
                                                    TardisCrypto.NullEncryptor(),
                                                    chunksize=args.chunksize,
                                                    stats=stats,
                                                    log=args.logmessages)
            except Exception as e:
                logger.error("Caught exception during sending of data in %s: %s", pathname, e)
                exceptionLogger.log(e)
            finally:
                if data:
                    data.close()
                if sig:
                    sig.close()

            Util.accumulateStat(stats, 'new')
            if args.report != 'none':
                repInfo = {
                    'type': reportType,
                    'size': size,
                    'sigsize': sigsize
                }
                report[os.path.split(pathname)] = repInfo
            logger.debug("Completed %s -- Checksum %s -- %s bytes, %s signature bytes", Util.shortPath(pathname), checksum, size, sigsize)
    except KeyError as e:
        logger.error("SendContent: No inode entry for %s", inode)
        logger.debug(repr(traceback.format_stack()))
        exceptionLogger.log(e)

def handleAckMeta(response):
    checkMessage(response, Protocol.Responses.ACKMETA)
    content = response.get('content', {})
    done    = response.get('done', {})
    # Ignore the done field.

    message = {
        "message": Protocol.Commands.METADATA,
        "data": []
    }

    for cks in content:
        data = fs_encode(metaCache[cks])
        sz = len(data)
        logger.debug("Sending meta data chunk: %s -- %s", cks, data)
        compress = args.compress if (args.compress and (len(data) > args.mincompsize)) else None
        compressor = CompressedBuffer.getCompressor(compress)
        encrypt, iv = makeEncryptor()

        data = compressor.compress(data)
        x = compressor.flush()
        if x:
            data = data + x
        if iv:
            data = iv + encrypt.encrypt(data) + encrypt.finish()
        chunk = {
            "checksum": cks,
            "encrypted": bool(iv),
            "compressed": compress,
            "size": sz,
            "data": data
        }
        message["data"].append(chunk)

    for cks in done:
        try:
            metaCache.pop(cks)
        except KeyError:
            logger.warning("Metadata value for hash %s not found", cks)

    sendMessage(message)

_defaultHash = None
def sendDirHash(inode):
    global _defaultHash
    if _defaultHash is None:
        _defaultHash = crypt.getHash().hexdigest()

    i = tuple(inode)
    (h, s) = dirHashes.setdefault(i, (_defaultHash, 0))

    message = {
        'message': Protocol.Commands.DHSH,
        'inode'  : inode,
        'hash'   : h,
        'size'   : s
    }

    sendMessage(message)
    try:
        del dirHashes[i]
    except KeyError:
        pass
        # This kindof isn't an error.   The BatchMessages call can cause the sendDirHashes to be sent again, which ends up deleteing
        # the message before it's deleted here.

allContent = []
allDelta   = []
allCkSum   = []
allRefresh = []
allDone    = []

def handleAckDir(message):
    global allContent, allDelta, allCkSum, allRefresh, allDone

    checkMessage(message, Protocol.Responses.ACKDIR)

    content = message.setdefault("content", {})
    done    = message.setdefault("done", {})
    delta   = message.setdefault("delta", {})
    cksum   = message.setdefault("cksum", {})
    refresh = message.setdefault("refresh", {})

    if verbosity > 2:
        path = message['path']
        if crypt and path:
            path = crypt.decryptPath(path)
        logger.debug("Processing ACKDIR: Up-to-date: %3d New Content: %3d Delta: %3d ChkSum: %3d -- %s", len(done), len(content), len(delta), len(cksum), Util.shortPath(path, 40))

    allContent += content
    allDelta   += delta
    allCkSum   += cksum
    allRefresh += refresh
    allDone    += done

def pushFiles():
    global allContent, allDelta, allCkSum, allRefresh, allDone
    logger.debug("Pushing files")

    processed = []

    for i in [tuple(x) for x in allContent]:
        try:
            if logger.isEnabledFor(log.FILES):
                logFileInfo(i, 'N')
            sendContent(i, 'New')
            processed.append(i)
        except Exception as e:
            logger.error("Unable to backup %s: %s", str(i), str(e))
            exceptionLogger.log(e)

    for i in [tuple(x) for x in allRefresh]:
        if logger.isEnabledFor(log.FILES):
            logFileInfo(i, 'R')
        try:
            sendContent(i, 'Full')
            processed.append(i)
        except Exception as e:
            logger.error("Unable to backup %s: %s", str(i), str(e))
            exceptionLogger.log(e)

    logger.debug("Ready to send delta's for %d files: %s", len(allDelta), str(allDelta))
    for i, basis in [tuple(x) for x in allDelta]:
        inode = tuple(i)
        logger.debug("Sending Delta for inode %s - Basis: %s", str(inode), str(basis))
        # If doing a full backup, send the full file, else just a delta.
        try:
            if args.full:
                if logger.isEnabledFor(log.FILES):
                    logFileInfo(inode, 'N')
                sendContent(inode, 'Full')
            else:
                if logger.isEnabledFor(log.FILES):
                    (_, name) = inodeDB.get(inode)
                    if name:
                        logger.log(log.FILES, "[D]: %s", Util.shortPath(name))
                processDelta(inode, basis)
        except Exception as e:
            logger.error("Unable to backup %s: %s ", str(i), str(e))
            exceptionLogger.log(e)

    # clear it out
    for i in processed:
        inodeDB.delete(i)
    for i in [tuple(x) for x in allDone]:
        inodeDB.delete(i)
    allRefresh = []
    allContent = []
    allDelta   = []
    allDone    = []

    # If checksum content is specified, concatenate the checksums and content requests, and handle checksums
    # for all of them.
    if len(allCkSum) > 0:
        cksums = [tuple(x) for x in allCkSum]
        allCkSum   = []             # Clear it out to avoid processing loop
        while cksums:
            processChecksums(cksums[0:args.cksumbatch])
            cksums = cksums[args.cksumbatch:]

    logger.debug("Done pushing")


@functools.cache
def addMeta(meta):
    """
    Add data to the metadata cache
    """
    m = crypt.getHash()
    m.update(bytes(meta, 'utf8'))
    digest = m.hexdigest()
    metaCache[digest] = meta
    newmeta.append(digest)
    return digest

def mkFileInfo(f):
    pathname = f.path
    s = f.stat(follow_symlinks=False)

    # Cleanup any bogus characters
    name = f.name.encode('utf8', 'backslashreplace').decode('utf8')

    mode = s.st_mode

    # If we don't want to even create dir entries for things we can't access, just return None
    # if we can't access the file itself
    if args.skipNoAccess and (not Util.checkPermission(s.st_uid, s.st_gid, mode)):
        return None

    if f.is_dir():
        dirname = os.path.dirname(pathname)
    else:
        dirname = pathname

    if stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
        finfo = {
            'name':   name,
            'inode':  s.st_ino,
            'dir':    stat.S_ISDIR(mode),
            'link':   stat.S_ISLNK(mode),
            'nlinks': s.st_nlink,
            'size':   s.st_size,
            'mtime':  int(s.st_mtime),          # We strip these down to the integer value beacuse FP conversions on the back side can get confused.
            'ctime':  int(s.st_ctime),
            'atime':  int(s.st_atime),
            'mode':   s.st_mode,
            'uid':    s.st_uid,                 # TODO: Remove
            'gid':    s.st_gid,                 # TODO: Remove
            'user':   getUserName(s.st_uid),
            'group':  getGroupName(s.st_gid),
            'dev':    virtualDev(s.st_dev, pathname)
        }

        if support_xattr and args.xattr:
            try:
                attrs = xattr.xattr(pathname, options=xattr.XATTR_NOFOLLOW)
                if len(attrs):
                    # Convert to a set of readable string tuples
                    # We base64 encode the data chunk, as it's often binary
                    # Ugly, but unfortunately necessary
                    attrdict = {str(k):str(base64.b64encode(v), 'utf8') for (k, v) in sorted(attrs.items())}
                    attr_string = json.dumps(attrdict)
                    cks = addMeta(attr_string)
                    finfo['xattr'] = cks
            except Exception:
                logger.warning("Could not read extended attributes from %s.   Ignoring", pathname)

        if support_acl and args.acl and not stat.S_ISLNK(mode):
            # BUG:? FIXME:? ACL section doesn't seem to work on symbolic links.  Instead wants to follow the link.
            # Definitely an issue
            try:
                if posix1e.has_extended(pathname):
                    acl = posix1e.ACL(file=pathname)
                    cks = addMeta(str(acl))
                    finfo['acl'] = cks
            except Exception:
                logger.warning("Could not read ACL's from %s.   Ignoring", pathname.encode('utf8', 'backslashreplace').decode('utf8'))

        # Insert into the inode DB
        inode = (s.st_ino, virtualDev(s.st_dev, pathname))

        inodeDB.insert(inode, finfo, pathname)
    else:
        if verbosity:
            logger.info("Skipping special file: %s", pathname)
        finfo = None
    return finfo

@functools.cache
def getUserName(uid):
    try:
        name = pwd.getpwuid(uid).pw_name
    except Exception as e:
        logger.warning("Unable to retrieve user name for UID %d", uid)
        exceptionLogger.log(e)
        name = str(uid)
    return crypt.encryptName(name)

@functools.cache
def getGroupName(gid):
    try:
        name = grp.getgrgid(gid).gr_name
    except Exception as e:
        logger.warning("Unable to retrieve group name for GID %d", gid)
        exceptionLogger.log(e)
        name = str(gid)
    return crypt.encryptName(name)

def getDirContents(dirname, dirstat, excludes=None):
    """ Read a directory, load any new exclusions, delete the excluded files, and return a list
        of the files, a list of sub directories, and the new list of excluded patterns """

    excludes = excludes or set()
    Util.accumulateStat(stats, 'dirs')
    device = virtualDev(dirstat.st_dev, dirname)

    # Process an exclude file which will be passed on down to the receivers
    newExcludes = loadExcludeFile(os.path.join(dirname, excludeFile))
    newExcludes = newExcludes.union(excludes)
    excludes = newExcludes

    # Add a list of local files to exclude.  These won't get passed to lower directories
    localExcludes = excludes.union(loadExcludeFile(os.path.join(dirname, args.localexcludefile)))

    files = []
    subdirs = []

    try:
        for f in filelist(dirname, localExcludes, args.skipfile):
            try:
                fInfo = mkFileInfo(f)
                if fInfo and (args.crossdev or device == fInfo['dev']):
                    mode = fInfo["mode"]
                    if stat.S_ISLNK(mode):
                        Util.accumulateStat(stats, 'links')
                    elif stat.S_ISREG(mode):
                        Util.accumulateStat(stats, 'files')
                        Util.accumulateStat(stats, 'backed', fInfo['size'])

                    if stat.S_ISDIR(mode):
                        sub = os.path.join(dirname, f)
                        if sub in excludeDirs:
                            logger.debug("%s excluded.  Skipping", sub)
                            continue
                        subdirs.append(sub)

                    files.append(fInfo)
            except (IOError, OSError) as e:
                logger.error("Error processing %s: %s", os.path.join(dirname, f), str(e))
            except Exception as e:
                # Is this necessary?  Fold into above?
                logger.error("Error processing %s: %s", os.path.join(dirname, f), str(e))
                exceptionLogger.log(e)
    except (IOError, OSError) as e:
        logger.error("Error reading directory %s: %s", dir, str(e))

    return (files, subdirs, excludes)

def handleAckClone(message):
    checkMessage(message, Protocol.Responses.ACKCLN)
    if verbosity > 2:
        logger.debug("Processing ACKCLN: Up-to-date: %d New Content: %d", len(message['done']), len(message['content']))

    logdirs = logger.isEnabledFor(log.DIRS)

    content = message.setdefault('content', {})
    done    = message.setdefault('done', {})

    # Purge out what hasn't changed
    for i in done:
        inode = tuple(i)
        if inode in cloneContents:
            (path, files) = cloneContents[inode]
            for f in files:
                key = (f['inode'], f['dev'])
                inodeDB.delete(key)
            del cloneContents[inode]
        else:
            logger.error("Unable to locate info for %s", inode)
        # And the directory.
        inodeDB.delete(inode)

    # Process the directories that have changed
    for i in content:
        finfo = tuple(i)
        if finfo in cloneContents:
            (path, files) = cloneContents[finfo]
            if logdirs:
                logger.log(log.DIRS, "[R]: %s", Util.shortPath(path))
            sendDirChunks(path, finfo, files)
            del cloneContents[finfo]
        else:
            logger.error("Unable to locate info for %s", str(finfo))

def makeCloneMessage():
    global cloneDirs
    message = {
        'message': Protocol.Commands.CLN,
        'clones': cloneDirs
    }
    cloneDirs = []
    return message

def sendClones():
    message = makeCloneMessage()
    sendMessage(message)

def flushClones():
    if cloneDirs:
        logger.debug("Flushing %d clones", len(cloneDirs))
        sendClones()

def sendPurge():
    """ Send a purge message.  Indicate if this time is relative (ie, days before now), or absolute. """
    message = {
        'message': Protocol.Commands.PRG
    }
    relative = args.purgetime is not None
    if purgePriority:
        message['priority'] = purgePriority

    if purgeTime:
        message.update({
            'time': purgeTime,
            'relative': relative
        })

    response = sendAndReceive(message)
    checkMessage(response, Protocol.Responses.ACKPRG)

def sendDirChunks(path, inode, files):
    """ Chunk the directory into dirslice sized chunks, and send each sequentially """
    path = crypt.encryptPath(path)
    (inum, dev) = inode
    vdev = virtualDev(dev, path)

    message = {
        'message': Protocol.Commands.DIR,
        'path'   : path,
        'inode'  : (inum, vdev)
    }

    chunkNum = 0
    for x in range(0, len(files), args.dirslice):
        if verbosity > 3:
            logger.debug("---- Generating chunk %d ----", chunkNum)
        chunkNum += 1
        chunk = files[x : x + args.dirslice]

        # Encrypt the names before sending them out
        for i in chunk:
            i['name'] = crypt.encryptName(i['name'])

        message["files"] = chunk
        message["last"]  = x + args.dirslice > len(files)
        if verbosity > 3:
            logger.debug("---- Sending chunk at %d ----", x)
        sendMessage(message)

    sendDirHash(inode)

def makeMetaMessage():
    global newmeta
    message = {
        'message': Protocol.Commands.META,
        'metadata': newmeta
    }
    newmeta = []
    return message

statusBar: StatusBar.StatusBar | None = None

def initProgressBar(scheduler):
    sbar = ShortPathStatusBar("{__elapsed__} | Dirs: {dirs} | Files: {files} | Full: {new} | Delta: {delta} | Data: {dataSent!B} | {waiting} ({sendQ}, {recvQ}) | {mode} ", stats, scheduler=scheduler)
    sbar.setValue('mode', '')
    sbar.createValues(['waiting', 'sendQ', 'recvQ'], 0)
    sbar.setTrailer('')
    return sbar

def setProgress(mode, name=""):
    if statusBar:
        statusBar.setValue('mode', mode)
        statusBar.setTrailer(name)

def setOutstanding(number):
    if statusBar:
        statusBar.setValue('waiting', number)

processedDirs = set()

def processDirectory(path, top, depth=0, excludes=None):
    """ Process a directory, send any contents along, and then dive down into subdirectories and repeat. """
    excludes = excludes or []

    newdepth = max(depth - 1, 0)

    setProgress("Dir:", path)

    try:
        s = os.lstat(path)
        if not stat.S_ISDIR(s.st_mode):
            return

        # Mark that we've processed it before attempting to determine if we actually should
        processedDirs.add(path)

        if path in excludeDirs:
            logger.debug("%s excluded.  Skipping", path)
            return

        # Return if a skipfile exists.   Realistically this
        # Should happen because we should have handled it in the filelist for then
        # directory, above, but just in case, check it
        if os.path.lexists(os.path.join(path, args.skipfile)):
            logger.debug("Skip file found.  Skipping %s", path)
            return

        if args.skipcaches and os.path.lexists(os.path.join(path, 'CACHEDIR.TAG')):
            logger.debug("CACHEDIR.TAG file found.  Analyzing")
            try:
                with open(os.path.join(path, 'CACHEDIR.TAG'), 'r', encoding='ascii') as f:
                    line = f.readline()
                    if line.startswith('Signature: 8a477f597d28d172789f06886806bc55'):
                        logger.debug("Valid CACHEDIR.TAG file found.  Skipping %s", dir)
                        return
            except Exception as e:
                logger.warning("Could not read %s.  Backing up directory %s", os.path.join(path, "CACHEDIR.TAG"), path)
                exceptionLogger.log(e)

        (files, subdirs, subexcludes) = getDirContents(path, s, excludes)

        h = Util.hashDir(crypt, files)
        dirHashes[(s.st_ino, s.st_dev)] = h

        # Figure out which files to clone, and which to update
        if files and args.clones:
            if len(files) > args.clonethreshold:
                newFiles = [f for f in files if max(f['ctime'], f['mtime']) >= lastTimestamp]
                oldFiles = [f for f in files if max(f['ctime'], f['mtime']) < lastTimestamp]
            else:
                maxTime = max([max(x["ctime"], x["mtime"]) for x in files])
                if maxTime < lastTimestamp:
                    oldFiles = files
                    newFiles = []
                else:
                    newFiles = files
                    oldFiles = []
        else:
            newFiles = files
            oldFiles = []

        if newFiles:
            # There are new and (maybe) old files.
            # First, save the hash.

            # Purge out any meta data that's been accumulated
            if newmeta:
                sendMessage(makeMetaMessage())

            if oldFiles:
                # There are oldfiles.  Hash them.
                if logger.isEnabledFor(log.DIRS):
                    logger.log(log.DIRS, "[A]: %s", Util.shortPath(path))
                cloneDir(s.st_ino, s.st_dev, oldFiles, path)
            else:
                if logger.isEnabledFor(log.DIRS):
                    logger.log(log.DIRS, "[B]: %s", Util.shortPath(path))
            sendDirChunks(os.path.relpath(path, top), (s.st_ino, s.st_dev), newFiles)

        else:
            # everything is old
            if logger.isEnabledFor(log.DIRS):
                logger.log(log.DIRS, "[C]: %s", Util.shortPath(path))
            cloneDir(s.st_ino, s.st_dev, oldFiles, path, info=h)

        # Make sure we're not at maximum depth
        if depth != 1:
            # Purge out the lists.  Allow garbage collection to take place.  These can get largish.
            files = oldFiles = newFiles = None
            # Process the sub directories
            for subdir in sorted(subdirs):
                dirJob = DirectoryJob(subdir, top, newdepth, subexcludes)
                directoryQueue.appendleft(dirJob)
    except OSError as e:
        logger.error("Error handling directory: %s: %s", path, str(e))
        exceptionLogger.log(e)
        raise ExitRecursionException(e)
    except Exception as e:
        # TODO: Clean this up
        logger.error("Error handling directory: %s: %s", path, str(e))
        exceptionLogger.log(e)
        raise ExitRecursionException(e)

def processTopLevelDirs(rootdir, directories):
    logger.debug("Processing directories %s", directories)
    for directory in directories:
        # skip if already processed.
        if directory in processedDirs:
            continue
        # Create the fake directory entry(s) for this.
        if rootdir:
            createPrefixPath(rootdir, directory)
            root = rootdir
        else:
            (root, name) = os.path.split(directory)
            f = mkFileInfo(FakeDirEntry(root, name))
            sendDirEntry(0, 0, [f])
        # And run the directory
        dirJob = DirectoryJob(directory, root, args.maxdepth, globalExcludes)
        directoryQueue.append(dirJob)

def runBackup():
    try:
        while directoryQueue:
            while response := receiveMessage(wait=False):
                handleResponse(response)

            dirJob = directoryQueue.popleft()
            processDirectory(dirJob.subdir, dirJob.top, dirJob.newdepth, dirJob.subexcludes)

        while outstandingMessages:
            response = receiveMessage(wait=True)
            handleResponse(response)
        logger.debug("Done with directory traversal")
        if newmeta:
            sendMessage(makeMetaMessage())
        flushClones()

        while outstandingMessages:
            response = receiveMessage(wait=True)
            handleResponse(response)
        logger.debug("Done with directory traversal")
    except Exception as e:
        logger.error(e)
        exceptionLogger.log(e)

def cloneDir(inode, device, files, path, info=None):
    """ Send a clone message, containing the hash of the filenames, and the number of files """
    if info:
        (h, s) = info
    else:
        (h, s) = Util.hashDir(crypt, files)

    message = {
        'inode': inode,
        'dev': device,
        'numfiles': s,
        'cksum': h
    }
    cloneDirs.append(message)
    cloneContents[(inode, device)] = (path, files)
    if len(cloneDirs) >= args.clones:
        flushClones()

def setPurgeValues():
    global purgeTime, purgePriority
    if args.purge:
        purgePriority = args.priority
        if args.purgeprior:
            purgePriority = args.purgeprior
        if args.purgedays:
            purgeTime = args.purgedays * 3600 * 24
        if args.purgehours:
            purgeTime = args.purgehours * 3600
        if args.purgetime:
            cal = parsedatetime.Calendar()
            (then, success) = cal.parse(args.purgetime)
            if success:
                purgeTime = time.mktime(then)
            else:
                raise Exception(f"Could not parse --keep-time argument: {args.purgetime} ")


def mkExcludePattern(pattern):
    logger.debug("Excluding %s", pattern)
    if not pattern.startswith('/'):
        pattern = '**/' + pattern
    return glob.translate(pattern, recursive=True, include_hidden=True)

@functools.lru_cache(maxsize=512)
def _doCompile(pattern):
    return re.compile(pattern)

def compileExcludes(patterns):
    pattern = "|".join(patterns)
    return _doCompile(pattern)

def loadExcludeFile(name):
    """ Load a list of patterns to exclude from a file. """
    try:
        with open(name) as f:
            excludes = [mkExcludePattern(x.rstrip('\n')) for x in f.readlines()]
        return set(excludes)
    except (FileNotFoundError, IOError):
        return set()

# Load all the excludes we might want
def loadExcludes():
    global excludeFile, globalExcludes
    if not args.ignoreglobalexcludes:
        globalExcludes = globalExcludes.union(loadExcludeFile(globalExcludeFile))
    if args.cvs:
        globalExcludes = globalExcludes.union(map(mkExcludePattern, cvsExcludes))
    if args.excludes:
        globalExcludes = globalExcludes.union(map(mkExcludePattern, args.excludes))
    if args.excludefiles:
        for f in args.excludefiles:
            globalExcludes = globalExcludes.union(loadExcludeFile(f))
    excludeFile         = args.excludefilename

def loadExcludedDirs():
    if args.excludedirs is not None:
        excludeDirs.extend(list(map(Util.fullPath, args.excludedirs)))

def loadNoCompressTypes():
    global noCompTypes

    # If no compression types are specified, load the list
    types = []
    for i in args.nocompressfile:
        try:
            logger.debug("Reading types to ignore from: %s", i)
            with open(i, 'r', encoding=systemencoding) as f:
                data = list(map(Util.stripComments, f.readlines()))
            types = types + [x for x in data if len(x)]
        except Exception as e:
            logger.error("Could not load nocompress types list from: %s", i)
            raise e
    types = types + args.nocompress
    noCompTypes = set(types)
    logger.debug("Types to ignore: %s", sorted(noCompTypes))

def calculateDirectories() -> tuple[list, str]:
    # Calculate the base directories
    directories = list(itertools.chain.from_iterable(list(map(glob.glob, list(map(Util.fullPath, args.directories))))))
    if args.basepath == 'common':
        rootdir = os.path.commonpath(directories)
        # If the rootdir is actually one of the directories, back off one directory
        if rootdir in directories:
            rootdir  = os.path.split(rootdir)[0]
    elif args.basepath == 'full':
        rootdir = '/'
    else:
        # None, just using the final component of the pathname.
        # Check that each final component is unique, or will cause server error.
        names = {}
        errors = False
        for i in directories:
            x = os.path.split(i)[1]
            if x in names:
                logger.error("%s directory name (%s) is not unique.  Collides with %s", i, x, names[x])
                errors = True
            else:
                names[x] = i
        if errors:
            raise Exception('All paths must have a unique final directory name if basepath is none')
        rootdir = None
    logger.debug("Rootdir is: %s", rootdir)
    return directories, rootdir

_nextMsgId = 0
outstandingMessages = 0
waittime = 0
trackOutstanding = False

def setMessageID(message):
    global _nextMsgId, outstandingMessages
    _nextMsgId += 1
    message['msgid'] = _nextMsgId
    if trackOutstanding:
        outstandingMessages += 1
        setOutstanding(outstandingMessages)
    return _nextMsgId

def sendMessage(message):
    setMessageID(message)
    if verbosity > 4:
        logger.debug("Send: %s", str(message))
    if args.logmessages:
        args.logmessages.write(f"\nSending message {message.get('msgid', 'Unknown')} {'-' * 40}\n")
        args.logmessages.write(pprint.pformat(message, width=250, compact=True) + '\n')
    messenger.sendMessage(message)

def receiveMessage(wait = True):
    global waittime
    setProgress("Receiving...")
    if wait:
        s = time.time()
    response = messenger.recvMessage(wait)
    if wait:
        e = time.time()
        waittime += e - s
    if response:
        if verbosity > 4:
            logger.debug("Receive: %s", str(response))
        if args.logmessages:
            args.logmessages.write(f"\nReceived message {response.get('respid', 'Unknown')} {'-' * 40}\n")
            args.logmessages.write(pprint.pformat(response, width=250, compact=True) + '\n')
    return response

def sendAndReceive(message):
    sendMessage(message)
    response = receiveMessage()
    return response

def sendKeys(password, client):
    logger.debug("Sending keys")
    (f, c) = crypt.getKeys()

    (salt, vkey) = srp.create_salted_verification_key(client, password)
    message = {
        "message": Protocol.Commands.SETKEYS,
        "filenameKey": f,
        "contentKey": c,
        "srpSalt": salt,
        "srpVkey": vkey,
        "cryptoScheme": crypt.getCryptoScheme()
    }
    response = sendAndReceive(message)
    checkMessage(response, Protocol.Responses.ACKSETKEYS)
    if response['response'] != 'OK':
        logger.error("Could not set keys")

currentResponse = None

def handleResponse(response, doPush=True):
    global currentResponse, outstandingMessages
    try:
        currentResponse = response
        msgtype = response['message']
        match msgtype:
            case Protocol.Responses.ACKDIR:
                handleAckDir(response)
            case Protocol.Responses.ACKCLN:
                handleAckClone(response)
            case Protocol.Responses.ACKSUM:
                handleAckSum(response)
            case Protocol.Responses.ACKMETA:
                handleAckMeta(response)
            case Protocol.Responses.ACKSGR:
                handleSig(response)
            case Protocol.Responses.ACKPRG | Protocol.Responses.ACKDHSH | Protocol.Responses.ACKCLICONFIG | \
                 Protocol.Responses.ACKCMDLN | Protocol.Responses.ACKCON | Protocol.Responses.ACKDEL | \
                 Protocol.Responses.ACKSIG | Protocol.Responses.ACKMETADATA:
                logger.debug("Ignoring message %d - %s", response.get('respid', -1), msgtype)
                pass
            case Protocol.Responses.ACKDONE:
                logger.warning("Got ACKDONE before processing complete")
                if outstandingMessages:
                    logger.warning("%d messages outstanding.", outstandingMessages)
            case _:
                logger.error("Unexpected response: %s", msgtype)

        if doPush:
            pushFiles()
    except Exception as e:
        logger.error("Error handling response %s %s: %s", response.get('msgid'), response.get('message'), e)
        logger.exception("Exception: ", exc_info=e)
        logger.error(pprint.pformat(response, width=150, depth=5, compact=True))
        exceptionLogger.log(e)

    # Clear the "outstandingMessage" marker for this job
    try:
        outstandingMessages -= 1
        setOutstanding(outstandingMessages)
    except Exception as e:
        logger.error("Exception processing message (%s, %s): %s", response.get('respid', 'Unknown'), response.get('message', 'None'), str(e))
        exceptionLogger.log(e)
        pass

def sendDirEntry(parent, device, files):
    # send a fake root directory
    message = {
        'message': Protocol.Commands.DIR,
        'files': files,
        'path' : None,
        'inode': [parent, device],
        'last' : True
    }
    sendMessage(message)

def splitDirs(x):
    root, rest = os.path.split(x)
    if root and rest:
        ret = splitDirs(root)
        ret.append(rest)
    elif root:
        if root == '/':
            ret = [root]
        else:
            ret = splitDirs(root)
    else:
        ret = [rest]
    return ret

def createPrefixPath(root, path):
    """ Create common path directories.  Will be empty, except for path elements to the repested directories. """
    rPath     = os.path.relpath(path, root)
    logger.debug("Making prefix path for: %s as %s", path, rPath)
    pathDirs  = splitDirs(rPath)
    parent    = 0
    parentDev = virtualDev(0, "/")
    current   = root
    for d in pathDirs:
        dirPath = os.path.join(current, d)
        st = os.lstat(dirPath)
        f = mkFileInfo(FakeDirEntry(current, d))
        f['name'] = crypt.encryptName(f['name'])
        if dirPath not in processedDirs:
            logger.debug("Sending dir entry for: %s", dirPath)
            sendDirEntry(parent, parentDev, [f])
            processedDirs.add(dirPath)
        parent    = st.st_ino
        parentDev = virtualDev(st.st_dev, dirPath)
        current   = dirPath

def setCrypto(password, version):
    global srpUsr, crypt
    srpUsr = srp.User(args.client, password)
    crypt = TardisCrypto.getCrypto(version, password, args.client)
    logger.debug("Using %s Crypto scheme", crypt.getCryptoScheme())
    return password

def doSendKeys(password):
    """ Set up cryptography system, and send the generated keys """
    assert(crypt)
    assert(srpUsr)
    logger.debug("Sending keys")
    crypt.genKeys()
    (f, c) = crypt.getKeys()
    (salt, vkey) = srp.create_salted_verification_key(args.client, password)
    message = {
        "message": Protocol.Commands.SETKEYS,
        "filenameKey": f,
        "contentKey": c,
        "srpSalt": salt,
        "srpVkey": vkey,
        "cryptoScheme": crypt.getCryptoScheme()
    }
    resp = sendAndReceive(message)
    return resp

def doSrpAuthentication(password, response):
    """ Setup cryptography and do authentication """
    try:
        setCrypto(password, response['cryptoScheme'])

        srpUname, srpValueA = srpUsr.start_authentication()
        logger.debug("Starting Authentication: %s, %s", srpUname, hexlify(srpValueA))
        message = {
            'message': Protocol.Commands.AUTH1,
            'srpUname': base64.b64encode(bytes(srpUname, 'utf8')),           # Probably unnecessary, uname == client
            'srpValueA': base64.b64encode(srpValueA),
        }
        resp = sendAndReceive(message)

        if resp['status'] == 'AUTHFAIL':
            raise AuthenticationFailed("Authentication Failed")

        srpValueS = base64.b64decode(resp['srpValueS'])
        srpValueB = base64.b64decode(resp['srpValueB'])

        logger.debug("Received Challenge : %s, %s", hexlify(srpValueS), hexlify(srpValueB))

        srpValueM = srpUsr.process_challenge(srpValueS, srpValueB)

        if srpValueM is None:
            raise AuthenticationFailed("Authentication Failed")

        logger.debug("Authentication Challenge response: %s", hexlify(srpValueM))

        message = {
            'message': Protocol.Commands.AUTH2,
            'srpValueM': base64.b64encode(srpValueM)
        }

        resp = sendAndReceive(message)
        if resp['status'] == 'AUTHFAIL':
            raise AuthenticationFailed("Authentication Failed")
        if resp['status'] != 'OK':
            raise Exception(resp['error'])
        srpHamk = base64.b64decode(resp['srpValueHAMK'])
        srpUsr.verify_session(srpHamk)
        return resp
    except KeyError as e:
        logger.error("Key not found %s", str(e))
        raise AuthenticationFailed("response incomplete")

def startBackup(name, priority, client, force, full=False, create=False, password=None, scheme=None, version=Tardis.__versionstring__):
    global lastTimestamp, crypt, trackOutstanding
    triedAuthentication = False
    crypt = None

    # Create a BACKUP message
    message = {
            'message'   : Protocol.Commands.BACKUP,
            'host'      : client,
            'encoding'  : encoding,
            'priority'  : priority,
            'autoname'  : name is None,
            'force'     : force,
            'time'      : time.time(),
            'version'   : version,
            'full'      : full,
            'create'    : create,
            'encrypted' : bool(password)
    }
    if name:
        message['name'] = name

    # BACKUP { json message }
    resp = sendAndReceive(message)

    if resp['status'] in [Protocol.Responses.NEEDKEYS, Protocol.Responses.AUTH]:
        if password is None:
            password = Util.getPassword(args.password, args.passwordfile, args.passwordprog, prompt=f"Password for {client}: ", confirm=create)
        if create:
            setCrypto(password, args.cryptoScheme or TardisCrypto.DEF_CRYPTO_SCHEME)

    if resp['status'] == Protocol.Responses.NEEDKEYS:
        resp = doSendKeys(password)
    if resp['status'] == Protocol.Responses.AUTH:
        triedAuthentication = True
        if not password:
            raise InitFailedException(f"Client {client} requires a password")
        resp = doSrpAuthentication(password, resp)

    if resp['status'] != 'OK':
        errmesg = "BACKUP request failed"
        if 'error' in resp:
            errmesg = errmesg + ": " + resp['error']
        raise Exception(errmesg)

    if triedAuthentication and not (args.password or args.passwordfile or args.passwordprog):
        # Password specified, but not needed
        raise AuthenticationFailed("Authentication Failed")

    sessionid      = uuid.UUID(resp['sessionid'])
    clientId       = uuid.UUID(resp['clientid'])
    lastTimestamp  = float(resp['prevDate'])
    backupName     = resp['name']
    newBackup      = resp['new'] == 'NEW'
    filenameKey    = resp.get('filenameKey')
    contentKey     = resp.get('contentKey')
    # FIXME: TODO: Should this be in the initialization?
    if not crypt:
        crypt = TardisCrypto.getCrypto(TardisCrypto.NO_CRYPTO_SCHEME, None, args.client)

    # Set up the encryption, if needed.
    ### TODO
    (f, c) = (None, None)

    if newBackup:
        # if new DB, generate new keys, and save them appropriately.
        if password:
            logger.debug("Generating new keys")
            crypt.genKeys()
            if args.keys:
                (f, c) = crypt.getKeys()
                Util.saveKeys(Util.fullPath(args.keys), clientId, f, c)
            else:
                sendKeys(password, client)
        else:
            if args.keys:
                (f, c) = crypt.getKeys()
                Util.saveKeys(Util.fullPath(args.keys), clientId, f, c)
    elif crypt.encrypting():
        # Otherwise, load the keys from the appropriate place
        if args.keys:
            (f, c) = Util.loadKeys(args.keys, clientId)
        else:
            f = filenameKey
            c = contentKey
        if not (f and c):
            logger.critical("Unable to load keyfile: %s", args.keys)
            sys.exit(1)
        crypt.setKeys(f, c)

    if verbosity or args.stats or args.report != 'none':
        logger.log(log.STATS, f"Name: {backupName} Server: {server}:{port} Session: {sessionid}")

    trackOutstanding = True

def checkConfig(c, t):
    # Check things in the config file that might be confusing
    # CompressedBuffer will convert True or 1 to zlib, anything else not in the list to none
    comp = c.get(t, 'CompressData').lower()
    if comp in ['true', '1']:
        c.set(t, 'CompressData', 'zlib')
    elif comp not in CompressedBuffer.getCompressors():
        c.set(t, 'CompressData', 'none')

    if not c.get(t, 'BasePath') in basePathChoices:
        c.set(t, 'BasePath', basePathChoices[0])
    if not c.get(t, 'CompressMsgs') in msgCompressionChoices:
        c.set(t, 'CompressMsgs', msgCompressionChoices[0])
    if not c.get(t, 'Report') in reportChoices:
        c.set(t, 'Report', reportChoices[0])

def processCommandLine():
    """ Do the command line thing.  Register arguments.  Parse it. """
    def _d(helpstr):
        """ Only print the help message if --debug is specified """
        return helpstr if args.debug else argparse.SUPPRESS

    def splitList(line):
        if not line:
            return []
        return shlex.split(line.strip())

    _def = 'Default: %(default)s'

    # Use the custom arg parser, which handles argument files more cleanly
    parser = CustomArgumentParser(description='Tardis Backup Client', fromfile_prefix_chars='@', formatter_class=Util.HelpFormatter, add_help=False,
                                  epilog='Options can be specified in files, with the filename specified by an @sign: e.g. "%(prog)s @args.txt" will read arguments from args.txt')

    parser.add_argument('--config',                 dest='config', default=Defaults.getDefault('TARDIS_CONFIG'),        help='Location of the configuration file. ' + _def)
    parser.add_argument('--job',                    dest='job', default=Defaults.getDefault('TARDIS_JOB'),              help='Job Name within the configuration file. ' + _def)
    parser.add_argument('--debug',                  dest='debug', default=False, action='store_true',                   help=argparse.SUPPRESS)
    (args, remaining) = parser.parse_known_args()

    t = args.job
    c = configparser.RawConfigParser(configDefaults, allow_no_value=True)

    if args.config:
        c.read(args.config)
        if not c.has_section(t):
            sys.stderr.write(f"WARNING: No Job named {t} listed.  Using defaults.  Jobs available: {str(c.sections()).strip('[]')}\n")
            c.add_section(t)                    # Make it safe for reading other values from.
        checkConfig(c, t)
    else:
        c.add_section(t)                        # Make it safe for reading other values from.

    locgroup = parser.add_argument_group("Local Backup options")
    locgroup.add_argument('--database', '-D',     dest='database',        default=c.get(t, 'BaseDir'), help='Dabatase directory (Default: %(default)s)')

    remotegroup = parser.add_argument_group("Remote Server options")
    remotegroup.add_argument('--server', '-s',           dest='server', default=c.get(t, 'Server'),                          help='Set the destination server. ' + _def)
    remotegroup.add_argument('--port', '-p',             dest='port', type=int, default=c.getint(t, 'Port'),                 help='Set the destination server port. ' + _def)

    modegroup = parser.add_mutually_exclusive_group()
    modegroup.add_argument('--local',               dest='local', action='store_true',  default=c.get(t, 'Local'), help='Run as a local job')
    modegroup.add_argument('--remote',              dest='local', action='store_false', default=c.get(t, 'Local'), help='Run against a remote server')

    parser.add_argument('--log', '-l',              dest='logfiles', action='append', default=splitList(c.get(t, 'LogFiles')), nargs="?", const=sys.stderr,
                        help='Send logging output to specified file.  Can be repeated for multiple logs. Default: stderr')

    parser.add_argument('--client', '-C',           dest='client', default=c.get(t, 'Client'),                          help='Set the client name.  ' + _def)
    parser.add_argument('--force',                  dest='force', action=argparse.BooleanOptionalAction, default=c.getboolean(t, 'Force'),
                        help='Force the backup to take place, even if others are currently running.  ' + _def)
    parser.add_argument('--full',                   dest='full', action=argparse.BooleanOptionalAction, default=c.getboolean(t, 'Full'),
                        help='Perform a full backup, with no delta information. ' + _def)
    parser.add_argument('--name',   '-n',           dest='name', default=None,                                          help='Set the backup name.  Leave blank to assign name automatically')
    parser.add_argument('--create',                 dest='create', default=False, action=argparse.BooleanOptionalAction,             help='Create a new client.')


    passgroup = parser.add_argument_group("Password/Encryption specification options")
    pwgroup = passgroup.add_mutually_exclusive_group()
    pwgroup.add_argument('--password', '-P',        dest='password', default=c.get(t, 'Password'), nargs='?', const=True,
                         help='Password.  Enables encryption')
    pwgroup.add_argument('--password-file', '-F',   dest='passwordfile', default=c.get(t, 'PasswordFile'),              help='Read password from file.  Can be a URL (HTTP/HTTPS or FTP)')
    pwgroup.add_argument('--password-prog',         dest='passwordprog', default=c.get(t, 'PasswordProg'),              help='Use the specified command to generate the password on stdout')

    passgroup.add_argument('--crypt',               dest='cryptoScheme', type=int, choices=range(TardisCrypto.MAX_CRYPTO_SCHEME+1), default=None,
                           help="Crypto scheme to use.  0-4\n" + TardisCrypto.getCryptoNames())

    passgroup.add_argument('--keys',                dest='keys', default=c.get(t, 'KeyFile'),
                           help='Load keys from file.  Keys are not stored in database')

    parser.add_argument('--send-config', '-S',      dest='sendconfig', action=argparse.BooleanOptionalAction, default=c.getboolean(t, 'SendClientConfig'),
                        help='Send the client config (effective arguments list) to the server for debugging.  Default=%(default)s')

    parser.add_argument('--compress-data',  '-Z',   dest='compress', const='zstd', default=c.get(t, 'CompressData'), nargs='?', choices=CompressedBuffer.getCompressors(),
                        help='Compress files.  ' + _def)
    parser.add_argument('--compress-min',           dest='mincompsize', type=int, default=c.getint(t, 'CompressMin'),   help='Minimum size to compress.  ' + _def)
    parser.add_argument('--nocompress-types',       dest='nocompressfile', default=splitList(c.get(t, 'NoCompressFile')), action='append',
                        help='File containing a list of MIME types to not compress.  ' + _def)
    parser.add_argument('--nocompress', '-z',       dest='nocompress', default=splitList(c.get(t, 'NoCompress')), action='append',
                        help='MIME type to not compress. Can be repeated')
    if support_xattr:
        parser.add_argument('--xattr',              dest='xattr', default=support_xattr, action=argparse.BooleanOptionalAction,               help='Backup file extended attributes')
    if support_acl:
        parser.add_argument('--acl',                dest='acl', default=support_acl, action=argparse.BooleanOptionalAction,                 help='Backup file access control lists')

    parser.add_argument('--priority',           dest='priority', type=int, default=None,                                help='Set the priority of this backup')
    parser.add_argument('--maxdepth', '-d',     dest='maxdepth', type=int, default=0,                                   help='Maximum depth to search')
    parser.add_argument('--crossdevice',        dest='crossdev', action=argparse.BooleanOptionalAction, default=False,               help='Cross devices. ' + _def)

    parser.add_argument('--basepath',           dest='basepath', default='full', choices=['none', 'common', 'full'],    help='Select style of root path handling ' + _def)

    excgrp = parser.add_argument_group('Exclusion options', 'Options for handling exclusions')
    excgrp.add_argument('--cvs-ignore',                 dest='cvs', default=c.getboolean(t, 'IgnoreCVS'), action=argparse.BooleanOptionalAction,
                        help='Ignore files like CVS.  ' + _def)
    excgrp.add_argument('--skip-caches',                dest='skipcaches', default=c.getboolean(t, 'SkipCaches'),action=argparse.BooleanOptionalAction,
                        help='Skip directories with valid CACHEDIR.TAG files.  ' + _def)
    excgrp.add_argument('--exclude', '-x',              dest='excludes', action='append', default=splitList(c.get(t, 'ExcludePatterns')),
                        help='Patterns to exclude globally (may be repeated)')
    excgrp.add_argument('--exclude-file', '-X',         dest='excludefiles', action='append',
                        help='Load patterns from exclude file (may be repeated)')
    excgrp.add_argument('--exclude-dir',                dest='excludedirs', action='append', default=splitList(c.get(t, 'ExcludeDirs')),
                        help='Exclude certain directories by path')

    excgrp.add_argument('--exclude-file-name',          dest='excludefilename', default=c.get(t, 'ExcludeFileName'),
                        help='Load recursive exclude files from this.  ' + _def)
    excgrp.add_argument('--local-exclude-file-name',    dest='localexcludefile', default=c.get(t, 'LocalExcludeFileName'),
                        help='Load local exclude files from this.  ' + _def)
    excgrp.add_argument('--skip-file-name',             dest='skipfile', default=c.get(t, 'SkipFileName'),
                        help='File to indicate to skip a directory.  ' + _def)
    excgrp.add_argument('--exclude-no-access',          dest='skipNoAccess', default=c.get(t, 'ExcludeNoAccess'), action=argparse.BooleanOptionalAction,
                        help="Exclude files to which the runner has no permission- won't generate directory entry. " + _def)
    excgrp.add_argument('--ignore-global-excludes',     dest='ignoreglobalexcludes', action=argparse.BooleanOptionalAction, default=False,
                        help='Ignore the global exclude file.  ' + _def)

    comgrp = parser.add_argument_group('Communications options', 'Options for specifying details about the communications protocol.')
    comgrp.add_argument('--compress-msgs', '-Y',    dest='compressmsgs', nargs='?', const='snappy',
                        choices=['none', 'zlib', 'zlib-stream', 'snappy'], default=c.get(t, 'CompressMsgs'),
                        help='Compress messages.  ' + _def)
    comgrp.add_argument('--validate-certs',         dest='validatecerts', action=argparse.BooleanOptionalAction, default=c.getboolean(t, 'ValidateCerts'),
                        help="Validate Certificates.   Set to false for self-signed certificates. " + _def)

    comgrp.add_argument('--clones', '-L',           dest='clones', type=int, default=1024,              help=_d('Maximum number of clones per chunk.  0 to disable cloning.  ' + _def))
    comgrp.add_argument('--minclones',              dest='clonethreshold', type=int, default=64,        help=_d('Minimum number of files to do a partial clone.  If less, will send directory as normal: ' + _def))
    comgrp.add_argument('--ckbatchsize',            dest='cksumbatch', type=int, default=100,           help=_d('Maximum number of checksums to handle in a single message.  ' + _def))
    comgrp.add_argument('--chunksize',              dest='chunksize', type=int, default=256*1024,       help=_d('Chunk size for sending data.  ' + _def))
    comgrp.add_argument('--dirslice',               dest='dirslice', type=int, default=128*1024,        help=_d('Maximum number of directory entries per message.  ' + _def))
    comgrp.add_argument('--logmessages',            dest='logmessages', type=argparse.FileType('w'),    help=_d('Log messages to file'))
    comgrp.add_argument('--signature',              dest='signature', default=c.getboolean(t, 'SendSig'), action=argparse.BooleanOptionalAction,
                        help=_d('Always send a signature.  ' + _def))
    comgrp.add_argument('--timeout',                dest='timeout', default=c.getfloat(t, 'Timeout'), type=float, const=None,              help='Set the timeout to N seconds.  ' + _def)

    parser.add_argument('--deltathreshold',         dest='deltathreshold', default=66, type=int,
                        help=_d('If delta file is greater than this percentage of the original, a full version is sent.  ' + _def))

    purgegroup = parser.add_argument_group("Options for purging old backup sets")
    purgegroup.add_argument('--purge',              dest='purge', action=argparse.BooleanOptionalAction, default=c.getboolean(t, 'Purge'),  help='Purge old backup sets when backup complete.  ' + _def)
    purgegroup.add_argument('--purge-priority',     dest='purgeprior', type=int, default=None,              help='Delete below this priority (Default: Backup priority)')

    prggroup = purgegroup.add_mutually_exclusive_group()
    prggroup.add_argument('--keep-days',        dest='purgedays', type=int, default=None,           help='Number of days to keep')
    prggroup.add_argument('--keep-hours',       dest='purgehours', type=int, default=None,          help='Number of hours to keep')
    prggroup.add_argument('--keep-time',        dest='purgetime', default=None,                     help='Purge before this time.  Format: YYYY/MM/DD:hh:mm')

    parser.add_argument('--stats',              action=argparse.BooleanOptionalAction, dest='stats', default=c.getboolean(t, 'Stats'),
                        help='Print stats about the transfer.  Default=%(default)s')
    parser.add_argument('--report',             dest='report', choices=['all', 'dirs', 'none'], const='all', default=c.get(t, 'Report'), nargs='?',
                        help='Print a report on all files or directories transferred.  ' + _def)
    parser.add_argument('--verbose', '-v',      dest='verbose', action='count', default=c.getint(t, 'Verbosity'),
                        help='Increase the verbosity')
    parser.add_argument('--progress',           dest='progress', action='store_true',               help='Show a one-line progress bar.')

    parser.add_argument('--exclusive',          dest='exclusive', action=argparse.BooleanOptionalAction, default=True, help='Make sure the client only runs one job at a time. ' + _def)
    parser.add_argument('--exceptions', '-E',   dest='exceptions', default=False, action=argparse.BooleanOptionalAction, help='Log full exception details')
    parser.add_argument('--logtime',            dest='logtime', default=False, action=argparse.BooleanOptionalAction, help='Log time')
    parser.add_argument('--logcolor',           dest='logcolor', default=True, action=argparse.BooleanOptionalAction, help='Generate colored logs')

    parser.add_argument('--version',            action='version', version='%(prog)s ' + Tardis.__versionstring__, help='Show the version')
    parser.add_argument('--help', '-h',         action='help')

    Util.addGenCompletions(parser)

    parser.add_argument('directories',          nargs='*', default=splitList(c.get(t, 'Directories')), help="List of directories to sync")

    args = parser.parse_args(remaining)

    return (args, c, t)

def parseServerInfo():
    """ Break up the server info passed in into useable chunks """
    serverStr = args.server
    if not serverStr.startswith('tardis://'):
        serverStr = 'tardis://' + serverStr
    try:
        info = urllib.parse.urlparse(serverStr)
        if info.scheme != 'tardis':
            raise Exception(f"Invalid URL scheme: {info.scheme}")

        sServer = info.hostname
        sPort   = info.port
        sClient = info.path.lstrip('/')

    except Exception as e:
        raise Exception(f"Invalid URL: {args.server} -- {e}")

    server = sServer or args.server
    port = sPort or args.port
    client = sClient or args.client

    return (server, port, client)

def setupLogging(logfiles, verbosity, logExceptions):
    global logger, exceptionLogger

    # Define a couple custom logging levels

    levels = [log.STATS, logging.INFO, log.DIRS, log.FILES, log.MSGS, logging.DEBUG]

    # Don't want logging complaining within it's own runs.
    logging.raiseExceptions = False

    # Create some default colors
    colors = colorlog.default_log_colors.copy()
    colors.update({
        'STATS': 'cyan',
        'DIRS':  'cyan,bold',
        'FILES': 'cyan',
        'DEBUG': 'green'
    })

    msgOnlyFmt = '%(message)s'
    if args.logtime:
        formats = { log.STATS: msgOnlyFmt }
        defaultFmt = '%(asctime)s %(levelname)s: %(message)s'
        cDefaultFmt = '%(asctime)s %(log_color)s%(levelname)s%(reset)s: %(message)s'
    else:
        formats = { logging.INFO: msgOnlyFmt, log.STATS: msgOnlyFmt }
        defaultFmt = '%(name)s %(levelname)s: %(message)s'
        cDefaultFmt = '%(name)s %(log_color)s%(levelname)s%(reset)s: %(message)s'

    # If no log file specified, log to stderr
    if len(logfiles) == 0:
        logfiles.append(sys.stderr)

    # Generate a handler and formatter for each logfile
    for logfile in logfiles:
        if isinstance(logfile, str):
            if logfile == ':STDERR:':
                isatty = os.isatty(sys.stderr.fileno())
                handler = Util.ClearingStreamHandler(sys.stderr)
            elif logfile == ':STDOUT:':
                isatty = os.isatty(sys.stdout.fileno())
                handler = Util.ClearingStreamHandler(sys.stdout)
            else:
                isatty = False
                path = Util.fullPath(logfile)
                # Check that the file is writable
                try:
                    handler = logging.handlers.WatchedFileHandler(path)
                except:
                    logging.basicConfig()
                    logger = logging.getLogger()
                    logger.critical(f"Unable to log to {path}")
                    raise
        else:
            isatty = os.isatty(logfile.fileno())
            handler = Util.ClearingStreamHandler(logfile)

        if isatty and args.logcolor:
            formatter = MultiFormatter.MultiFormatter(default_fmt=cDefaultFmt, formats=formats, baseclass=colorlog.ColoredFormatter, log_colors=colors, reset=True)
        else:
            formatter = MultiFormatter.MultiFormatter(default_fmt=defaultFmt, formats=formats)

        handler.setFormatter(formatter)
        logging.root.addHandler(handler)

    # Default logger
    logger = logging.getLogger('Client')

    # Pick a level.  Lowest specified level if verbosity is too large.
    loglevel = levels[verbosity] if verbosity < len(levels) else levels[-1]
    logging.root.setLevel(loglevel)

    # Mark if we're logging exceptions
    exceptionLogger = Util.ExceptionLogger(logger, logExceptions, True)

    # Create a special logger just for messages
    return logger

def printStats(starttime, endtime):
    connstats = conn.getStats()

    duration = endtime - starttime
    duration = datetime.timedelta(duration.days, duration.seconds, duration.seconds - (duration.seconds % 100000))          # Truncate the microseconds

    logger.log(log.STATS, f"Runtime:          {duration}")
    logger.log(log.STATS, f"Backed Up:        Dirs: {stats['dirs']:,}  Files: {stats['files']:,}  Links: {stats['links']:,}  Total Size: {Util.fmtSize(stats['backed'])}")
    logger.log(log.STATS, f"Files Sent:       Full: {stats['new']:,}  Deltas: {stats['delta']:,}")
    logger.log(log.STATS, f"Data Sent:        Sent: {Util.fmtSize(stats['dataSent'])}   Backed: {Util.fmtSize(stats['dataBacked'])}")
    logger.log(log.STATS, f"Messages:         Sent: {connstats['messagesSent']:,} ({Util.fmtSize(connstats['bytesSent'])}) Received: {connstats['messagesRecvd']:,} ({Util.fmtSize(connstats['bytesRecvd'])})")
    logger.log(log.STATS, f"Data Sent:        {Util.fmtSize(stats['dataSent'])}")

    if (stats['denied'] or stats['gone']):
        logger.log(log.STATS, f"Files Not Sent:   Disappeared: {stats['gone']:,}  Permission Denied: {stats['denied']:,}")

    logger.log(log.STATS, f"Wait Times:   {str(datetime.timedelta(0, waittime))}")
    logger.log(log.STATS, f"Sending Time: {str(datetime.timedelta(0, Util._transmissionTime))}")

def pickMode():
    if args.local != '' and args.local is not None:
        if args.local in [True, 'True']:
            if args.server is None:
                raise Exception("Remote mode specied without a server")
            return True

        if args.local in [False, 'False']:
            if args.database is None:
                raise Exception("Local mode specied without a database")
            return False

    if args.server is not None and args.database is not None:
        raise Exception("Both database and server specified.  Unable to determine mode.   Use --local/--remote switches")

    if args.server is not None:
        return False
    if args.database is not None:
        return True

    raise Exception("Neither database nor remote server is set.   Unable to backup")

def printReport(repFormat):
    lastDir = None
    length = 0
    numFiles = 0
    deltas   = 0
    dataSize = 0
    logger.log(log.STATS, "")
    if report:
        length = functools.reduce(max, list(map(len, [x[1] for x in report])))
        length = max(length, 50)

        filefmts = ['', 'KB', 'MB', 'GB', 'TB', 'PB']
        dirfmts  = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
        fmt  = f'%-{length + 4}s %-6s %-10s %-10s'
        fmt2 = f'  %-{length}s   %-6s %-10s %-10s'
        fmt3 = f'  %-{length}s   %-6s %-10s'
        fmt4 = '  %d files (%d full, %d delta, %s)'

        logger.log(log.STATS, fmt, "FileName", "Type", "Size", "Sig Size")
        logger.log(log.STATS, fmt, '-' * (length + 4), '-' * 6, '-' * 10, '-' * 10)
        for i in sorted(report):
            r = report[i]
            (d, f) = i

            if d != lastDir:
                if repFormat == 'dirs' and lastDir:
                    logger.log(log.STATS, fmt4, numFiles, numFiles - deltas, deltas, Util.fmtSize(dataSize, suffixes=dirfmts))
                numFiles = 0
                deltas = 0
                dataSize = 0
                logger.log(log.STATS, "%s:", Util.shortPath(d, 80))
                lastDir = d

            numFiles += 1
            if r['type'] == 'Delta':
                deltas += 1
            dataSize += r['size']

            if repFormat == 'all' or repFormat is True:
                if r['sigsize']:
                    logger.log(log.STATS, fmt2, f, r['type'], Util.fmtSize(r['size'], suffixes=filefmts), Util.fmtSize(r['sigsize'], suffixes=filefmts))
                else:
                    logger.log(log.STATS, fmt3, f, r['type'], Util.fmtSize(r['size'], suffixes=filefmts))
        if repFormat == 'dirs' and lastDir:
            logger.log(log.STATS, fmt4, numFiles, numFiles - deltas, deltas, Util.fmtSize(dataSize, suffixes=dirfmts))
    else:
        logger.log(log.STATS, "No files backed up")

def lockRun(server, port, client):
    lockName = 'tardis_' + str(server) + '_' + str(port) + '_' + str(client)

    # Create our own pidfile path.  We do this in /tmp rather than /var/run as tardis may not be run by
    # the superuser (ie, can't write to /var/run)
    pidfile = pid.PidFile(piddir=tempfile.gettempdir(), pidname=lockName)

    try:
        pidfile.create()
    except pid.PidFileError as e:
        exceptionLogger.log(e)
        raise Exception(f"Tardis already running: {e}")
    except Exception as e:
        exceptionLogger.log(e)
        raise
    return pidfile

def mkBackendConfig(jobname):
    bc = Backend.BackendConfig()
    j = jobname
    bc.umask           = Util.parseInt(config.get(j, 'Umask'))
    bc.cksContent      = config.getint(j, 'CksContent')
    bc.serverSessionID = socket.gethostname() + time.strftime("-%Y-%m-%d::%H:%M:%S%Z", time.gmtime())
    bc.formats         = list(map(str.strip, config.get(j, 'Formats').split(',')))
    bc.priorities      = list(map(int, config.get(j, 'Priorities').split(',')))
    bc.keep            = list(map(int, config.get(j, 'KeepDays').split(',')))
    bc.forceFull       = list(map(int, config.get(j, 'ForceFull').split(',')))

    bc.savefull        = config.getboolean(j, 'SaveFull')
    bc.maxChain        = config.getint(j, 'MaxDeltaChain')
    bc.deltaPercent    = float(config.getint(j, 'MaxChangePercent')) / 100.0        # Convert to a ratio
    bc.autoPurge       = config.getboolean(j, 'AutoPurge')
    bc.saveConfig      = config.getboolean(j, 'SaveConfig')
    bc.dbbackups       = config.getint(j, 'DBBackups')

    bc.user            = None
    bc.group           = None

    bc.basedir         = args.database
    bc.allowNew        = True
    bc.allowUpgrades   = True

    bc.allowOverrides  = True
    bc.linkBasis       = config.getboolean(j, 'LinkBasis')

    bc.requirePW       = config.getboolean(j, 'RequirePassword')

    bc.skip            = args.skipfile

    bc.exceptions      = args.exceptions

    return bc

def runBackend(jobname):
    conn = Connection.DirectConnection(args.timeout)
    beConfig = mkBackendConfig(jobname)

    backend = Backend.Backend(conn.serverMessages, beConfig, logSession=False)
    backendThread = threading.Thread(target=backend.runBackup, name="Backend")
    backendThread.start()
    return conn, backend, backendThread

def initialize():
    global starttime, server, port, client, priority
    setProgress("Initializing...")
    try:
        starttime = datetime.datetime.now()

        # Get the actual names we're going to use
        (server, port, client) = parseServerInfo()

        if args.exclusive:
            lockRun(server, port, client)

        # setup purge times
        setPurgeValues()

        # Load the excludes
        loadExcludes()

        # Load any excluded directories
        loadExcludedDirs()

        # Load any password info
        try:
            password = Util.getPassword(args.password, args.passwordfile, args.passwordprog, prompt=f"Password for {client}: ", confirm=args.create)
        except Exception as e:
            logger.critical("Could not retrieve password.: %s", str(e))
            exceptionLogger.log(e)
            sys.exit(1)

        # If no compression types are specified, load the list
        loadNoCompressTypes()

        directories, rootdir = calculateDirectories()

    except Exception as e:
        logger.critical("Unable to initialize: %s", (str(e)))
        exceptionLogger.log(e)
        sys.exit(1)

    return password, directories, rootdir, server, port

def shutdown():
    # Send a purge command, if requested.
    if args.purge:
        sendPurge()
    message = {
        "message": Protocol.Commands.DONE
    }
    response = sendAndReceive(message)
    checkMessage(response, Protocol.Responses.ACKDONE)

def encryptString(string):
    clHash = crypt.getHash()
    clHash.update(bytes(string, 'utf8'))
    h = clHash.hexdigest()
    encrypt, iv = makeEncryptor()
    if iv is None:
        iv = b''
    data = iv + encrypt.encrypt(bytes(string, 'utf8')) + encrypt.finish() + encrypt.digest()
    return h, iv, data

def sendConfigInfo(directories):
    # Generate a string of the command line
    commandLine = ' '.join(sys.argv) + '\n'

    # Send a command line (encrypted), and a hash of it, so it can be saved easily.
    h, iv, data = encryptString(commandLine)

    message = {
        'message': Protocol.Commands.COMMANDLINE,
        'hash': h,
        'line': data,
        'size': len(commandLine),
        'encrypted': bool(iv)
    }
    sendMessage(message)

    # Send the full configuration, if so desired.
    # Note, this should probably be encrypted too.  It contains more information than the above.
    if args.sendconfig:
        a = vars(args)
        a['directories'] = directories
        if a['password']:
            a['password'] = '-- removed --'
        jsonArgs = json.dumps(a, cls=Util.ArgJsonEncoder, sort_keys=True)
        message = {
            "message": Protocol.Commands.CLICONFIG,
            "args":    jsonArgs
        }
        sendMessage(message)

def main():
    global args, config, conn, messenger, verbosity, crypt, noCompTypes, srpUsr, statusBar

    # Read the command line arguments.
    (args, config, jobname) = processCommandLine()

    # Memory debugging.
    # Enable only if you really need it.
    # from dowser import launch_memory_usage_server
    # launch_memory_usage_server()

    # Set up logging
    verbosity = args.verbose or 0
    try:
        setupLogging(args.logfiles, verbosity, args.exceptions)
        # determine mode:
        localmode = pickMode()
    except Exception as e:
        logger.critical(e)
        sys.exit(1)

    # Open the connection
    backendThread = None

    # Initialize the progress bar, if requested
    if args.progress:
        # Create a scheduler thread, if need be
        scheduler = ThreadedScheduler.ThreadedScheduler() if args.progress else None
        statusBar = initProgressBar(scheduler)
        scheduler.start()

    # Get the connection object
    try:
        password, directories, rootdir, server, port = initialize()

        if localmode:
            (conn, _, backendThread) = runBackend(jobname)
        else:
            conn = Connection.MsgPackConnection(server, port, compress=args.compressmsgs, timeout=args.timeout, validate=args.validatecerts)

        messenger = Messenger.Messenger(conn.sender, timeout=args.timeout)
        messenger.run()
        messenger.setProgressBar(statusBar)
    except Exception as e:
        logger.critical("Unable to start session with %s:%s: %s", server, port, str(e))
        exceptionLogger.log(e)
        sys.exit(1)

    # Now, do the actual work here.
    exc = None
    try:
        if args.progress:
            statusBar.start()

        startBackup(args.name, args.priority, args.client, args.force, args.full, args.create, password, args.cryptoScheme)

        # Send information about this backup.
        sendConfigInfo(directories)

        # Now, process top level directories
        processTopLevelDirs(rootdir, directories)

        # Do the actual backup
        runBackup()

        setProgress("Finishing backup...")

        # Finish up
        shutdown()

    except KeyboardInterrupt:
        logger.warning("Backup Interupted")
        exc = "Backup Interrupted"
    except ExitRecursionException as e:
        root = e.rootException
        logger.error("Caught exception: %s, %s", root.__class__.__name__, root)
        exc = str(e)
    except Exception as e:
        logger.error("Caught exception: %s, %s", e.__class__.__name__, e)
        exc = str(e)
        exceptionLogger.log(e)
    finally:
        conn.close(exc)
        if localmode:
            logger.info("Waiting for server to complete")
            backendThread.join()        # Should I do communicate?

    endtime = datetime.datetime.now()

    if args.progress:
        statusBar.shutdown()

    # Print stats and files report
    if args.stats:
        printStats(starttime, endtime)
    if args.report != 'none':
        printReport(args.report)

    print('')

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit("Interrupted")
