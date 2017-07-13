# vi: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2016, Eric Koldinger, All Rights Reserved.
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
import sys
import os.path
import logging
import logging.handlers
import fnmatch
import glob
import itertools
import json
import argparse
import ConfigParser
import time
import datetime
import base64
import subprocess
import hashlib
import tempfile
import cStringIO
import shlex
import urlparse
import functools
import stat
import uuid

from binascii import hexlify

import magic
import pid
import parsedatetime
import srp

import Tardis
import Tardis.TardisCrypto as TardisCrypto
import Tardis.CompressedBuffer as CompressedBuffer
import Tardis.Connection as Connection
import Tardis.Util as Util
import Tardis.Defaults as Defaults
import Tardis.librsync as librsync

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

configDefaults = {
    'Server':               Defaults.getDefault('TARDIS_SERVER'),
    'Port':                 Defaults.getDefault('TARDIS_PORT'),
    'Client':               Defaults.getDefault('TARDIS_CLIENT'),
    'Force':                str(False),
    'Full':                 str(False),
    'Timeout':              str(300.0),
    'Password':             None,
    'PasswordFile':         None,
    'PasswordProg':         None,
    'Crypt':                str(True),
    'KeyFile':              None,
    'SendClientConfig':     Defaults.getDefault('TARDIS_SEND_CONFIG'),
    'CompressData':         'none',
    'CompressMin':          str(4096),
    'NoCompressFile':       Defaults.getDefault('TARDIS_NOCOMPRESS'),
    'NoCompress':           None,
    'Local':                str(False),
    'LocalServerCmd':       'tardisd --config ' + local_config,
    'CompressMsgs':         'none',
    'ChecksumContent':      str(0),
    'Purge':                str(False),
    'IgnoreCVS':            str(False),
    'SkipCaches':           str(False),
    'SendSig':              str(False),
    'ExcludePatterns':      None,
    'ExcludeFiles':         None,
    'ExcludeDirs':          None,
    'GlobalExcludeFileName':Defaults.getDefault('TARDIS_GLOBAL_EXCLUDES'),
    'ExcludeFileName':      Defaults.getDefault('TARDIS_EXCLUDES'),
    'LocalExcludeFileName': Defaults.getDefault('TARDIS_LOCAL_EXCLUDES'),
    'SkipFileName':         Defaults.getDefault('TARDIS_SKIP'),
    'LogFiles':             None,
    'Verbosity':            str(0),
    'Stats':                str(False),
    'Report':               str(False),
    'Directories':          '.',
}

excludeDirs         = []

starttime           = None

encoding            = None
encoder             = None
decoder             = None

purgePriority       = None
purgeTime           = None

globalExcludes      = []
cvsExcludes         = ["RCS", "SCCS", "CVS", "CVS.adm", "RCSLOG", "cvslog.*", "tags", "TAGS", ".make.state", ".nse_depinfo",
                       "*~", "#*", ".#*", ",*", "_$*", "*$", "*.old", "*.bak", "*.BAK", "*.orig", "*.rej", ".del-*", "*.a",
                       "*.olb", "*.o", "*.obj", "*.so", "*.exe", "*.Z", "*.elc", "*.ln", "core", ".*.swp", ".*.swo",
                       ".svn", ".git", ".hg", ".bzr"]
verbosity           = 0

conn                = None
args                = None
config              = None

cloneDirs           = []
cloneContents       = {}
batchMsgs           = []
metaCache           = Util.bidict()                 # A cache of metadata.  Since many files can have the same metadata, we check that
                                                    # that we haven't sent it yet.
newmeta             = []                            # When we encounter new metadata, keep it here until we flush it to the server.

noCompTypes         = []

crypt               = None
logger              = None

srpUsr              = None

sessionid           = None
clientId            = None
lastTimestamp       = None
backupName          = None
newBackup           = None
filenameKey         = None
contentKey          = None

# Stats block.
# dirs/files/links  == Number of directories/files/links backed up total
# new/delta         == Number of new/delta files sent
# backed            == Total size of data represented by the backup.
# dataSent          == Number of data bytes sent this run (not including messages)
# dataBacked        == Number of bytes backed up this run
# Example: If you have 100 files, and 99 of them are already backed up (ie, one new), backed would be 100, but new would be 1.
# dataSent is the compressed and encrypted size of the files (or deltas) sent in this run, but dataBacked is the total size of
# the files.
stats = { 'dirs' : 0, 'files' : 0, 'links' : 0, 'backed' : 0, 'dataSent': 0, 'dataBacked': 0 , 'new': 0, 'delta': 0}

report = {}

inodeDB             = {}
dirHashes           = {
    (0, 0): ('00000000000000000000000000000000', 0)
    }

# Logging Formatter that allows us to specify formats that won't have a levelname header, ie, those that
# will only have a message
class MessageOnlyFormatter(logging.Formatter):
    def __init__(self, fmt = '%(levelname)s: %(message)s', levels=[logging.INFO]):
        logging.Formatter.__init__(self, fmt)
        self.levels = levels

    def format(self, record):
        if record.levelno in self.levels:
            return record.getMessage()
        return logging.Formatter.format(self, record)

# A custom argument parser to nicely handle argument files, and strip out any blank lines
# or commented lines
class CustomArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super(CustomArgumentParser, self).__init__(*args, **kwargs)

    def convert_arg_line_to_args(self, line):
        for arg in line.split():
            if not arg.strip():
                continue
            if arg[0] == '#':
                break
            yield arg

class ProtocolError(Exception):
    pass

class AuthenticationFailed(Exception):
    pass

def setEncoder(format):
    global encoder, encoding, decoder
    if format == 'base64':
        encoding = "base64"
        encoder  = base64.b64encode
        decoder  = base64.b64decode
    elif format == 'bin':
        encoding = "bin"
        encoder = lambda x: x
        decoder = lambda x: x

systemencoding      = sys.getfilesystemencoding()

def fs_encode(val):
    """ Turn filenames into str's (ie, series of bytes) rather than Unicode things """
    if not isinstance(val, bytes):
        #return val.encode(sys.getfilesystemencoding())
        return val.encode(systemencoding)
    else:
        return val

def checkMessage(message, expected):
    """ Check that a message is of the expected type.  Throw an exception if not """
    if not message['message'] == expected:
        logger.critical("Expected {} message, received {}".format(expected, message['message']))
        raise ProtocolError("Expected {} message, received {}".format(expected, message['message']))

def filelist(dir, excludes):
    """ List the files in a directory, except those that match something in a set of patterns """
    files = map(fs_encode, os.listdir(dir))
    for p in excludes:
        remove = [x for x in fnmatch.filter(files, p)]
        if len(remove):
            files = set(files) - set(remove)
    for f in files:
        yield f

def delInode(inode):
    if inode in inodeDB:
        del inodeDB[inode]

def processChecksums(inodes):
    """ Generate checksums for requested checksum files """
    files = []
    for inode in inodes:
        if inode in inodeDB:
            (_, pathname) = inodeDB[inode]
            if args.progress:
                printProgress("File [C]:", pathname)

            m = Util.getHash(crypt, args.crypt)
            s = os.lstat(pathname)
            mode = s.st_mode
            if stat.S_ISLNK(mode):
                m.update(os.readlink(pathname))
            else:
                with open(pathname, "rb") as file:
                    for chunk in iter(functools.partial(file.read, args.chunksize), ''):
                        m.update(chunk)
            checksum = m.hexdigest()
            files.append({ "inode": inode, "checksum": checksum })
        else:
            logger.error("Unable to process checksum for %s, not found in inodeDB", str(inode))
    message = {
        "message": "CKS",
        "files": files
    }

    #response = sendAndReceive(message)
    #handleAckSum(response)
    batchMessage(message)


def logFileInfo(i, c):
    if i in inodeDB:
        (x, name) = inodeDB[i]
        if "size" in x:
            size = x["size"]
        else:
            size = 0
        size = Util.fmtSize(size, formats=['','KB','MB','GB', 'TB', 'PB'])
        logger.log(logging.FILES, "File: [%c]: %s (%s)", c, Util.shortPath(name), size)

def handleAckSum(response):
    checkMessage(response, 'ACKSUM')
    logfiles = logger.isEnabledFor(logging.FILES)

    done    = response.setdefault('done', {})
    content = response.setdefault('content', {})
    delta   = response.setdefault('delta', {})

    # First, delete all the files which are "done", ie, matched
    for i in [tuple(x) for x in done]:
        if logfiles:
            if i in inodeDB:
                (x, name) = inodeDB[i]
                logger.log(logging.FILES, "File: [C]: %s", Util.shortPath(name))
        delInode(i)

    # First, then send content for any files which don't
    # FIXME: TODO: There should be a test in here for Delta's
    for i in [tuple(x) for x in content]:
        if logfiles:
            logFileInfo(i, 'n')
        sendContent(i, 'Full')
        delInode(i)

    for i in [tuple(x) for x in delta]:
        if logfiles:
            logFileInfo(i, 'd')
        processDelta(i)
        delInode(i)

def makeEncryptor():
    if args.crypt and crypt:
        iv = crypt.getIV()
        encryptor = crypt.getContentCipher(iv)
        func = lambda x: encryptor.encrypt(x)
        pad  = lambda x: crypt.pad(x)
        hmac = crypt.getHash(func=hashlib.sha512)
    else:
        iv = None
        func = lambda x: x
        pad  = lambda x: x
        hmac = None
    return (func, pad, iv, hmac)

def processDelta(inode):
    """ Generate a delta and send it """

    if inode in inodeDB:
        (_, pathname) = inodeDB[inode]
        message = {
            "message" : "SGR",
            "inode" : inode
        }
        if args.progress:
            printProgress("File [D]:", pathname)
        setMessageID(message)
        logger.debug("Processing delta: %s :: %s", str(inode), pathname)

        ## TODO: Comparmentalize this better.  Should be able to handle the SIG response
        ## Separately from the SGR.  Just needs some thinking.  SIG implies immediate
        ## Follow on by more data, which is unique
        sigmessage = sendAndReceive(message)

        if sigmessage['status'] == 'OK':
            newsig = None
            # Try to process the signature and the delta.  If we fail, send the whole content.
            try:
                oldchksum = sigmessage['checksum']
                sigfile = cStringIO.StringIO()
                #sigfile = cStringIO.StringIO(conn.decode(sigmessage['signature']))
                Util.receiveData(conn.sender, sigfile)
                logger.debug("Received sig file: %d", sigfile.tell())
                sigfile.seek(0)

                # If we're encrypted, we need to generate a new signature, and send it along
                makeSig = (args.crypt and crypt) or args.signature

                logger.debug("Generating delta for %s", pathname)

                # Create a buffered reader object, which can generate the checksum and an actual filesize while
                # reading the file.  And, if we need it, the signature
                reader = CompressedBuffer.BufferedReader(open(pathname, "rb"), hasher=Util.getHash(crypt, args.crypt), signature=makeSig)
                # HACK: Monkeypatch the reader object to have a seek function to keep librsync happy.  Never gets called
                reader.seek = lambda x, y: 0

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
            except Exception as e:
                logger.warning("Unable to process signature.  Sending full file: %s: %s", pathname, str(e))
                if args.exceptions:
                    logger.exception(e)
                sendContent(inode, 'Full')
                return

            if deltasize < (filesize * float(args.deltathreshold) / 100.0):
                (encrypt, pad, iv, hmac) = makeEncryptor()
                Util.accumulateStat(stats, 'delta')
                message = {
                    "message": "DEL",
                    "inode": inode,
                    "size": filesize,
                    "checksum": checksum,
                    "basis": oldchksum,
                    "encoding": encoding,
                    "encrypted": (iv is not None)
                }

                batchMessage(message, flush=True, batch=False, response=False)
                compress = (args.compress and (filesize > args.mincompsize))
                progress = printProgress if args.progress else None
                (sent, _, _) = Util.sendData(conn.sender, delta, encrypt, pad, chunksize=args.chunksize, compress=compress, stats=stats, hmac=hmac, iv=iv, progress=progress)
                delta.close()

                # If we have a signature, send it.
                if newsig:
                    message = {
                        "message" : "SIG",
                        "checksum": checksum
                    }
                    #sendMessage(message)
                    batchMessage(message, flush=True, batch=False, response=False)
                    # Send the signature, generated above
                    (sSent, _, _) = Util.sendData(conn.sender, newsig, chunksize=args.chunksize, compress=False, stats=stats, progress=progress)            # Don't bother to encrypt the signature
                    newsig.close()

                if args.report:
                    x = { 'type': 'Delta', 'size': sent }
                    if newsig:
                        x['sigsize'] = sSent
                    else:
                        x['sigsize'] = 0

                    report[os.path.split(pathname)] = x
            else:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("Delta size for %s is too large.  Sending full content: Delta: %d File: %d", Util.shortPath(pathname, 40), deltasize, filesize)
                sendContent(inode, 'Full')
        else:
            sendContent(inode, 'Full')

def sendContent(inode, reportType):
    """ Send the content of a file.  Compress and encrypt, as specified by the options. """

    if inode in inodeDB:
        checksum = None
        (fileInfo, pathname) = inodeDB[inode]
        if pathname:
            if args.progress:
                printProgress("File [N]:", pathname)
            mode = fileInfo["mode"]
            filesize = fileInfo["size"]
            if stat.S_ISDIR(mode):
                return
            (encrypt, pad, iv, hmac) = makeEncryptor()
            message = {
                "message":      "CON",
                "inode":        inode,
                "encoding":     encoding,
                "encrypted":    (iv is not None)
            }

            # Attempt to open the data source
            # Punt out if unsuccessful
            try:
                if stat.S_ISLNK(mode):
                    # It's a link.  Send the contents of readlink
                    data = cStringIO.StringIO(os.readlink(pathname))
                else:
                    data = open(pathname, "rb")
            except IOError as e:
                logger.error("Could not open %s: %s", pathname, e)
                return

            # Attempt to send the data.
            sig = None
            try:
                compress = args.compress if (args.compress and (filesize > args.mincompsize)) else None
                progress = printProgress if args.progress else None
                # Check if it's a file type we don't want to compress
                if compress and noCompTypes:
                    mimeType = magic.from_buffer(data.read(128), mime=True)
                    data.seek(0)
                    if mimeType in noCompTypes:
                        logger.debug("Not compressing %s.  Type %s", pathname, mimeType)
                        compress = False
                makeSig = (args.crypt and crypt) or args.signature
                #sendMessage(message)
                batchMessage(message, batch=False, flush=True, response=False)
                (size, checksum, sig) = Util.sendData(conn.sender, data,
                                                      encrypt, pad, hasher=Util.getHash(crypt, args.crypt),
                                                      chunksize=args.chunksize,
                                                      compress=compress,
                                                      signature=makeSig,
                                                      hmac=hmac,
                                                      iv=iv,
                                                      stats=stats,
                                                      progress=progress)

                if sig:
                    sig.seek(0)
                    message = {
                        "message" : "SIG",
                        "checksum": checksum
                    }
                    #sendMessage(message)
                    batchMessage(message, batch=False, flush=True, response=False)
                    (sSent, _, _) = Util.sendData(conn, sig, chunksize=args.chunksize, stats=stats, progress=progress)            # Don't bother to encrypt the signature
            except Exception as e:
                logger.error("Caught exception during sending of data in %s: %s", pathname, e)
                if args.exceptions:
                    logger.exception(e)
                raise e
            finally:
                if data is not None:
                    data.close()
                if sig is not None:
                    sig.close()

            Util.accumulateStat(stats, 'new')
            if args.report:
                repInfo = { 'type': reportType, 'size': size, 'sigsize': 0 }
                if sig:
                    repInfo['sigsize'] = sSent
                report[os.path.split(pathname)] = repInfo
    else:
        logger.debug("Unknown inode {} -- Probably linked".format(inode))

def handleAckMeta(message):
    checkMessage(message, 'ACKMETA')
    content = message.setdefault('content', {})
    done    = message.setdefault('done', {})

    for cks in content:
        logger.debug("Sending meta data chunk: %s", cks)
        data = metaCache.inverse[cks][0]

        (encrypt, pad, iv, hmac) = makeEncryptor()
        message = {
            "message": "METADATA",
            "checksum": cks,
            "encrypted": (iv is not None)
        }

        sendMessage(message)
        compress = (args.compress and (len(data) > args.mincompsize))
        progress = printProgress if args.progress else None
        Util.sendData(conn.sender, cStringIO.StringIO(data), encrypt, pad, chunksize=args.chunksize, compress=compress, stats=stats, hmac=hmac, iv=iv, progress=progress)

def sendDirHash(inode):
    i = tuple(inode)
    #try:
    #    (h,s) = dirHashes[i]
    #except KeyError:
    #    logger.error("%s, No directory hash available for inode %d on device %d", i, i[0], i[1])
    (h,s) = dirHashes.setdefault(i, ('00000000000000000000000000000000', 0))

    message = {
        'message': 'DHSH',
        'inode'  : inode,
        'hash'   : h,
        'size'   : s
        }

    batchMessage(message)
    del dirHashes[i]

def cksize(i, threshhold):
    if i in inodeDB:
        (f, _) = inodeDB[i]
        if f['size'] > threshhold:
            return True
    return False

def handleAckDir(message):
    checkMessage(message, 'ACKDIR')

    content = message.setdefault("content", {})
    done    = message.setdefault("done", {})
    delta   = message.setdefault("delta", {})
    cksum   = message.setdefault("cksum", {})
    refresh = message.setdefault("refresh", {})

    if verbosity > 2:
        logger.debug("Processing ACKDIR: Up-to-date: %3d New Content: %3d Delta: %3d ChkSum: %3d -- %s", len(done), len(content), len(delta), len(cksum), Util.shortPath(message['path'], 40))

    for i in [tuple(x) for x in done]:
        delInode(i)

    # If checksum content in NOT specified, send the data for each file
    for i in [tuple(x) for x in content]:
        if args.ckscontent and cksize(i, args.ckscontent):
            cksum.append(i)
        else:
            if logger.isEnabledFor(logging.FILES):
                logFileInfo(i, 'N')
            sendContent(i, 'New')
            delInode(i)

    for i in [tuple(x) for x in refresh]:
        if logger.isEnabledFor(logging.FILES):
            logFileInfo(i, 'N')
        sendContent(i, 'Full')
        delInode(i)

    for i in [tuple(x) for x in delta]:
        # If doing a full backup, send the full file, else just a delta.
        if args.full:
            if logger.isEnabledFor(logging.FILES):
                logFileInfo(i, 'N')
            sendContent(i, 'Full')
        else:
            if logger.isEnabledFor(logging.FILES):
                if i in inodeDB:
                    (x, name) = inodeDB[i]
                    logger.log(logging.FILES, "File: [D]: %s", Util.shortPath(name))
            processDelta(i)
        delInode(i)

    # If checksum content is specified, concatenate the checksums and content requests, and handle checksums
    # for all of them.
    if len(cksum) > 0:
        processChecksums([tuple(x) for x in cksum])

    #if message['last']:
    #    sendDirHash(message['inode'])

def addMeta(meta):
    """
    Add data to the metadata cache
    """
    if meta in metaCache:
        return metaCache[meta]
    else:
        m = Util.getHash(crypt, args.crypt)
        m.update(meta)
        digest = m.hexdigest()
        metaCache[meta] = digest
        newmeta.append(digest)
        return digest

def mkFileInfo(dir, name):
    pathname = os.path.join(dir, name)
    s = os.lstat(pathname)
    mode = s.st_mode
    if stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
        if args.crypt and crypt:
            name = crypt.encryptFilename(name.decode(systemencoding, 'replace'))
        finfo =  {
            'name':   name,
            'inode':  s.st_ino,
            'dir':    stat.S_ISDIR(mode),
            'link':   stat.S_ISLNK(mode),
            'nlinks': s.st_nlink,
            'size':   s.st_size,
            'mtime':  int(s.st_mtime),              # We strip these down to the integer value beacuse FP conversions on the back side can get confused.
            'ctime':  int(s.st_ctime),
            'atime':  int(s.st_atime),
            'mode':   s.st_mode,
            'uid':    s.st_uid,
            'gid':    s.st_gid,
            'dev':    s.st_dev
            }

        if support_xattr and args.xattr:
            attrs = xattr.xattr(pathname, options=xattr.XATTR_NOFOLLOW)
            #items = attrs.items()
            if len(attrs):
                # Convert to a set of readable string tuples
                # We base64 encode the data chunk, as it's often binary
                # Ugly, but unfortunately necessary
                attr_string = json.dumps(dict(map(lambda x: (str(x[0]), base64.b64encode(x[1])), sorted(attrs.iteritems()))))
                cks = addMeta(attr_string)
                finfo['xattr'] = cks

        if support_acl and args.acl and not stat.S_ISLNK(mode):
            # BUG:? FIXME:? ACL section doesn't seem to work on symbolic links.  Instead wants to follow the link.
            # Definitely an issue
            if posix1e.has_extended(pathname):
                acl = posix1e.ACL(file=pathname)
                cks = addMeta(str(acl))
                finfo['acl'] = cks

        inodeDB[(s.st_ino, s.st_dev)] = (finfo, pathname)
    else:
        if verbosity:
            logger.info("Skipping special file: %s", pathname)
        finfo = None
    return finfo

def getDirContents(dir, dirstat, excludes=[]):
    """ Read a directory, load any new exclusions, delete the excluded files, and return a list
        of the files, a list of sub directories, and the new list of excluded patterns """

    #logger.debug("Processing directory : %s", dir)
    Util.accumulateStat(stats, 'dirs')
    device = dirstat.st_dev

    # Process an exclude file which will be passed on down to the receivers
    newExcludes = loadExcludeFile(os.path.join(dir, excludeFile))
    newExcludes.extend(excludes)
    excludes = newExcludes

    # Add a list of local files to exclude.  These won't get passed to lower directories
    localExcludes = list(excludes)
    localExcludes.extend(loadExcludeFile(os.path.join(dir, args.localexcludefile)))

    files = []
    subdirs = []

    try:
        for f in filelist(dir, localExcludes):
            try:
                fInfo = mkFileInfo(dir, f)
                if fInfo and (args.crossdev or device == fInfo['dev']):
                    mode = fInfo["mode"]
                    if stat.S_ISLNK(mode):
                        Util.accumulateStat(stats, 'links')
                    elif stat.S_ISREG(mode):
                        Util.accumulateStat(stats, 'files')
                        Util.accumulateStat(stats, 'backed', fInfo['size'])

                    if stat.S_ISDIR(mode):
                        sub = os.path.join(dir, f)
                        if sub in excludeDirs:
                            logger.debug("%s excluded.  Skipping", sub)
                            continue
                        else:
                            subdirs.append(sub)

                    files.append(fInfo)
            except (IOError, OSError) as e:
                logger.error("Error processing %s: %s", os.path.join(dir, f), str(e))
            except Exception as e:
                ## Is this necessary?  Fold into above?
                logger.error("Error processing %s: %s", os.path.join(dir, f), str(e))
                if args.exceptions:
                    logger.exception(e)
    except (IOError, OSError) as e:
        logger.error("Error reading directory %s: %s" ,dir, str(e))

    return (files, subdirs, excludes)

def handleAckClone(message):
    checkMessage(message, 'ACKCLN')
    if verbosity > 2:
        logger.debug("Processing ACKCLN: Up-to-date: %d New Content: %d", len(message['done']), len(message['content']))

    logdirs = logger.isEnabledFor(logging.DIRS)

    content = message.setdefault('content', {})
    done    = message.setdefault('done', {})

    # Process the directories that have changed
    for i in content:
        finfo = tuple(i)
        if finfo in cloneContents:
            (path, files) = cloneContents[finfo]
            if logdirs:
                logger.log(logging.DIRS, "Dir: [R]: %s", Util.shortPath(path))
            sendDirChunks(path, finfo, files)
            del cloneContents[finfo]
        else:
            logger.error("Unable to locate info for %s", str(finfo))

    # Purge out what hasn't changed
    for i in done:
        inode = tuple(i)
        if inode in cloneContents:
            (path, files) = cloneContents[inode]
            for f in files:
                key = (f['inode'], f['dev'])
                delInode(key)
            del cloneContents[inode]
        else:
            logger.error("Unable to locate info for %s", inode)
        # And the directory.
        delInode(inode)

def makeCloneMessage():
    global cloneDirs
    message = {
        'message': 'CLN',
        'clones': cloneDirs
    }
    cloneDirs = []
    return message

def sendClones():
    message = makeCloneMessage()
    setMessageID(message)
    response = sendAndReceive(message)
    checkMessage(response, 'ACKCLN')
    handleAckClone(response)

def flushClones():
    if cloneDirs:
        logger.debug("Flushing %d clones", len(cloneDirs))
        if args.batchdirs:
            batchMessage(makeCloneMessage())
        else:
            sendClones()

def sendBatchMsgs():
    global batchMsgs
    logger.debug("Sending %d batch messages", len(batchMsgs))
    message = {
        'message' : 'BATCH',
        'batch': batchMsgs
    }
    setMessageID(message)
    logger.debug("BATCH Starting. %s commands", len(batchMsgs))

    batchMsgs = []

    response = sendAndReceive(message)
    checkMessage(response, 'ACKBTCH')
    # Process the response messages
    logger.debug("Got response.  %d responses", len(response['responses']))
    handleResponse(response)
    logger.debug("BATCH Ending.")

def flushBatchMsgs():
    if len(batchMsgs):
        sendBatchMsgs()
        return True
    else:
        return False

def sendPurge(relative):
    """ Send a purge message.  Indicate if this time is relative (ie, days before now), or absolute. """
    message =  { 'message': 'PRG' }
    if purgePriority:
        message['priority'] = purgePriority
    if purgeTime:
        message.update( { 'time': purgeTime, 'relative': relative })

    batchMessage(message, flush=True, batch=False)

def sendDirChunks(path, inode, files):
    """ Chunk the directory into dirslice sized chunks, and send each sequentially """
    message = {
        'message': 'DIR',
        'path'   :  path,
        'inode'  : list(inode),
    }

    chunkNum = 0
    for x in range(0, len(files), args.dirslice):
        if verbosity > 3:
            logger.debug("---- Generating chunk %d ----", chunkNum)
        chunkNum += 1
        chunk = files[x : x + args.dirslice]
        message["files"] = chunk
        message["last"]  = (x + args.dirslice > len(files))
        if verbosity > 3:
            logger.debug("---- Sending chunk ----")
        batchMessage(message, batch=False)

    sendDirHash(inode)

def makeMetaMessage():
    global newmeta
    message = {
        'message': 'META',
        'metadata': newmeta
        }
    newmeta = []
    return message

_progressBarFormat = None
_windowWidth = 80
_ansiClearEol = '\x1b[K'
_startOfLine = '\r'

def initProgressBar():
    _, width = Util.getTerminalSize()
    global _progressBarFormat, _windowWidth

    if width < 110:
        _progressBarFormat = '(%d, %d) :: (%d, %d, %s) :: %s '
    else:
        _progressBarFormat = 'Dirs: %d | Files: %d | Full: %d | Delta: %d | Data: %s | %s '
    _windowWidth = width

    #logger.warning("Initializing progress bar.  Width: %d. Path Width: %d.  Format: %s",
    #            width, _progressPathWidth, _progressBarFormat)
    #print _progressBarFormat
    #sys.exit()

_lastInfo = (None, None)                # STATIC for printProgress

def printProgress(header=None, name=None):
    global _lastInfo
    bar = _progressBarFormat % ( stats['dirs'], stats['files'], stats['new'], stats['delta'], Util.fmtSize(stats['dataSent']), header or _lastInfo[0])

    width = _windowWidth - len(bar) - 4
    print bar + Util.shortPath(name or _lastInfo[1], width) + _ansiClearEol + _startOfLine,
    if header or name:
        #update the last info
        _lastInfo = (header or _lastInfo[0], name or _lastInfo[1])
    sys.stdout.flush()

processedDirs = set()

def recurseTree(dir, top, depth=0, excludes=[]):
    """ Process a directory, send any contents along, and then dive down into subdirectories and repeat. """
    global dirHashes

    newdepth = 0
    if depth > 0:
        newdepth = depth - 1

    s = os.lstat(dir)
    if not stat.S_ISDIR(s.st_mode):
        return

    if args.progress:
        printProgress("Dir:", dir)
    try:
        # Mark that we've processed it before attempting to determine if we actually should
        processedDirs.add(dir)

        if dir in excludeDirs:
            logger.debug("%s excluded.  Skipping", dir)
            return

        if os.path.lexists(os.path.join(dir, args.skipfile)):
            logger.debug("Skip file found.  Skipping %s", dir)
            return

        if args.skipcaches and os.path.lexists(os.path.join(dir, 'CACHEDIR.TAG')):
            logger.debug("CACHEDIR.TAG file found.  Analyzing")
            try:
                with file(os.path.join(dir, 'CACHEDIR.TAG'), 'r') as f:
                    line = f.readline()
                    if line.startswith('Signature: 8a477f597d28d172789f06886806bc55'):
                        logger.debug("Valid CACHEDIR.TAG file found.  Skipping %s", dir)
                        return
            except:
                logger.warning("Could not read %s.  Backing up directory %s", os.path.join(dir, 'CACHEDIR.TAG'), dir)

        (files, subdirs, subexcludes) = getDirContents(dir, s, excludes)

        h = Util.hashDir(crypt, files, args.crypt)
        #logger.debug("Dir: %s (%d, %d): Hash: %s Size: %d.", Util.shortPath(dir), s.st_ino, s.st_dev, h[0], h[1])
        dirHashes[(s.st_ino, s.st_dev)] = h

        # Figure out which files to clone, and which to update
        if files and args.clones:
            if len(files) > args.clonethreshold:
                newFiles = [f for f in files if max(f['ctime'], f['mtime']) >= lastTimestamp]
                oldFiles = [f for f in files if max(f['ctime'], f['mtime']) < lastTimestamp]
            else:
                maxTime = max(map(lambda x: max(x["ctime"], x["mtime"]), files))
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
                batchMessage(makeMetaMessage())

            if oldFiles:
                # There are oldfiles.  Hash them.
                if logger.isEnabledFor(logging.DIRS):
                    logger.log(logging.DIRS, "Dir: [A]: %s", Util.shortPath(dir))
                cloneDir(s.st_ino, s.st_dev, oldFiles, dir)
            else:
                if logger.isEnabledFor(logging.DIRS):
                    logger.log(logging.DIRS, "Dir: [B]: %s", Util.shortPath(dir))
            sendDirChunks(os.path.relpath(dir, top), (s.st_ino, s.st_dev), newFiles)

        else:
            # everything is old
            if logger.isEnabledFor(logging.DIRS):
                logger.log(logging.DIRS, "Dir: [C]: %s", Util.shortPath(dir))
            cloneDir(s.st_ino, s.st_dev, oldFiles, dir, info=h)

        # Make sure we're not at maximum depth
        if depth != 1:
            # Purge out the lists.  Allow garbage collection to take place.  These can get largish.
            files = oldFiles = newFiles = None
            # Process the sub directories
            for subdir in sorted(subdirs):
                recurseTree(subdir, top, newdepth, subexcludes)

    except (OSError) as e:
        logger.error("Error handling directory: %s: %s", dir, str(e))
        #raise
        #traceback.print_exc()
    except (IOError) as e:
        logger.error("Error handling directory: %s: %s", dir, str(e))
        raise
    except Exception as e:
        # TODO: Clean this up
        if args.exceptions:
            logger.exception(e)
        raise

def cloneDir(inode, device, files, path, info=None):
    """ Send a clone message, containing the hash of the filenames, and the number of files """
    if info:
        (h, s) = info
    else:
        (h, s) = Util.hashDir(crypt, files, args.crypt)

    message = {'inode':  inode, 'dev': device, 'numfiles': s, 'cksum': h}
    cloneDirs.append(message)
    cloneContents[(inode, device)] = (path, files)
    if len(cloneDirs) >= args.clones:
        flushClones()

def splitDir(files, when):
    newFiles = []
    oldFiles = []
    for f in files:
        if f['mtime'] < when:
            oldFiles.append(f)
        else:
            newFiles.append(f)
    return newFiles, oldFiles


def setBackupName(args):
    """ Calculate the name of the backup set """
    global purgeTime, purgePriority, starttime
    name = args.name
    priority = args.priority
    auto = True

    # If a name has been specified, we're not an automatic set.
    if name:
        auto = False
    else:
        # Else, no name specified, we're auto.  Create a default name.
        name = time.strftime("Backup_%Y-%m-%d_%H:%M:%S")

    if args.purge:
        purgePriority = priority
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
                #logger.error("Could not parse --keep-time argument: %s", args.purgetime)
                raise Exception("Could not parse --keep-time argument: {} ".format(args.purgetime))

    return (name, priority, auto)

def loadExcludeFile(name):
    """ Load a list of patterns to exclude from a file. """
    try:
        with open(name) as f:
            excludes = [x.rstrip('\n') for x in f.readlines()]
        return excludes
    except IOError as e:
        #traceback.print_exc()
        return []



# Load all the excludes we might want
def loadExcludes(args):
    global excludeFile
    if not args.ignoreglobalexcludes:
        globalExcludes.extend(loadExcludeFile(globalExcludeFile))
    if args.cvs:
        globalExcludes.extend(cvsExcludes)
    if args.excludes:
        globalExcludes.extend(args.excludes)
    if args.excludefiles:
        for f in args.excludefiles:
            globalExcludes.extend(loadExcludeFile(f))
    excludeFile         = args.excludefilename

def loadExcludedDirs(args):
    global excludeDirs
    if args.excludedirs is not None:
        excludeDirs.extend(map(Util.fullPath, args.excludedirs))

def sendMessage(message):
    if verbosity > 4:
        logger.debug("Send: %s", str(message))
    conn.send(message)

def receiveMessage():
    response = conn.receive()
    if verbosity > 4:
        logger.debug("Receive: %s", str(response))
    return response

def sendAndReceive(message):
    sendMessage(message)
    response = receiveMessage()
    return response

def sendKeys(password, client, includeKeys=True):
    logger.debug("Sending keys")
    (f, c) = crypt.getKeys()
    salt, vkey = crypt.createSRPValues(password, client)
    message = { "message": "SETKEYS",
                "filenameKey": f,
                "contentKey": c,
                "srpSalt": salt,
                "srpVkey": vkey
              }
    response = sendAndReceive(message)
    checkMessage(response, 'ACKSETKEYS')
    if response['response'] != 'OK':
        logger.error("Could not set keys")

def handleResponse(response):
    msgtype = response['message']
    if msgtype == 'ACKDIR':
        handleAckDir(response)
    elif msgtype == 'ACKCLN':
        handleAckClone(response)
    elif msgtype == 'ACKPRG':
        pass
    elif msgtype == 'ACKSUM':
        handleAckSum(response)
    elif msgtype == 'ACKMETA':
        handleAckMeta(response)
    elif msgtype == 'ACKDHSH':
        # TODO: Respond
        pass
    elif msgtype == 'ACKBTCH':
        for ack in response['responses']:
            handleResponse(ack)
    else:
        logger.error("Unexpected response: %s", msgtype)

nextMsgId = 0
def setMessageID(message):
    global nextMsgId
    message['msgid'] = nextMsgId
    nextMsgId += 1

def batchMessage(message, batch=True, flush=False, response=True):
    setMessageID(message)

    batch = batch and (args.batchsize > 0)

    if batch:
        batchMsgs.append(message)
    if flush or not batch or len(batchMsgs) >= args.batchsize:
        flushClones()
        flushBatchMsgs()
    if not batch:
        if response:
            respmessage = sendAndReceive(message)
            handleResponse(respmessage)
        else:
            sendMessage(message)

def sendDirEntry(parent, device, files):
    # send a fake root directory
    message = {
        'message': 'DIR',
        'files': files,
        'path' : None,
        'inode': [parent, device],
        'files': files,
        'last' : True
        }

    #for x in map(os.path.realpath, args.directories):
        #(dir, name) = os.path.split(x)
        #file = mkFileInfo(dir, name)
        #if file and file["dir"] == 1:
            #files.append(file)
    #
    # and send it.
    batchMessage(message)

def splitDirs(x):
    root, rest = os.path.split(x)
    if root and rest:
        ret = splitDirs(root)
        ret.append(rest)
    elif root:
        if root is '/':
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
    parentDev = 0
    current   = root
    for d in pathDirs:
        dirPath = os.path.join(current, d)
        st = os.lstat(dirPath)
        f = mkFileInfo(current, d)
        if dirPath not in processedDirs:
            logger.debug("Sending dir entry for: %s", dirPath)
            sendDirEntry(parent, parentDev, [f])
            processedDirs.add(dirPath)
        parent    = st.st_ino
        parentDev = st.st_dev
        current   = dirPath

def runServer(cmd, tempfile):
    server_cmd = shlex.split(cmd) + ['--single', '--local', tempfile]
    logger.debug("Invoking server: " + str(server_cmd))
    subp = subprocess.Popen(server_cmd)
    # Wait until the subprocess has created the domain socket.
    # There's got to be a better way to do this. Oy.
    for _ in range(0, 20):
        if os.path.exists(tempfile):
            return subp
        if subp.poll():
            raise Exception("Subprocess died: %d" % (subp.returncode))
        time.sleep(0.5)

    logger.error("Unable to locate socket %s from process %d.  Killing subprocess", tempfile, subp.pid)
    subp.terminate()
    return None

def doSrpAuthentication(message):
    try:
        srpValueS = base64.b64decode(message['srpValueS'])
        srpValueB = base64.b64decode(message['srpValueB'])

        logger.debug("Received Challenge : %s, %s", hexlify(srpValueS), hexlify(srpValueB))

        srpValueM = srpUsr.process_challenge(srpValueS, srpValueB)

        if srpValueM is None:
            raise AuthenticationFailed("Authentication Failed")
        logger.debug("Authentication Challenge response: %s", hexlify(srpValueM))

        message = {
            'message': 'AUTH2',
            'srpValueM': base64.b64encode(srpValueM)
        }

        resp = sendAndReceive(message)
        if resp['status'] == 'AUTHFAIL':
            raise AuthenticationFailed("Authentication Failed")
        srpHamk = base64.b64decode(resp['srpValueHAMK'])
        srpUsr.verify_session(srpHamk)
        return resp
    except KeyError as e:
        logger.error("Key not found %s", str(e))
        raise AuthenticationFailed("response incomplete")
    

def startBackup(name, priority, client, autoname, force, full=False, version=0):
    global sessionid, clientId, lastTimestamp, backupName, newBackup, filenameKey, contentKey

    # Create a BACKUP message
    message = {
            'message'   : 'BACKUP',
            'host'      : client,
            'encoding'  : encoding,
            'name'      : name,
            'priority'  : priority,
            'autoname'  : autoname,
            'force'     : force,
            'time'      : time.time(),
            'version'   : version,
            'full'      : full
    }
    if srpUsr:
        srpUname, srpValueA = srpUsr.start_authentication()
        logger.debug("Starting Authentication: %s, %s", hexlify(srpUname), hexlify(srpValueA))
        message['srpUname']  = base64.b64encode(srpUname)           # Probably unnecessary, uname == client
        message['srpValueA'] = base64.b64encode(srpValueA)

    # BACKUP { json message }
    resp = sendAndReceive(message)

    if resp['status'] == 'AUTH':
        resp = doSrpAuthentication(resp)
    if resp['status'] != 'OK':
        errmesg = "BACKUP request failed"
        if 'error' in resp:
            errmesg = errmesg + ": " + resp['error']
        raise Exception(errmesg)

    sessionid      = uuid.UUID(resp['sessionid'])
    clientId       = uuid.UUID(resp['clientid'])
    lastTimestamp  = float(resp['prevDate'])
    backupName     = resp['name']
    newBackup      = resp['new']
    if 'filenameKey' in resp:
        filenameKey = resp['filenameKey']
    if 'contentKey' in resp:
        contentKey = resp['contentKey']

def getConnection(server, port):
    #if args.protocol == 'json':
    #    conn = Connection.JsonConnection(server, port, name, priority, client, autoname=auto, token=token, force=args.force, timeout=args.timeout, full=args.full)
    #    setEncoder("base64")
    #elif args.protocol == 'bson':
    #    conn = Connection.BsonConnection(server, port, name, priority, client, autoname=auto, token=token, compress=args.compressmsgs, force=args.force, timeout=args.timeout, full=args.full)
    #    setEncoder("bin")
    #elif args.protocol == 'msgp':

    conn = Connection.MsgPackConnection(server, port, compress=args.compressmsgs, timeout=args.timeout)
    setEncoder("bin")
    return conn

def splitList(line):
    if not line:
        return []
    else:
        return shlex.split(line.strip())

def checkConfig(c, t):
    # Check things in the config file that might be confusing
    # CompressedBuffer will convert True or 1 to zlib, anything else not in the list to none
    comp = c.get(t, 'CompressData').lower()
    if (comp == 'true') or (comp == '1'):
        c.set(t, 'CompressData', 'zlib')
    elif not (comp in CompressedBuffer.getCompressors()):
        c.set(t, 'CompressData', 'none')

def processCommandLine():
    """ Do the command line thing.  Register arguments.  Parse it. """
    def _d(help):
        """ Only print the help message if --debug is specified """
        return help if args.debug else argparse.SUPPRESS

    # Use the custom arg parser, which handles argument files more cleanly
    parser = CustomArgumentParser(description='Tardis Backup Client', fromfile_prefix_chars='@', formatter_class=Util.HelpFormatter, add_help=False,
                                  epilog='Options can be specified in files, with the filename specified by an @sign: e.g. "%(prog)s @args.txt" will read arguments from args.txt')

    parser.add_argument('--config',                 dest='config', default=None,                                        help='Location of the configuration file.   Default: %(default)s')
    parser.add_argument('--job',                    dest='job', default='Tardis',                                       help='Job Name within the configuration file.  Default: %(default)s')
    parser.add_argument('--debug',                  dest='debug', default=False, action='store_true',                   help=argparse.SUPPRESS)
    (args, remaining) = parser.parse_known_args()

    t = args.job
    c = ConfigParser.ConfigParser(configDefaults)
    if args.config:
        c.read(args.config)
        if not c.has_section(t):
            sys.stderr.write("WARNING: No Job named %s listed.  Using defaults.  Jobs available: %s\n" %(t, str(c.sections()).strip('[]')))
            c.add_section(t)                    # Make it safe for reading other values from.
        checkConfig(c, t)
    else:
        c.add_section(t)                        # Make it safe for reading other values from.

    parser.add_argument('--server', '-s',           dest='server', default=c.get(t, 'Server'),                          help='Set the destination server. Default: %(default)s')
    parser.add_argument('--port', '-p',             dest='port', type=int, default=c.getint(t, 'Port'),                 help='Set the destination server port. Default: %(default)s')
    parser.add_argument('--log', '-l',              dest='logfiles', action='append', default=splitList(c.get(t, 'LogFiles')), nargs="?", const=sys.stderr,
                        help='Send logging output to specified file.  Can be repeated for multiple logs. Default: stderr')

    parser.add_argument('--client',                 dest='client', default=c.get(t, 'Client'),                          help='Set the client name.  Default: %(default)s')
    parser.add_argument('--force',                  dest='force', action=Util.StoreBoolean, default=c.getboolean(t, 'Force'),
                        help='Force the backup to take place, even if others are currently running')
    parser.add_argument('--full',                   dest='full', action=Util.StoreBoolean, default=c.getboolean(t, 'Full'),
                        help='Perform a full backup, with no delta information. Default: %(default)s')
    parser.add_argument('--name',   '-n',           dest='name', default=None,                                          help='Set the backup name.  No name to assign name automatically')
    parser.add_argument('--timeout',                dest='timeout', default=300.0, type=float, const=None,              help='Set the timeout to N seconds.  Default: %(default)s')

    passgroup = parser.add_argument_group("Password/Encryption specification options")
    pwgroup = passgroup.add_mutually_exclusive_group()
    pwgroup.add_argument('--password', '-P',        dest='password', default=c.get(t, 'Password'), nargs='?', const=True,
                         help='Password.  Enables encryption')
    pwgroup.add_argument('--password-file', '-F',   dest='passwordfile', default=c.get(t, 'PasswordFile'),              help='Read password from file.  Can be a URL (HTTP/HTTPS or FTP)')
    pwgroup.add_argument('--password-prog',         dest='passwordprog', default=c.get(t, 'PasswordProg'),              help='Use the specified command to generate the password on stdout')

    passgroup.add_argument('--crypt',               dest='crypt',action=Util.StoreBoolean, default=c.getboolean(t, 'Crypt'),
                           help='Encrypt data.  Only valid if password is set')
    passgroup.add_argument('--keys',                dest='keys', default=c.get(t, 'KeyFile'),
                           help='Load keys from file.  Keys are not stored in database')

    parser.add_argument('--send-config', '-S',      dest='sendconfig', action=Util.StoreBoolean, default=c.getboolean(t, 'SendClientConfig'),
                        help='Send the client config (effective arguments list) to the server for debugging.  Default=%(default)s');

    parser.add_argument('--compress-data',  '-Z',   dest='compress', const='zlib', default=c.get(t, 'CompressData'), nargs='?', choices=CompressedBuffer.getCompressors(),
                        help='Compress files.  Default: %(default)s')
    parser.add_argument('--compress-min',           dest='mincompsize', type=int, default=c.getint(t, 'CompressMin'),   help='Minimum size to compress.  Default: %(default)d')
    parser.add_argument('--nocompress-types',       dest='nocompressfile', default=splitList(c.get(t, 'NoCompressFile')), action='append',
                        help='File containing a list of MIME types to not compress.  Default: %(default)s')
    parser.add_argument('--nocompress', '-z',       dest='nocompress', default=splitList(c.get(t, 'NoCompress')), action='append',
                        help='MIME type to not compress. Can be repeated')
    if support_xattr:
        parser.add_argument('--xattr',              dest='xattr', default=True, action=Util.StoreBoolean,               help='Backup file extended attributes')
    if support_acl:
        parser.add_argument('--acl',                dest='acl', default=True, action=Util.StoreBoolean,                 help='Backup file access control lists')

    locgrp = parser.add_argument_group("Arguments for running server locally under tardis")
    locgrp.add_argument('--local',              dest='local', action=Util.StoreBoolean, default=c.getboolean(t, 'Local'),
                        help='Run server as a local client')
    locgrp.add_argument('--local-server-cmd',   dest='serverprog', default=c.get(t, 'LocalServerCmd'),                  help='Local server program to run.  Default: %(default)s')

    parser.add_argument('--priority',           dest='priority', type=int, default=None,                                help='Set the priority of this backup')
    parser.add_argument('--maxdepth', '-d',     dest='maxdepth', type=int, default=0,                                   help='Maximum depth to search')
    parser.add_argument('--crossdevice',        dest='crossdev', action=Util.StoreBoolean,                              help='Cross devices')

    parser.add_argument('--basepath',           dest='basepath', default='full', choices=['none', 'common', 'full'],    help="Select style of root path handling Default: %(default)s")

    excgrp = parser.add_argument_group('Exclusion options', 'Options for handling exclusions')
    excgrp.add_argument('--cvs-ignore',                 dest='cvs', default=c.getboolean(t, 'IgnoreCVS'), action=Util.StoreBoolean,
                        help='Ignore files like CVS')
    excgrp.add_argument('--skip-caches',                dest='skipcaches', default=c.getboolean(t, 'SkipCaches'),action=Util.StoreBoolean,
                        help='Skip directories with valid CACHEDIR.TAG files')
    excgrp.add_argument('--exclude', '-x',              dest='excludes', action='append', default=splitList(c.get(t, 'ExcludePatterns')),
                        help='Patterns to exclude globally (may be repeated)')
    excgrp.add_argument('--exclude-file', '-X',         dest='excludefiles', action='append',                           help='Load patterns from exclude file (may be repeated)')
    excgrp.add_argument('--exclude-dir',                dest='excludedirs', action='append', default=splitList(c.get(t, 'ExcludeDirs')),
                        help='Exclude certain directories by path')

    excgrp.add_argument('--exclude-file-name',          dest='excludefilename', default=c.get(t, 'ExcludeFileName'),
                        help='Load recursive exclude files from this.  Default: %(default)s')
    excgrp.add_argument('--local-exclude-file-name',    dest='localexcludefile', default=c.get(t, 'LocalExcludeFileName'),
                        help='Load local exclude files from this.  Default: %(default)s')
    excgrp.add_argument('--skip-file-name',             dest='skipfile', default=c.get(t, 'SkipFileName'),
                        help='File to indicate to skip a directory.  Default: %(default)s')
    excgrp.add_argument('--ignore-global-excludes',     dest='ignoreglobalexcludes', action=Util.StoreBoolean, default=False,
                        help='Ignore the global exclude file')

    comgrp = parser.add_argument_group('Communications options', 'Options for specifying details about the communications protocol.')
    comgrp.add_argument('--compress-msgs', '-C',    dest='compressmsgs', nargs='?', const='zlib', choices=['none', 'zlib', 'zlib-stream', 'snappy'], default=c.get(t, 'CompressMsgs'),
                        help='Compress messages.  Default: %(default)s')
    comgrp.add_argument('--cks-content',            dest='ckscontent', default=c.getint(t, 'ChecksumContent'), type=int, nargs='?', const=4096,
                        help='Checksum files before sending.  Is the minimum size to checksum (smaller files automaticaly sent).  Can reduce run time if lots of duplicates are expected.  Default: %(default)s')

    comgrp.add_argument('--clones', '-L',           dest='clones', type=int, default=100,               help=_d('Maximum number of clones per chunk.  0 to disable cloning.  Default: %(default)s'))
    comgrp.add_argument('--minclones',              dest='clonethreshold', type=int, default=64,        help=_d('Minimum number of files to do a partial clone.  If less, will send directory as normal: %(default)s'))
    comgrp.add_argument('--batchdir', '-B',         dest='batchdirs', type=int, default=16,             help=_d('Maximum size of small dirs to send.  0 to disable batching.  Default: %(default)s'))
    comgrp.add_argument('--batchsize',              dest='batchsize', type=int, default=100,            help=_d('Maximum number of small dirs to batch together.  Default: %(default)s'))
    comgrp.add_argument('--chunksize',              dest='chunksize', type=int, default=256*1024,       help=_d('Chunk size for sending data.  Default: %(default)s'))
    comgrp.add_argument('--dirslice',               dest='dirslice', type=int, default=1000,            help=_d('Maximum number of directory entries per message.  Default: %(default)s'))
    comgrp.add_argument('--protocol',               dest='protocol', default="msgp", choices=['json', 'bson', 'msgp'],
                        help=_d('Protocol for data transfer.  Default: %(default)s'))
    comgrp.add_argument('--signature',              dest='signature', default=c.getboolean(t, 'SendSig'), action=Util.StoreBoolean,
                        help=_d('Always send a signature.  Default: %(default)s'))

    parser.add_argument('--deltathreshold',         dest='deltathreshold', default=66, type=int,
                        help=_d('If delta file is greater than this percentage of the original, a full version is sent.  Default: %(default)s'))

    parser.add_argument('--sanity',                 dest='sanity', default=False, action=Util.StoreBoolean, help=_d('Run sanity checks to determine if everything is pushed to server'))

    purgegroup = parser.add_argument_group("Options for purging old backup sets")
    purgegroup.add_argument('--purge',              dest='purge', action=Util.StoreBoolean, default=c.getboolean(t, 'Purge'),  help='Purge old backup sets when backup complete')
    purgegroup.add_argument('--purge-priority',     dest='purgeprior', type=int, default=None,              help='Delete below this priority (Default: Backup priority)')

    prggroup = purgegroup.add_mutually_exclusive_group()
    prggroup.add_argument('--keep-days',        dest='purgedays', type=int, default=None,           help='Number of days to keep')
    prggroup.add_argument('--keep-hours',       dest='purgehours', type=int, default=None,          help='Number of hours to keep')
    prggroup.add_argument('--keep-time',        dest='purgetime', default=None,                     help='Purge before this time.  Format: YYYY/MM/DD:hh:mm')

    parser.add_argument('--stats',              action=Util.StoreBoolean, dest='stats', default=c.getboolean(t, 'Stats'),
                        help='Print stats about the transfer.  Default=%(default)s')
    parser.add_argument('--report',             action=Util.StoreBoolean, dest='report', default=c.getboolean(t, 'Report'),
                        help='Print a report on all files transferred.  Default=%(default)s')
    parser.add_argument('--verbose', '-v',      dest='verbose', action='count', default=c.getint(t, 'Verbosity'),
                        help='Increase the verbosity')
    parser.add_argument('--progress',           dest='progress', action='store_true',               help='Show a one-line progress bar.')

    parser.add_argument('--exclusive',          dest='exclusive', action=Util.StoreBoolean, default=True, help='Make sure the client only runs one job at a time. Default: %(default)s')
    parser.add_argument('--log-exceptions',     dest='exceptions', default=False, action=Util.StoreBoolean, help='Log full exception details')

    parser.add_argument('--version',            action='version', version='%(prog)s ' + Tardis.__versionstring__, help='Show the version')
    parser.add_argument('--help', '-h',         action='help')

    parser.add_argument('directories',          nargs='*', default=splitList(c.get(t, 'Directories')), help="List of directories to sync")

    return (parser.parse_args(remaining), c)

def parseServerInfo(args):
    """ Break up the server info passed in into useable chunks """
    if args.local:
        sServer = 'localhost'
        sPort   = 'local'
        sClient = args.client
    else:
        serverStr = args.server
        #logger.debug("Got server string: %s", serverStr)
        if not serverStr.startswith('tardis://'):
            serverStr = 'tardis://' + serverStr
        try:
            info = urlparse.urlparse(serverStr)
            if info.scheme != 'tardis':
                raise Exception("Invalid URL scheme: {}".format(info.scheme))

            sServer = info.hostname
            sPort   = info.port
            sClient = info.path.lstrip('/')

        except Exception as e:
            raise Exception("Invalid URL: {} -- {}".format(args.server, e.message))

    server = sServer or args.server
    port = sPort or args.port
    client = sClient or args.client

    return (server, port, client)

def setupLogging(logfiles, verbosity):
    global logger

    # Define a couple custom logging levels
    logging.STATS = logging.INFO + 1
    logging.DIRS  = logging.INFO - 1
    logging.FILES = logging.INFO - 2
    logging.MSGS  = logging.INFO - 3
    logging.addLevelName(logging.STATS, "STAT")
    logging.addLevelName(logging.FILES, "FILE")
    logging.addLevelName(logging.DIRS,  "DIR")
    logging.addLevelName(logging.MSGS,  "MSG")

    levels = [logging.STATS, logging.DIRS, logging.FILES, logging.MSGS, logging.DEBUG] #, logging.TRACE]

    formatter = MessageOnlyFormatter(levels=[logging.INFO, logging.FILES, logging.DIRS, logging.STATS])

    if len(logfiles) == 0:
        logfiles.append(sys.stderr)
    for logfile in logfiles:
        if type(logfile) is str:
            if logfile == ':STDERR:':
                handler = logging.StreamHandler(sys.stderr)
            elif logfile == ':STDOUT:':
                handler = logging.StreamHandler(sys.stdout)
            else:
                handler = logging.handlers.WatchedFileHandler(Util.fullPath(logfile))
        else:
            handler = logging.StreamHandler(logfile)

        handler.setFormatter(formatter)
        logging.root.addHandler(handler)

    # Default logger
    logger = logging.getLogger('')
    # Pick a level.  Lowest specified level if verbosity is too large.
    loglevel = levels[verbosity] if verbosity < len(levels) else levels[-1]
    logger.setLevel(loglevel)

    # Create a special logger just for messages
    return logger

def printStats(starttime, endtime):
    connstats = conn.getStats()

    duration = endtime - starttime
    duration = datetime.timedelta(duration.days, duration.seconds, duration.seconds - (duration.seconds % 100000))          # Truncate the microseconds

    logger.log(logging.STATS, "Runtime:     {}".format(duration))
    logger.log(logging.STATS, "Backed Up:   Dirs: {:,}  Files: {:,}  Links: {:,}  Total Size: {:}".format(stats['dirs'], stats['files'], stats['links'], Util.fmtSize(stats['backed'])))
    logger.log(logging.STATS, "Files Sent:  Full: {:,}  Deltas: {:,}".format(stats['new'], stats['delta']))
    logger.log(logging.STATS, "Data Sent:   Sent: {:}   Backed: {:}".format(Util.fmtSize(stats['dataSent']), Util.fmtSize(stats['dataBacked'])))
    logger.log(logging.STATS, "Messages:    Sent: {:,} ({:}) Received: {:,} ({:})".format(connstats['messagesSent'], Util.fmtSize(connstats['bytesSent']), connstats['messagesRecvd'], Util.fmtSize(connstats['bytesRecvd'])))
    logger.log(logging.STATS, "Data Sent:   {:}".format(Util.fmtSize(stats['dataSent'])))


def printReport():
    lastDir = ''
    length = 0
    logger.log(logging.STATS, "")
    if report:
        length = reduce(max, map(len, map(lambda x:x[0], report)))
        length = max(length, 50)
        fmts = ['','KB','MB','GB', 'TB', 'PB']
        fmt  = '%-{}s %-6s %-10s %-10s'.format(length + 2)
        fmt2 = '  %-{}s %-6s %-10s %-10s'.format(length)
        fmt3 = '  %-{}s %-6s %-10s'.format(length)
        logger.log(logging.STATS, fmt, "FileName", "Type", "Size", "Sig Size")
        logger.log(logging.STATS, fmt, '-' * (length + 2), '-' * 6, '-' * 10, '-' * 10)
        for i in sorted(report):
            r = report[i]
            (d, f) = i
            if d != lastDir:
                logger.log(logging.STATS, "%s:", Util.shortPath(d, 80))
                lastDir = d
            if r['sigsize']:
                logger.log(logging.STATS, fmt2, f, r['type'], Util.fmtSize(r['size'], formats=fmts), Util.fmtSize(r['sigsize'], formats=fmts))
            else:
                logger.log(logging.STATS, fmt3, f, r['type'], Util.fmtSize(r['size'], formats=fmts))
    else:
        logger.log(logging.STATS, "No files backed up")

def lockRun(server, port, client):
    lockName = 'tardis_' + str(server) + '_' + str(port) + '_' + str(client)

    # Create our own pidfile path.  We do this in /tmp rather than /var/run as tardis may not be run by
    # the superuser (ie, can't write to /var/run)
    pidfile = pid.PidFile(piddir=tempfile.gettempdir(), pidname=lockName)

    try:
        pidfile.create()
    except pid.PidFileError as e:
        raise Exception("Tardis already running: %s", e)
    return pidfile

def main():
    global starttime, args, config, conn, verbosity, crypt, noCompTypes, srpUsr
    # Read the command line arguments.
    (args, config) = processCommandLine()

    # Memory debugging.
    # Enable only if you really need it.
    #from dowser import launch_memory_usage_server
    #launch_memory_usage_server()

    # Set up logging
    verbosity=args.verbose if args.verbose else 0
    setupLogging(args.logfiles, verbosity)

    starttime = datetime.datetime.now()
    subserver = None

    if args.progress:
        initProgressBar()

    try:
        # Get the actual names we're going to use
        (server, port, client) = parseServerInfo(args)

        if args.exclusive:
            lockRun(server, port, client)

        # Figure out the name and the priority of this backupset
        (name, priority, auto) = setBackupName(args)

        # Load the excludes
        loadExcludes(args)

        # Load any excluded directories
        loadExcludedDirs(args)

        # Error check the purge parameter.  Disable it if need be
        #if args.purge and not (purgeTime is not None or auto):
        #   logger.error("Must specify purge days with this option set")
        #   args.purge=False

        # Load any password info
        try:
            password = Util.getPassword(args.password, args.passwordfile, args.passwordprog, prompt="Password for %s: " % (client))
        except Exception as e:
            logger.critical("Could not retrieve password.")
            sys.exit(1)
        # Purge out the original password.  Maybe it might go away.
        if args.password:
            args.password = '-- removed --'

        if password:
            srpUsr = srp.User(args.client, password)
            crypt = TardisCrypto.TardisCrypto(password, client)

        # If no compression types are specified, load the list
        types = []
        for i in args.nocompressfile:
            try:
                logger.debug("Reading types to ignore from: %s", i)
                data = map(Util.stripComments, file(i, 'r').readlines())
                types = types + [x for x in data if len(x)]
            except Exception as e:
                logger.error("Could not load nocompress types list from: %s", i)
                raise e
        types = types + args.nocompress
        noCompTypes = set(types)
        logger.debug("Types to ignore: %s", sorted(noCompTypes))

        # Calculate the base directories
        directories = list(itertools.chain.from_iterable(map(glob.glob, map(Util.fullPath, args.directories))))
        if args.basepath == 'common':
            rootdir = os.path.commonprefix(directories)
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
                name = os.path.split(i)[1]
                if name in names:
                    logger.error("%s directory name (%s) is not unique.  Collides with %s", i, name, names[name])
                    errors = True
                else:
                    names[name] = i
            if errors:
                raise Exception('All paths must have a unique final directory name if basepath is none')
            rootdir = None
        logger.debug("Rootdir is: %s", rootdir)
    except Exception as e:
        logger.critical("Unable to initialize: %s", (str(e)))
        if args.exceptions:
            logger.exception(e)
        sys.exit(1)

    # Open the connection

    # If we're using a local connection, create the domain socket, and start the server running.
    if args.local:
        tempsocket = os.path.join(tempfile.gettempdir(), "tardis_local_" + str(os.getpid()))
        port = tempsocket
        server = None
        subserver = runServer(args.serverprog, tempsocket)
        if subserver is None:
            logger.critical("Unable to create server")
            sys.exit(1)

    # Get the connection object
    try:
        conn = getConnection(server, port)
        startBackup(name, args.priority, args.client, auto, args.force, args.full)
    except Exception as e:
        logger.critical("Unable to start session with %s:%s: %s", server, port, str(e))
        if args.exceptions:
            logger.exception(e)
        sys.exit(1)

    if verbosity or args.stats or args.report:
        logger.log(logging.STATS, "Name: {} Server: {}:{} Session: {}".format(backupName, server, port, sessionid))

    # Set up the encryption, if needed.
    if args.crypt and crypt:
        (f, c) = (None, None)

        if newBackup == 'NEW':
            # if new DB, generate new keys, and save them appropriately.
            logger.debug("Generating new keys")
            crypt.genKeys()
            if args.keys:
                (f, c) = crypt.getKeys()
                Util.saveKeys(Util.fullPath(args.keys), clientid, f, c)
            else:
                sendKeys(password, client)
        else:
            # Otherwise, load the keys from the appropriate place
            if args.keys:
                (f, c) = Util.loadKeys(args.keys, clientid)
            else:
                f = filenameKey
                c = contentKey
            if not (f and c):
                logger.critical("Unable to load keyfile: %s", args.keys)
                sys.exit(1)
            crypt.setKeys(f, c)

    # Send the command line, if so desired.
    if args.sendconfig:
        a = vars(args)
        a['directories'] = directories
        if a['password']:
            a['password'] = '-- removed --'
        jsonArgs = json.dumps(a, cls=Util.ArgJsonEncoder, sort_keys=True)
        message = {
            "message": "CLICONFIG",
            "args":    jsonArgs
        }
        batchMessage(message)

    # Now, do the actual work here.
    try:
        # Now, process all the actual directories
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
                f = mkFileInfo(root, name)
                sendDirEntry(0, 0, [f])
            # And run the directory
            recurseTree(directory, root, depth=args.maxdepth, excludes=globalExcludes)

        # If any metadata, clone or batch requests still lying around, send them now
        if newmeta:
            batchMessage(makeMetaMessage())
        flushClones()
        while flushBatchMsgs():
            pass

        # Send a purge command, if requested.
        if args.purge:
            if args.purgetime:
                sendPurge(False)
            else:
                sendPurge(True)
        conn.close()
    except KeyboardInterrupt as e:
        logger.warning("Backup Interupted")
        if args.exceptions:
            logger.exception(e)
    except Exception as e:
        logger.error("Caught exception: %s, %s", e.__class__.__name__, e)
        if args.exceptions:
            logger.exception(e)

    if args.progress:
        print ' ' +  _startOfLine + _ansiClearEol + _startOfLine,

    if args.local:
        logger.info("Waiting for server to complete")
        subserver.wait()        # Should I do communicate?

    endtime = datetime.datetime.now()

    if args.sanity:
        # Sanity checks.  Enable for debugging.
        if len(cloneContents) != 0:
            logger.warning("Warning: Some cloned directories not processed: %d", len(cloneContents))
            for key in cloneContents:
                (path, files) = cloneContents[key]
                print "{}:: {}".format(path, len(files))

        # This next one is usually non-zero, for some reason.  Enable to debug.
        if len(inodeDB) != 0:
            logger.warning("Warning: %d InodeDB entries not processed", len(inodeDB))
            for key in inodeDB.keys():
                (_, path) = inodeDB[key]
                print "{}:: {}".format(key, path)

    # Print stats and files report
    if args.stats:
        printStats(starttime, endtime)
    if args.report:
        printReport()

    if args.local:
        os.unlink(tempsocket)

if __name__ == '__main__':
    sys.exit(main())
