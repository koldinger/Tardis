# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2024, Eric Koldinger, All Rights Reserved.
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
import logging
import argparse
import configparser
import sys
import subprocess
import shlex
import getpass
import stat
import fnmatch
import json
import base64
import functools
import pwd
import grp
import time
import struct
import io
import signal

import urllib.request
import urllib.parse
import urllib.error

import srp
import passwordmeter
import colorlog
import parsedatetime

from icecream import ic

from . import Connection
from . import CompressedBuffer
from . import Defaults
from . import TardisDB
from . import TardisCrypto
from . import CacheDir
from . import RemoteDB

try:
    import genzshcomp
except ImportError:
    genzshcomp = None


logger = logging.getLogger('UTIL')

def fmtSize(num, base=1024, suffixes=None):
    if suffixes is None:
        suffixes = ['bytes','KB','MB','GB', 'TB', 'PB', 'EB']
    fmt = "%d %s"
    if num is None:
        return 'None'
    num = float(num)
    for x in suffixes[:-1]:
        #if num < base and num > -base:
        if -base < num < base:
            return (fmt % (num, x)).strip()
        num /= float(base)
        fmt = "%3.1f %s"
    return (fmt % (num, suffixes[-1])).strip()

def getIntOrNone(config, section, name):
    try:
        x = config.get(section, name)
        return int(x, 0)
    except Exception:
        return None

@functools.cache
def getGroupName(gid):
    group = grp.getgrgid(gid)
    if group:
        return group.gr_name
    return None

@functools.cache
def getUserId(uid):
    user = pwd.getpwuid(uid)
    if user:
        return user.pw_name
    return None

# Format time.  If we're less that a year before now, print the time as Jan 12, 02:17, if earlier,
# then Jan 12, 2014.  Same as ls.
_now = time.time()
_yearago = _now - (365 * 24 * 3600)
def formatTime(then):
    if then > _yearago:
        fmt = '%b %d %H:%M'
    else:
        fmt = '%b %d, %Y'
    return time.strftime(fmt, time.localtime(then))

# Strip comments from input lines.
def stripComments(line):
    return line.partition('#')[0].strip()

# Convert a string to an integer
def parseInt(x):
    if x.startswith('0x'):
        return int(x[2:], 16)
    if x.startswith('0o'):
        return int(x[2:], 8)
    if x.startswith('0'):
        return int(x[1:], 8)
    return int(x)

# Make a path look short.
def shortPath(path, width=80):
    """
    Compress a path to only show the last elements if it's wider than specified.
    Replaces early elements with ".../"
    """

    # If we're already short enough, just return what we have
    if not path or len(path) < width:
        return path

    # Compensate for a coming .../ plus slosh
    width -= 5

    # split into path prefix, + the current file
    path, retPath = os.path.split(path)

    # Check to see if we're already wider than width.....
    # If so, put a "..." in the middle of the filename
    # retPath is the current file at this point
    if len(retPath) > width:
        namecomps = retPath.rsplit('.', 1)
        #print("Name Comps:: ",  namecomps)
        if len(namecomps) == 2:
            main, suffix = namecomps
        else:
            main = namecomps[0]
            suffix = ''
        #print("Split:: ", main, suffix)
        length = min(len(retPath), width) - 5
        retPath   = main[0:(length // 2) - 1] + "..." + main[-(length // 2) + 1:]
        if suffix:
            retPath = '.'.join([retPath, suffix])

    #print("First chunk:: ", len(retPath), retPath)

    # Build it up backwards from the end
    while len(retPath) < width:
        path, tail = os.path.split(path)
        #print(retPath, len(retPath), path, tail)
        if not path or not tail:
            break
        if len(tail) + len(os.sep) + len(retPath) > width:
            break
        retPath = os.path.join(tail, retPath)

    return "..." + os.sep + retPath

def accumulateStat(stats, name, amount=1):
    if stats:
        stats[name] = stats.setdefault(name, 0) + amount

def setupLogging(verbosity=1, levels=None, fmt=None, stream=sys.stdout):
    if levels is None:
        levels = [logging.WARNING, logging.INFO, logging.DEBUG]

    loglevel = levels[verbosity] if verbosity < len(levels) else logging.DEBUG

    if fmt is None:
        if loglevel <= logging.DEBUG:
            fmt = "%(log_color)s%(levelname)s%(reset)s : %(filename)s:%(lineno)d: %(message)s"
        else:
            fmt = "%(log_color)s%(levelname)s%(reset)s : %(message)s"

    colors = colorlog.default_log_colors.copy()
    colors.update({ 'DEBUG': 'green' })

    formatter = colorlog.TTYColoredFormatter(fmt, log_colors=colors, stream=stream)
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logging.root.addHandler(handler)

    logging.raiseExceptions = False

    logger = logging.getLogger("")
    logger.setLevel(loglevel)
    return logger

# Functions for reducing a path.

def findDirInRoot(tardis, bset, path, crypt=None):
    #logger = logging.getLogger('UTIL')
    """
    Find a directory which exists in the root directory
    Return the number of components which must be removed to have a directory in
    the root of the tree.
    """
    comps = path.split(os.sep)
    comps.pop(0)
    for i in range(0, len(comps)):
        name = comps[i]
        #logger.debug("Looking for root directory %s (%d)", name, i)
        if crypt:
            name = crypt.encryptFilename(name)
        info = tardis.getFileInfoByName(name, (0, 0), bset)
        if info and info['dir'] == 1:
            return i
    return None

def reducePath(tardis, bset, path, reduceBy, crypt=None):
    #logger = logging.getLogger('UTIL')
    """
    Reduce a path by a specified number of directory levels.
    If the number is sys.maxint, perform a "smart" reduction, by looking for a directory
    element which occurs in the root directory.
    """
    #logger.debug("Computing path for %s in %d (%d)", path, bset, reduce)
    if reduceBy == sys.maxsize:
        reduceBy = findDirInRoot(tardis, bset, path, crypt)
    if reduceBy:
        #logger.debug("Reducing path by %d entries: %s", reduceBy, path)
        comps = path.split(os.sep)
        if reduceBy > len(comps):
            #logger.error("Path reduction value (%d) greater than path length (%d) for %s.  Skipping.", reduceBy, len(comps), path)
            return None
        tmp = os.path.join(os.sep, *comps[reduceBy + 1:])
        #logger.info("reduced path %s to %s", path, tmp)
        path = tmp
    return path

def isMagic(path):
    if ('*' in path) or ('?' in path) or ('[' in path):
        return True
    return False

def matchPath(pattern, path):
    if pattern == path:
        return True
    pats = pattern.split(os.sep)
    dirs = path.split(os.sep)
    inWild = False
    while len(pats) != 0 and len(dirs) != 0:
        if not inWild:
            p = pats.pop(0)
            d = dirs.pop(0)
            if p == '**':
                inWild = True
            else:
                if not fnmatch.fnmatch(d, p):
                    return False
        else:
            d = dirs.pop(0)
            p = pats[0]
            if p != '**':
                if fnmatch.fnmatch(d, p):
                    inWild = False
                    pats.pop(0)
            else:
                pats.pop(0)

    if len(pats) or len(dirs):
        return False
    return True

def fullPath(name):
    return os.path.realpath(os.path.expanduser(os.path.expandvars(name)))


"""
Retrieve a password.
Either takes a URL, a program name, a plain password string.
Only one can be valid.
Retrieves from the URL, program, or file if so specified.
If a string is passed in, returns it.
If the string is True or empty (''), it will use the getpass function to prompt on the
terminal.
"""
def _readWithTimeout(prompt, timeout):
    def _interuptPassword(signum, frame):
        print("\nTimeout")
        raise Exception("Password read timedout")

    previous = signal.signal(signal.SIGALRM, _interuptPassword)
    try:
        if timeout:
            signal.alarm(timeout)
        password = getpass.getpass(prompt=prompt)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    return password.rstrip()

def getPassword(password, pwurl, pwprog, prompt='Password: ', allowNone=True, confirm=False, strength=False, timeout=Defaults.getDefault('TARDIS_PWTIMEOUT')):
    ic("GetPassword")
    methods = 0
    if password: methods += 1
    if pwurl:    methods += 1
    if pwprog:   methods += 1

    ic(methods)

    if methods > 1:
        raise Exception("Cannot specify more than one password retrieval mechanism")

    if methods == 0 and not allowNone:
        # Nothing specified, and it wants a value.  Set password to True to fetch
        password = True

    ic(password)

    if password is True or password == '':
        password = _readWithTimeout(prompt, int(timeout))
        password = password.rstrip()       # Delete trailing characters
        if confirm:
            pw2 = _readWithTimeout("Confirm password:", int(timeout))
            if password != pw2:
                raise Exception("Passwords don't match")

    if pwurl:
        loc = urllib.parse.urlunparse(urllib.parse.urlparse(pwurl, scheme='file'))
        pwf = urllib.request.urlopen(loc)
        password = pwf.readline().rstrip().decode('utf8')
        pwf.close()

    if pwprog:
        a = shlex.split(pwprog)
        output = subprocess.check_output(a)
        password = output.split('\n')[0].rstrip()

    ic(password)

    if not allowNone and not password:
        raise Exception("Password required")

    if strength and password:
        if not checkPasswordStrength(password):
            raise Exception("Password not strong enough")

    return password


def checkPasswordStrength(password):
    pwStrMin     = float(Defaults.getDefault('TARDIS_PW_STRENGTH'))
    strength, improvements = passwordmeter.test(password)
    if strength < pwStrMin:
        logger.error("Password too weak: %f (%f required)", strength, pwStrMin)
        for i in improvements:
            logger.error("    %s", improvements[i])
        return False
    return True

# Get the database, cachedir, and crypto object.

def setupDataConnection(dataLoc, client, password, keyFile, dbName, dbLoc=None, allow_upgrade=False, retpassword=False):
    """ Setup a data connection to a client.   Determines the correct way to connect, either via direct filesystem,
    or via TardisRemote (http).
    Returns a 3-tuple, the TardisDB object, the CacheDir object, and the appropriate crypto object
    """
    logger.debug("Connection requested for %s under %s", client, dataLoc)
    crypt = None

    loc = urllib.parse.urlparse(dataLoc)
    if loc.scheme in ['http', 'https']:
        logger.debug("Creating remote connection to %s", dataLoc)
        # If no port specified, insert the port
        if loc.port is None:
            netloc = loc.netloc + ":" + Defaults.getDefault('TARDIS_REMOTE_PORT')
            dbLoc = urllib.parse.urlunparse((loc.scheme, netloc, loc.path, loc.params, loc.query, loc.fragment))
        else:
            dbLoc = dataLoc
        # get the RemoteURL object
        logger.debug("==> %s %s", dbLoc, client)
        tardis = RemoteDB.RemoteDB(dbLoc, client)
        cache = tardis
    else:
        logger.debug("Creating direct connection to %s", dataLoc)
        cacheDir = os.path.join(loc.path, client)
        cache = CacheDir.CacheDir(cacheDir, create=False)
        if not dbLoc:
            dbDir = cacheDir
        else:
            dbDir = os.path.join(dbLoc, client)
        dbPath = os.path.join(dbDir, dbName)
        tardis = TardisDB.TardisDB(dbPath, allow_upgrade=allow_upgrade)

    needsAuth = tardis.needsAuthentication()
    if needsAuth and password is None:
        password = getPassword(True, None, None, f"Password for {client}: ", allowNone=False)

    if needsAuth:
        authenticate(tardis, client, password)
    elif password:
        raise TardisDB.AuthenticationFailed()

    # Password specified, so create the crypto unit
    #cryptoScheme = tardis.getConfigValue('CryptoScheme', '1')
    cryptoScheme = tardis.getCryptoScheme()

    crypt = TardisCrypto.getCrypto(cryptoScheme, password, client)
    if keyFile:
        (f, c) = loadKeys(keyFile, tardis.getConfigValue('ClientID'))
    else:
        (f, c) = tardis.getKeys()
    crypt.setKeys(f, c)

    if retpassword:
        return (tardis, cache, crypt, password)
    return (tardis, cache, crypt)

# Perform SRP authentication locally against the DB
def authenticate(db, client, password):
    usr      = srp.User(client, password)
    uname, A = usr.start_authentication()

    s, B = db.authenticate1(uname, A)

    M = usr.process_challenge(s, B)

    if M is None:
        raise TardisDB.AuthenticationFailed()

    HAMK = db.authenticate2(M)

    usr.verify_session(HAMK)

    if not usr.authenticated():
        raise TardisDB.AuthenticationFailed()


def getBackupSet(db, bset):
    bsetInfo = None
    # First, try as an integer
    try:
        bset = int(bset)
        bsetInfo = db.getBackupSetInfoById(bset)
    except ValueError:
        # Else, let's look it up based on name
        if bset == Defaults.getDefault('TARDIS_RECENT_SET') or bset == '' or bset is None:
            bsetInfo = db.lastBackupSet()
        else:
            bsetInfo = db.getBackupSetInfo(bset)
            if not bsetInfo:
                bsetInfo = db.getBackupSetInfoByTag(bset)
        if not bsetInfo:
            # still nothing, hm, let's try a date format
            cal = parsedatetime.Calendar()
            (then, success) = cal.parse(bset)
            if success:
                timestamp = time.mktime(then)
                logger.debug("Using time: %s", time.asctime(then))
                bsetInfo = db.getBackupSetInfoForTime(timestamp)
                if bsetInfo and bsetInfo['backupset'] != 1:
                    bset = bsetInfo['backupset']
                    logger.debug("Using backupset: %s %d for %s", bsetInfo['name'], bsetInfo['backupset'], bset)
                else:
                    # Weed out the ".Initial" set
                    logger.critical("No backupset at date: %s (%s)", bset, time.asctime(then))
                    bsetInfo = None
            else:
                logger.critical("Could not parse string: %s", bset)
    return bsetInfo

# Data manipulation functions

_suffixes = [".basis", ".sig", ".meta", ""]
def _removeOrphans(db, cache):
    #logger = logging.getLogger('UTIL')

    size = 0
    count = 0
    # Get a list of orphan'd files
    orphans = db.listOrphanChecksums(isFile=True)
    for cksum in orphans:
        logger.debug("Removing %s", cksum)
        # And remove them each....
        try:
            s = cache.size(cksum)
            if s:
                size += s
                count += 1

            sig = cksum + ".sig"
            size += cache.size(sig)

            cache.removeSuffixes(cksum, _suffixes)

            db.deleteChecksum(cksum)
        except OSError:
            logger.warning("No checksum file for checksum %s", cksum)
    return count, size

def removeOrphans(db, cache):
    count = 0
    size = 0
    rounds = 0
    # Repeatedly prune the file trees until there are no more checksums
    # we have to do this, as there can be multiple levels of basis files, each dependant on the one above (below?)
    # Theoretically we should be able to do this is one go, but SQLite's implementation of recursive queries doesn't
    # seem to work quite right.
    while True:
        (lCount, lSize) = _removeOrphans(db, cache)
        if lCount == 0:
            break
        rounds += 1
        count  += lCount
        size   += lSize

    db.deleteOrphanChecksums(False)
    return count, size, rounds

# Data transmission functions

def _chunks(stream, chunksize):
    last = b''
    for chunk in iter(functools.partial(stream.read, chunksize), b''):
        if last:
            yield (last, False)
        last = chunk
    yield (last, True)

_transmissionTime = 0

def sendDataPlain(sender, data, chunksize=(16 * 1024), compress=None, stats=None, log=None):
    """
    Send data, with no encryption, or calculation
    """
    encrypt = TardisCrypto.NullEncryptor()
    sendData(sender, data, encrypt, chunksize=chunksize, compress=compress, stats=stats, log=log)

def sendData(sender, data, encrypt, chunksize=(16 * 1024), hasher=None, compress=None, stats=None, signature=False, progress=None, progressPeriod=8*1024*1024, log=None):
    """
    Send a block of data, optionally encrypt and/or compress it before sending
    Compress should be either None, for no compression, or one of the known compression types (zlib, bzip, lzma)
    """
    #logger = logging.getLogger('Data')
    if isinstance(sender, Connection.Connection):
        sender = sender.sender
    size = 0
    status = "OK"
    ck = None
    sig = None

    start = time.time()
    if progress:
        # Set the chunksize
        if progressPeriod % chunksize != 0:
            progressPeriod -= progressPeriod % chunksize

    if compress:
        stream = CompressedBuffer.CompressedBufferedReader(data, hasher=hasher, signature=signature, compressor=compress)
    else:
        stream = CompressedBuffer.BufferedReader(data, hasher=hasher, signature=signature)

    try:
        if encrypt.iv:
            sender.sendMessage(encrypt.iv, raw=True)
            accumulateStat(stats, 'dataSent', len(encrypt.iv))
        for chunk, eof in _chunks(stream, chunksize):
            #print len(chunk), eof
            if chunk:
                data = encrypt.encrypt(chunk)
            else:
                data = b''
            if eof:
                data += encrypt.finish()
            #chunkMessage = { "chunk" : num, "data": data }
            if data:
                sender.sendMessage(data, raw=True)
                accumulateStat(stats, 'dataSent', len(data))
                size += len(data)
                if progress:
                    if (size % progressPeriod) == 0:
                        progress()

            #num += 1
        digest = encrypt.digest()
        if digest:
            sender.sendMessage(digest, raw=True)
            accumulateStat(stats, 'dataSent', len(digest))

    except Exception as e:
        status = "Fail"
        #logger = logging.getLogger('Data')
        #logger.exception(e)
        raise e
    finally:
        sender.sendMessage(b'', raw=True)
        compressed = compress if stream.isCompressed() else "None"
        size = stream.size()

        accumulateStat(stats, 'dataBacked', size)

        message = { "chunk": "done", "size": size, "status": status, "compressed": compressed }
        if hasher:
            ck = stream.checksum()
            message["checksum"] = ck
        if signature:
            sig = stream.signatureFile()
        #print message
        sender.sendMessage(message)
        stream = None
        end = time.time()
        global _transmissionTime
        _transmissionTime += end - start
        if log:
            log.write("Sent %d bytes\n" % size)
    return size, ck, sig

def receiveData(receiver, output, log=None):
    """ Receive a block of data from the sender, and store it in the specified file.
    Collect some info sent, and return it.
    """
    # logger = logging.getLogger('Data')
    if isinstance(receiver, Connection.Connection):
        receiver = receiver.sender
    bytesReceived = 0
    checksum = None
    compressed = False
    while True:
        chunk = receiver.recvMessage(raw=True)
        #print chunk
        # logger.debug("Chunk: %s", str(chunk))
        if len(chunk) == 0:
            break
        data = receiver.decode(chunk)
        if output:
            output.write(data)
            output.flush()
        bytesReceived += len(data)

    chunk = receiver.recvMessage()
    status = chunk['status']
    size   = chunk['size']
    if 'checksum' in chunk:
        checksum = chunk['checksum']
    if 'compressed' in chunk:
        compressed = chunk['compressed']
    if log:
        log.write("Received %d bytes\n" % size)
    return (bytesReceived, status, size, checksum, compressed)


# Function to determine whether we can execute a function
_uidForPerm = os.getuid()
_groupForPerm = os.getgroups()

def checkPermission(pUid, pGid, mode, uid=_uidForPerm, groups=_groupForPerm):
    # Check for super user.   Hack, this isn't really right, but still.
    # Assumes *nix permission system.   May not work on Windows or Mac.
    if uid == 0:
        return True
    if stat.S_ISDIR(mode):
        if (uid == pUid) and (stat.S_IRUSR & mode) and (stat.S_IXUSR & mode):
            return True
        if (pGid in groups) and (stat.S_IRGRP & mode) and (stat.S_IXGRP & mode):
            return True
        if (stat.S_IROTH & mode) and (stat.S_IXOTH & mode):
            return True
    else:
        if (uid == pUid) and (stat.S_IRUSR & mode):
            return True
        if (pGid in groups) and (stat.S_IRGRP & mode):
            return True
        if stat.S_IROTH & mode:
            return True
    return False

"""
Load a key file.
Key files are config databases, where each section is keyed by the clientID from the server.  Each secition needs to contain two entries, a ContentKey
and a FilenameKey, both of which are base64 encoded strings containing the encyrpted keys.
"""
def _updateLen(value, length):
    if not value:
        return None

    res = base64.b64decode(value)
    if len(res) != length:
        if len(res) > length:
            res = base64.b64encode(res[0:length])
        else:
            res = base64.b64encode(res + '\0' * (length - len(res)))
    else:
        res = value
    return res

def loadKeys(name, client):
    config = configparser.ConfigParser({'ContentKey': None, 'FilenameKey': None}, allow_no_value=True)
    client = str(client)
    config.add_section(client)
    config.read(fullPath(name))
    try:
        contentKey =  _updateLen(config.get(client, 'ContentKey'), 32)
        nameKey    =  _updateLen(config.get(client, 'FilenameKey'), 32)
        return (nameKey, contentKey)
    except configparser.NoOptionError:
        raise Exception("No keys available for client " + client)

def saveKeys(name, client, nameKey, contentKey, srpSalt=None, srpVKey=None):
    def _addOrDelete(config, client, key, value):
        if value:
            config.set(client, key, value)
        else:
            config.remove_option(client, key)

    config = configparser.ConfigParser()
    config.add_section(client)
    config.read(name)

    _addOrDelete(config, client, 'ContentKey', contentKey)
    _addOrDelete(config, client, 'FilenameKey', nameKey)
    _addOrDelete(config, client, 'SRPSalt', srpSalt)
    _addOrDelete(config, client, 'SRPVkey', srpVKey)

    with open(name, 'w') as configfile:
        config.write(configfile)

def mkKeyString(client, nameKey, contentKey):
    config = configparser.ConfigParser()
    config.add_section(client)
    config.set(client, 'ContentKey', contentKey)
    config.set(client, 'FilenameKey', nameKey)
    x = io.StringIO()
    config.write(x)
    return x.getvalue()

###
### Create a metadata file for file.
###
def recordMetaData(cache, checksum, size, compressed, encrypted, disksize, basis=None, logger=None):
    f = None
    metaName = checksum + '.meta'
    metaData = {'checksum': checksum, 'compressed': bool(compressed), 'encrypted': bool(encrypted), 'size': size, 'disksize': disksize }
    if basis:
        metaData['basis'] = basis
    metaStr = json.dumps(metaData)
    logger.debug("Storing metadata for %s: %s", checksum, metaStr)

    try:
        f = cache.open(metaName, 'w')
        f.write(metaStr)
        f.write('\n')
        f.close()
    except Exception as e:
        logger.warning("Could not write metadata file for %s: %s: %s", checksum, metaName, str(e))


class StoreBoolean(argparse.Action):
    """
    Class to handle options of the form "--[no]argument" where you can specify --noargument to store a False,
    or --argument to store a true.
    """
    def __init__(self, option_strings, dest, negate="no", nargs=0, **kwargs):
        if nargs != 0:
            raise ValueError("nargs not allowed")
        #if len(option_strings) > 1:
        #    raise ValueError("Multiple option strings not allowed")
        self.negative_option = "--" + negate + option_strings[0][2:]
        self.help_option = "--[" + negate + "]" + option_strings[0][2:]
        option_strings.append(self.negative_option)
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, arguments, values, option_string=None):
        #print "Here: ", option_string, " :: ", self.option_strings
        if option_string == self.negative_option:
            value = False
        else:
            value = True
        setattr(arguments, self.dest, value)


class Toggle(argparse.Action):
    """
    Class to handle toggling options.  -x = true -xx = false -xxx = true, etc
    """
    def __init__(self,
                 option_strings,
                 dest,
                 default=None,
                 required=False,
                 help=None):
        super().__init__(
            option_strings=option_strings,
            dest=dest,
            nargs=0,
            default=default,
            required=required,
            help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        new_value = not argparse._ensure_value(namespace, self.dest, False)
        setattr(namespace, self.dest, new_value)

class GenShellCompletions(argparse.Action):
    """
    Class to generate arguments and exit
    """
    def __call__(self, parser, namespace, values, option_string=None):
        path = os.path.split(sys.argv[0])[1]
        c = genzshcomp.CompletionGenerator(path, parser, parser_type='argparse', output_format=values)
        print(c.get())
        sys.exit(0)

def addGenCompletions(parser):
    if genzshcomp:
        parser.add_argument('--gencompletions',  dest='gencomps',    default=None, const='zsh', nargs='?', choices=['bash', 'zsh', 'list'], help=argparse.SUPPRESS, action=GenShellCompletions)

# Help formatter to handle the StoreBoolean options.
# Only handles overriding the basic HelpFormatter class.

class HelpFormatter(argparse.RawTextHelpFormatter):
    def _format_action_invocation(self, action):
        #print "_format_action_invocation", str(action)
        if hasattr(action, 'help_option'):
            ret = action.help_option
        else:
            ret = super()._format_action_invocation(action)
        #print "Got ", ret
        return ret

# Argument formatter.  Useful for converting our command line arguments into strings"

class ArgJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, io.IOBase):
            if obj == sys.stderr:
                return "<stderr>"
            if obj == sys.stdout:
                return "<stdout>"
            return "<file>"
        return json.JSONEncoder()

# Stream Handler which will always clear the line before printing
class ClearingStreamHandler(logging.StreamHandler):
    clearLines = False

    def __init__(self, stream = None):
        super().__init__(stream)
        if stream is None:
            stream = sys.stderr
        self.clearLines = os.isatty(stream.fileno())

    def emit(self, record):
        _ansiClearEol = '\x1b[K'

        if self.clearLines:
            self.stream.write(_ansiClearEol)

        super().emit(record)

# AN exception logging mechanism
class ExceptionLogger:
    def __init__(self, logger, logExceptions):
        self.logger = logger
        self.logExceptions = logExceptions

    def log(self, exception):
        if self.logExceptions:
            self.logger.exception(exception)



# Class to have a two directional dictionary.

class bidict(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.inverse = {}
        for key, value in self.items():
            self.inverse.setdefault(value,[]).append(key)

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.inverse.setdefault(value,[]).append(key)

    def __delitem__(self, key):
        self.inverse.setdefault(self[key],[]).remove(key)
        if self[key] in self.inverse and not self.inverse[self[key]]:
            del self.inverse[self[key]]
        super().__delitem__(key)

# Get a hash function.  Configurable.

_hashMagic = struct.pack("!I", 0xffeeddcc)

def hashDir(crypt, files, decrypt=False):
    """ Generate the hash of the filenames, and the number of files, so we can confirm that the contents are the same """
    if decrypt:
        f = list(files)
        #print map(crypt.decryptFilename, [x['name'] for x in f])
        filenames = sorted([crypt.decryptFilename(n) for n in [x['name'] for x in f]])
    else:
        filenames = sorted([x["name"] for x in files])

    m = crypt.getHash()
    # Insert "magic" number to help prevent collisions
    m.update(_hashMagic)
    # Insert a magic number
    # Generate a length, and convert it to a byte string
    z = struct.pack("!I", len(filenames))
    # Hash that
    m.update(z)
    for f in filenames:
        # For each entry, hash the name, and a null character
        m.update(bytes(f, 'utf8', 'xmlcharrefreplace'))
        m.update(b'\0')
    m.update(z)
    # Again, Insert "magic" number to help prevent collisions
    m.update(_hashMagic)
    return (m.hexdigest(), len(filenames))


def asString(a, policy='ignore'):
    if isinstance(a, str):
        return a
    if isinstance(a, bytes):
        return a.decode('utf-8', policy)
    return str(a)


# 'Test' code

if __name__ == "__main__":
    p = argparse.ArgumentParser(formatter_class=HelpFormatter)

    p.add_argument("--doit", action=StoreBoolean, help="Yo mama")
    p.add_argument("-x", action=Toggle, help="Whatever")

    args = p.parse_args()
    print(args)
