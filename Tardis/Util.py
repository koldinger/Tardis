# vim: set et sw=4 sts=4 fileencoding=utf-8:
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
import logging
import argparse
import ConfigParser
import sys
import subprocess
import hashlib
import shlex
import StringIO
import getpass
import stat
import fnmatch
import json
import base64
from functools import partial

import Messages
import Connection
import CompressedBuffer
import Tardis
import Defaults

import TardisDB
import TardisCrypto
import CacheDir
import RemoteDB

#import pycurl
import urlparse
import urllib

logger = logging.getLogger('UTIL')

def fmtSize(num, base=1024, formats = ['bytes','KB','MB','GB', 'TB', 'PB']):
    fmt = "%d %s"
    if num is None:
        return 'None'
    num = float(num)
    for x in formats:
        #if num < base and num > -base:
        if -base < num < base:
            return (fmt % (num, x)).strip()
        num /= float(base)
        fmt = "%3.1f %s"
    return (fmt % (num, 'EB')).strip()

def getIntOrNone(config, section, name):
    try:
        x = config.get(section, name)
        return int(x, 0)
    except:
        return None

def stripComments(line):
    return line.partition('#')[0].strip()

def shortPath(path, width=80):
    """
    Compress a path to only show the last elements if it's wider than specified.
    Replaces early elements with ".../"
    """
    if not path or len(path) < width:
        return path

    width -= 5
    path, retPath = os.path.split(path)

    # Check to see if we're already wider than width.....
    # If so, put a "..." in the middle of the filename
    if len(retPath) > width:
        namecomps = retPath.rsplit('.', 1)
        if len(namecomps) == 2:
            main, suffix = namecomps
        else:
            main = namecomps[0]
            suffix = ''
        length = len(main) - len(suffix) - 5
        length = min(length, width - 10)
        retPath   = main[0:length/2] + "..." + main[-(length/2):]
        if suffix:
            retPath = '.'.join([retPath, suffix])

    # Build it up backwards from the end
    while len(retPath) < width:
        path, tail = os.path.split(path)
        if len(tail) + len(retPath) > width:
            break
        else:
            retPath = os.path.join(tail, retPath)

    return "..." + os.sep + retPath


def accumulateStat(stats, stat, amount=1):
    if stats:
        stats[stat] = stats.setdefault(stat, 0) + amount

"""
Functions for reducing a path.
"""
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

def reducePath(tardis, bset, path, reduce, crypt=None):
    #logger = logging.getLogger('UTIL')
    """
    Reduce a path by a specified number of directory levels.
    If the number is sys.maxint, perform a "smart" reduction, by looking for a directory
    element which occurs in the root directory.
    """
    #logger.debug("Computing path for %s in %d (%d)", path, bset, reduce)
    if reduce == sys.maxint:
        reduce = findDirInRoot(tardis, bset, path, crypt)
    if reduce:
        #logger.debug("Reducing path by %d entries: %s", reduce, path)
        comps = path.split(os.sep)
        if reduce > len(comps):
            #logger.error("Path reduction value (%d) greater than path length (%d) for %s.  Skipping.", reduce, len(comps), path)
            return None
        tmp = os.path.join(os.sep, *comps[reduce + 1:])
        #logger.info("Reduced path %s to %s", path, tmp)
        path = tmp
    return path 

"""
"""

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
    while (len(pats) != 0 and len(dirs) != 0):
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
    else:
        return True

def fullPath(name):
    return os.path.realpath(os.path.expanduser(os.path.expandvars(name)))

"""
Filemode printer.  Translated from Perl's File::Strmode function (from cpan.org)
Not necessary in Python 3, but stat.filemode() doesn't exist in Python 2
"""
_fmtypes = { stat.S_IFDIR: 'd', stat.S_IFCHR: 'c', stat.S_IFBLK: 'b', stat.S_IFREG: '-', stat.S_IFLNK: 'l', stat.S_IFSOCK: 's', stat.S_IFIFO: 'p' }

def filemode(mode):
    str = _fmtypes.setdefault(stat.S_IFMT(mode), '?')
    str += 'r' if mode & stat.S_IRUSR else '-'
    str += 'w' if mode & stat.S_IWUSR else '-'
    if mode & stat.S_IXUSR:
        str += 's' if mode & stat.S_ISUID else 'x'
    else:
        str += 's' if mode & stat.S_ISUID else 'x'

    str += 'r' if mode & stat.S_IRGRP else '-'
    str += 'w' if mode & stat.S_IWGRP else '-'
    if mode & stat.S_IXGRP:
        str += 's' if mode & stat.S_ISGID else 'x'
    else:
        str += 's' if mode & stat.S_ISGID else 'x'

    str += 'r' if mode & stat.S_IROTH else '-'
    str += 'w' if mode & stat.S_IWOTH else '-'
    if mode & stat.S_IXOTH:
        str += 't' if mode & stat.S_ISVTX else 'x'
    else:
        str += 'T' if mode & stat.S_ISVTX else 'x'
    return str

def getTerminalSize():
    rows, columns = os.popen('stty size', 'r').read().split()
    return int(rows), int(columns)

"""
Retrieve a password.
Either takes a URL, a program name, a plain password string.
Only one can be valid.
Retrieves from the URL, program, or file if so specified.
If a string is passed in, returns it.
If the string is True or empty (''), it will use the getpass function to prompt on the
terminal.
"""
def getPassword(password, pwurl, pwprog, prompt='Password: ', allowNone=True):
    methods = 0
    if password: methods += 1
    if pwurl:    methods += 1
    if pwprog:   methods += 1

    if methods > 1:
        raise Exception("Cannot specify more than one password retrieval mechanism")

    if methods == 0 and not allowNone:
        # Nothing specified, and it wants a value.  Set password to True to fetch
        password = True

    if password == True or password == '':
        password = getpass.getpass(prompt=prompt)
        password.rstrip()       # Delete trailing characters

    if pwurl:
        pwf = urllib.urlopen(pwurl)
        password = pwf.readline().rstrip()
        pwf.close()

    if pwprog:
        args = shlex.split(pwprog)
        output = subprocess.check_output(args)
        password = output.split('\n')[0].rstrip()

    return password

"""
Get the database, cachedir, and crypto object.
"""
def setupDataConnection(dbLoc, client, password, keyFile, dbName):
    crypt = None
    if password:
        crypt = TardisCrypto.TardisCrypto(password, client)
    password = None
    token = None
    if crypt:
        token = crypt.createToken()

    loc = urlparse.urlparse(dbLoc)
    if (loc.scheme == 'http') or (loc.scheme == 'https'):
        # If no port specified, insert the port
        if loc.port is None:
            netloc = loc.netloc + ":" + Defaults.getDefault('TARDIS_REMOTE_PORT')
            dbLoc = urlparse.urlunparse((loc.scheme, netloc, loc.path, loc.params, loc.query, loc.fragment))
        # get the RemoteURL object
        tardis = RemoteDB.RemoteDB(dbLoc, client, token=token)
        cache = tardis
    else:
        baseDir = os.path.join(loc.path, client)
        cache = CacheDir.CacheDir(baseDir, create=False)
        dbPath = os.path.join(baseDir, dbName)
        tardis = TardisDB.TardisDB(dbPath, token=token)

    if crypt:
        if keyFile:
            (f, c) = loadKeys(keyFile, tardis.getConfigValue('ClientID'))
        else:
            (f, c) = tardis.getKeys()
        crypt.setKeys(f, c)

    return (tardis, cache, crypt)

"""
Data manipulation functions
"""
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
        except OSError as e:
            logger.warning("No checksum file for checksum %s", c)
            pass            # Do something better here.
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

"""
Data transmission functions
"""

def _chunks(stream, chunksize):
    last = ''
    for chunk in iter(partial(stream.read, chunksize), ''):
        if last:
            yield (last, False)
        last = chunk
    yield (last, True)

def sendData(sender, data, encrypt=lambda x:x, pad=lambda x:x, chunksize=(16 * 1024), hasher=None, compress=False, stats=None, signature=False, hmac=None, iv=None, progress=None, progressPeriod=8*1024*1024):
    """ Send a block of data, optionally encrypt and/or compress it before sending """
    #logger = logging.getLogger('Data')
    if isinstance(sender, Connection.Connection):
        sender = sender.sender
    num = 0
    size = 0
    status = "OK"
    ck = None
    sig = None

    if progress:
        # Set the chunksize
        if progressPeriod % chunksize != 0:
            progressPeriod -= progressPeriod % chunksize

    if compress:
        stream = CompressedBuffer.CompressedBufferedReader(data, hasher=hasher, signature=signature)
    else:
        stream = CompressedBuffer.BufferedReader(data, hasher=hasher, signature=signature)

    try:
        if iv:
            sender.sendMessage(iv, raw=True)
            accumulateStat(stats, 'dataSent', len(iv))
            if hmac:
                hmac.update(iv)
        for chunk, eof in _chunks(stream, chunksize):
            if eof:
                chunk = pad(chunk)
            #print len(chunk), eof
            data = sender.encode(encrypt(chunk))
            if hmac:
                hmac.update(data)
            #chunkMessage = { "chunk" : num, "data": data }
            if data:
                sender.sendMessage(data, raw=True)
                accumulateStat(stats, 'dataSent', len(data))
                size += len(data)
                if progress:
                    if (size % progressPeriod) == 0:
                        progress()

            #num += 1
        if hmac:
            sender.sendMessage(hmac.digest(), raw=True)
            accumulateStat(stats, 'dataSent', hmac.digest_size)
    except Exception as e:
        status = "Fail"
        #logger = logging.getLogger('Data')
        #logger.exception(e)
        raise e
    finally:
        sender.sendMessage('', raw=True)
        compressed = stream.isCompressed()
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
    return size, ck, sig

def receiveData(receiver, output):
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
        bytes = receiver.decode(chunk)
        if output:
            output.write(bytes)
            output.flush()
        bytesReceived += len(bytes)

    chunk = receiver.recvMessage()
    status = chunk['status']
    size   = chunk['size']
    if 'checksum' in chunk:
        checksum = chunk['checksum']
    if 'compressed' in chunk:
        compressed = chunk['compressed']
    return (bytesReceived, status, size, checksum, compressed)

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
    config = ConfigParser.ConfigParser({'ContentKey': None, 'FilenameKey': None})
    config.add_section(client)
    config.read(fullPath(name))
    contentKey =  _updateLen(config.get(client, 'ContentKey'), 32)
    nameKey    =  _updateLen(config.get(client, 'FilenameKey'), 32)
    return (nameKey, contentKey)

def saveKeys(name, client, nameKey, contentKey):
    config = ConfigParser.ConfigParser()
    config.add_section(client)
    config.read(name)

    if contentKey:
        config.set(client, 'ContentKey', contentKey)
    else:
        config.remove_option(client, 'ContentKey')

    if nameKey:
        config.set(client, 'FilenameKey', nameKey)
    else:
        config.remove_option(client, 'FilenameKey')

    with open(name, 'wb') as configfile:
        config.write(configfile)

"""
Class to handle options of the form "--[no]argument" where you can specify --noargument to store a False,
or --argument to store a true.
"""
class StoreBoolean(argparse.Action):
    def __init__(self, option_strings, dest, negate="no", nargs=0, **kwargs):
        if nargs is not 0:
            raise ValueError("nargs not allowed")
        #if len(option_strings) > 1:
        #    raise ValueError("Multiple option strings not allowed")
        self.negative_option = "--" + negate + option_strings[0][2:]
        self.help_option = "--[" + negate + "]" + option_strings[0][2:]
        option_strings.append(self.negative_option)
        super(StoreBoolean, self).__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, args, values, option_string=None):
        #print "Here: ", option_string, " :: ", self.option_strings
        if option_string == self.negative_option:
            value = False
        else:
            value = True
        setattr(args, self.dest, value)

"""
Class to handle toggling options.  -x = true -xx = false -xxx = true, etc
"""
class Toggle(argparse.Action):
    def __init__(self,
                 option_strings,
                 dest,
                 default=None,
                 required=False,
                 help=None):
        super(Toggle, self).__init__(
            option_strings=option_strings,
            dest=dest,
            nargs=0,
            default=default,
            required=required,
            help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        new_value = not argparse._ensure_value(namespace, self.dest, False)
        setattr(namespace, self.dest, new_value)

"""
Help formatter to handle the StoreBoolean options.
Only handles overriding the basic HelpFormatter class.
"""
class HelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action):
        #print "_format_action_invocation", str(action)
        if hasattr(action, 'help_option'):
            ret = action.help_option
        else:
            ret = super(HelpFormatter, self)._format_action_invocation(action)
        #print "Got ", ret
        return ret

"""
Class to have a two directional dictionary.
"""
class bidict(dict):
    def __init__(self, *args, **kwargs):
        super(bidict, self).__init__(*args, **kwargs)
        self.inverse = {}
        for key, value in self.iteritems():
            self.inverse.setdefault(value,[]).append(key) 

    def __setitem__(self, key, value):
        super(bidict, self).__setitem__(key, value)
        self.inverse.setdefault(value,[]).append(key)

    def __delitem__(self, key):
        self.inverse.setdefault(self[key],[]).remove(key)
        if self[key] in self.inverse and not self.inverse[self[key]]: 
            del self.inverse[self[key]]
        super(bidict, self).__delitem__(key)

"""
Get a hash function.  Configurable.
"""
def getHash(crypt=None, doCrypt=True, func=hashlib.md5):
    if crypt and doCrypt:
        return crypt.getHash(func)
    else:
        return func()

"""
'Test' code
"""

if __name__ == "__main__":
    p = argparse.ArgumentParser(formatter_class=MyHelpFormatter)

    p.add_argument("--doit", action=StoreBoolean, help="Yo mama")
    p.add_argument("-x", action=Toggle, help="Whatever")

    args = p.parse_args()
    print args
