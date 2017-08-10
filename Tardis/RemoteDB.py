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

import logging
import tempfile
import sys
import urllib
import functools
import base64

from binascii import unhexlify

import requests
import requests_cache

import Tardis
import Tardis.TardisDB as TardisDB


requests_cache.install_cache(backend='memory', expire_after=30.0)

# Define a decorator that will wrap our functions in a retry mechanism
# so that if the connection to the server fails, we can automatically
# reconnect.
def reconnect(func):
    #print "Decorating ", str(func)
    @functools.wraps(func)
    def doit(self, *args, **kwargs):
        try:
            # Try the original function
            return func(self, *args, **kwargs)
        except requests.HTTPError as e:
            # Got an exception.  If it's ' 401 (not authorized)
            # reconnecton, and try it again
            logger=logging.getLogger('Reconnect')
            logger.info("Got HTTPError: %s", e)
            if e.response.status_code == 401:
                logger.info("Reconnecting")
                self.connect()
                logger.info("Retrying %s(%s %s)", str(func), str(args), str(kwargs))
                return func(self, *args, **kwargs)
            raise e
    return doit

def fs_encode(val):
    """ Turn filenames into str's (ie, series of bytes) rather than Unicode things """
    if not isinstance(val, bytes):
        #return val.encode(sys.getfilesystemencoding())
        return val.encode(sys.getfilesystemencoding())
    else:
        return val


class RemoteDB(object):
    """ Proxy class to retrieve objects via HTTP queries """
    session = None
    headers = {}
    prevBackupSet = None

    def __init__(self, url, host, prevSet=None, extra=None, compress=True, verify=False):
        self.logger=logging.getLogger('Remote')
        self.logger.debug("-> %s %s", url, host)
        self.baseURL = url
        if not url.endswith('/'):
            self.baseURL += '/'

        self.verify = verify
        self.host = host
        self.headers = { "user-agent": "TardisDB-" + Tardis.__versionstring__ }

        self.logger.debug("Connection to %s", url)

        # Disable insecure requests warning, if verify is disabled.
        # Generates too much output
        if not self.verify:
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

        if compress:
            self.headers['Accept-Encoding'] = "deflate"

        self.prevSet = prevSet
        self.connect()


    #def __del__(self):
    #    try:
    #        self.close()
    #    except Exception as e:
    #        self.logger.warning("Caught exception closing: " + str(e))
    #        self.logger.exception(e)

    def connect(self):
        self.logger.debug("Creating new connection to %s for %s", self.baseURL, self.host)
        self.session = requests.Session()
        self.session.verify = self.verify

        postData = { 'host': self.host }
        self.loginData = postData

        response = self.session.post(self.baseURL + "login", data=postData)
        response.raise_for_status()

    def authenticate1(self, uname, srpValueA):
        postData = {
            'srpUname':  base64.b64encode(uname),
            'srpValueA': base64.b64encode(srpValueA)
        }
        response = self.session.post(self.baseURL + 'authenticate1', data=postData)
        # Check for "not authenticated", which indicates authentication failed.
        if response.status_code == 401:
            raise TardisDB.AuthenticationFailed("Bad Password")
        # Catch other errors.
        response.raise_for_status()
        data = response.json()
        srpValueS = base64.b64decode(data['srpValueS'])
        srpValueB = base64.b64decode(data['srpValueB'])
        return srpValueS, srpValueB
        
    def authenticate2(self, srpValueM):
        postData = {
            'srpValueM': base64.b64encode(srpValueM)
        }
        response = self.session.post(self.baseURL + 'authenticate2', data=postData)
        # Check for "not authenticated", which indicates authentication failed.
        if response.status_code == 401:
            raise TardisDB.AuthenticationFailed("Bad Password")
        # Catch other errors.
        response.raise_for_status()
        data = response.json()
        srpValueH = base64.b64decode(data['srpValueH'])
        return srpValueH

    def close(self):
        self.logger.debug("Closing session")
        if self.session:
            r = self.session.get(self.baseURL + "close", headers=self.headers)
        r.raise_for_status()
        self.session = None
        return r.json()

    def _setPrevBackupSet(self):
        if self.prevSet:
            f = self.getBackupSetInfo(self.prevSet)
            if f:
                self.prevBackupSet = f['backupset']
                self.prevBackupName = f['name']
        else:
            b = self.lastBackupSet()
            self.prevBackupSet  = b['backupset']
            self.prevBackupName = b['name']
        self.logger.debug("Last Backup Set: %s %d", self.prevBackupName, self.prevBackupSet)
        return self.prevBackupSet

    def _bset(self, current):
        """ Determine the backupset we're being asked about.
            True == current, false = previous, otherwise a number is returned
        """
        if type(current) is bool:
            if current:
                return str(None)
            else:
                if self.prevBackupSet:
                    return str(self.prevBackupSet)
                else:
                    return str(self._setPrevBackupSet())
        else:
            return str(current)

    @reconnect
    def listBackupSets(self):
        r = self.session.get(self.baseURL + "listBackupSets", headers=self.headers)
        r.raise_for_status()
        for i in r.json():
            self.logger.debug("Returning %s", str(i))
            i['name'] = fs_encode(i['name'])
            yield i

    @reconnect
    def lastBackupSet(self, completed=True):
        r = self.session.get(self.baseURL + "lastBackupSet/" + str(int(completed)), headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def getBackupSetInfo(self, name):
        name = urllib.quote(name, '')
        r = self.session.get(self.baseURL + "getBackupSetInfo/" + name, headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def getBackupSetInfoById(self, bset):
        r = self.session.get(self.baseURL + "getBackupSetInfoById/" + str(bset), headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def getBackupSetDetails(self, name):
        name = urllib.quote(str(name), '')
        r = self.session.get(self.baseURL + "getBackupSetDetails/" + str(name), headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def getBackupSetInfoForTime(self, time):
        r = self.session.get(self.baseURL + "getBackupSetInfoForTime/" + str(time), headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def getFileInfoByName(self, name, parent, current=True):
        bset = self._bset(current)
        (inode, device) = parent
        name = urllib.quote(name, '/')
        r = self.session.get(self.baseURL + "getFileInfoByName/" + bset + "/" + str(device) + "/" + str(inode) + "/" + name, headers=self.headers)
        r.raise_for_status()
        return r.json()


    @reconnect
    def getFileInfoByInode(self, node, current=True):
        bset = self._bset(current)
        (inode, device) = node
        r = self.session.get(self.baseURL + "getFileInfoByInode/" + bset + "/" + str(device) + "/" + str(inode), headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def getFileInfoByPath(self, path, current=False):
        bset = self._bset(current)
        if not path.startswith('/'):
            path = '/' + path
        path = urllib.quote(path, '/')
        r = self.session.get(self.baseURL + "getFileInfoByPath/" + bset + path, headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def getFileInfoByPathForRange(self, path, first, last, permchecker=None):
        if not path.startswith('/'):
            path = '/' + path
        path = urllib.quote(path, '/')
        r = self.session.get(self.baseURL + "getFileInfoByPathForRange/" + str(first) + '/' + str(last) + path, headers=self.headers)
        r.raise_for_status()
        for i in r.json():
            yield i

    @reconnect
    def readDirectory(self, dirNode, current=False):
        (inode, device) = dirNode
        bset = self._bset(current)
        r = self.session.get(self.baseURL + "readDirectory/" + bset + "/" + str(device) + "/" + str(inode), headers=self.headers)
        r.raise_for_status()
        for i in r.json():
            i['name'] = fs_encode(i['name'])
            yield i

    @reconnect
    def readDirectoryForRange(self, dirNode, first, last):
        (inode, device) = dirNode
        r = self.session.get(self.baseURL + "readDirectoryForRange/" + str(device) + "/" + str(inode) + "/" + str(first) + "/" + str(last), headers=self.headers)
        r.raise_for_status()
        for i in r.json():
            i['name'] = fs_encode(i['name'])
            yield i

    @reconnect
    def checkPermissions(self, path, checker, current=False):
        bset = self._bset(current)
        r = self.session.get(self.baseURL + "getFileInfoForPath/" + bset + "/" + path, headers=self.headers)
        r.raise_for_status()
        for i in r.json():
            ret = checker(i['uid'], i['gid'], i['mode'])
            if not ret:
                return False
        return True

    @reconnect
    def getNewFiles(self, bset, other):
        r = self.session.get(self.baseURL + "getNewFiles/" + str(bset) + "/" + str(other), headers=self.headers)
        r.raise_for_status()
        for i in r.json():
            i['name'] = fs_encode(i['name'])
            yield i

    @reconnect
    def getChecksumByPath(self, path, current=False, permchecker=None):
        bset = self._bset(current)
        if not path.startswith('/'):
            path = '/' + path
        path = urllib.quote(path, '/')
        r = self.session.get(self.baseURL + "getChecksumByPath/" + bset + path, headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def getChecksumInfo(self, checksum):
        r = self.session.get(self.baseURL + "getChecksumInfo/" + checksum, headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def getChecksumInfoChain(self, checksum):
        r = self.session.get(self.baseURL + "getChecksumInfoChain/" + checksum, headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def getChecksumInfoChainByPath(self, name, bset, permchecker=None):
        if not name.startswith('/'):
            name = '/' + name
        name = urllib.quote(name, '/')
        r = self.session.get(self.baseURL + "getChecksumInfoChainByPath/" + str(bset) + name, headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def getFirstBackupSet(self, name, current=False):
        bset = self._bset(current)
        r = self.session.get(self.baseURL + "getFirstBackupSet/" + str(bset) + "/" + name, headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def getChainLength(self, checksum):
        r = self.session.get(self.baseURL + "getChainLength/" + checksum, headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def getConfigValue(self, name):
        r = self.session.get(self.baseURL + "getConfigValue/" + name, headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def setConfigValue(self, name, value):
        r = self.session.get(self.baseURL + "setConfigValue/" + name + "/" + value, headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def getKeys(self):
        fnKey = self.getConfigValue('FilenameKey')
        cnKey = self.getConfigValue('ContentKey')
        #self.logger.info("Got keys: %s %s", fnKey, cnKey)
        return (fnKey, cnKey)

    @reconnect
    def setKeys(self, salt, vkey, fKey, cKey):
        postData = { 'Salt': base64.b64encode(salt), 'SrpVKey': base64.b64encode(vkey), 'FilenameKey': fKey, 'ContentKey': cKey }
        response = self.session.post(self.baseURL + "setKeys", data=postData)
        response.raise_for_status()

    @reconnect
    def setSrpValues(self, salt, vkey):
        postData = { 'salt': salt, 'vkey': vkey }
        response = self.session.post(self.baseURL + "setSrpValues", data=postData)
        response.raise_for_status()
        return response.json()

    @reconnect
    def getSrpValues(self):
        salt = unhexlify(self.getConfigValue('SRPSalt'))
        vKey = unhexlify(self.getConfigValue('SRPVkey'))
        return (salt, vKey)

    @reconnect
    def listPurgeSets(self, priority, timestamp, current=False):
        bset = self._bset(current)
        r = self.session.get(self.baseURL + "listPurgeSets/" + bset + '/' + str(priority) + '/' + str(timestamp), headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def listPurgeIncomplete(self, priority, timestamp, current=False):
        bset = self._bset(current)
        r = self.session.get(self.baseURL + "listPurgeIncomplete/" + bset + '/' + str(priority) + '/' + str(timestamp), headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def purgeSets(self, priority, timestamp, current=False):
        bset = self._bset(current)
        r = self.session.get(self.baseURL + "purgeSets/" + bset + '/' + str(priority) + '/' + str(timestamp), verify=self.verify, headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def purgeIncomplete(self, priority, timestamp, current=False):
        bset = self._bset(current)
        r = self.session.get(self.baseURL + "purgeIncomplete/" + bset + '/' + str(priority) + '/' + str(timestamp), headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def deleteBackupSet(self, bset):
        r = self.session.get(self.baseURL + "deleteBackupSet/" + str(bset))
        r.raise_for_status()
        return r.json()

    @reconnect
    def listOrphanChecksums(self, isFile):
        r = self.session.get(self.baseURL + 'listOrphanChecksums/' + str(int(isFile)), headers=self.headers)
        r.raise_for_status()
        return r.json()

    @reconnect
    def open(self, checksum, mode):
        temp = tempfile.SpooledTemporaryFile("wb")
        r = self.session.get(self.baseURL + "getFileData/" + checksum, stream=True)
        r.raise_for_status()
        #self.logger.debug("%s", str(r.headers))

        for chunk in r.iter_content(chunk_size=64 * 1024):
            temp.write(chunk)

        temp.seek(0)
        return temp

    @reconnect
    def removeOrphans(self):
        r = self.session.get(self.baseURL + "removeOrphans", verify=self.verify, headers=self.headers)
        r.raise_for_status()
        return r.json()
