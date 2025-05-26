# vim: set et sw=4 sts=4 fileencoding=utf-8:

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

import base64
import functools
import importlib
import importlib.resources
import logging
import os
import os.path
import sqlite3
import sys
import time
import uuid
from binascii import hexlify, unhexlify
from textwrap import dedent

import srp

import Tardis

from . import ConnIdLogAdapter, Rotator, Util

# from icecream import ic
# ic.configureOutput(includeContext=True)

# Exception classes
class AuthenticationException(Exception):
    pass

class AuthenticationFailed(AuthenticationException):
    pass

class NotAuthenticated(AuthenticationException):
    pass

# Subclass the Row object to add a "get" operation.
# Allows it t

class TardisRow(sqlite3.Row):
    def get(self, value, default=None):
        try:
            if self[value] is not None:
                return self[value]
            return default
        except IndexError:
            return default

    def __str__(self):
        return str(dict(**self))


    def __repr__(self):
        return repr(dict(**self))


# Utility functions
def authenticate(func):
    @functools.wraps(func)
    def doit(self, *args, **kwargs):
        if self._isAuthenticated():
            return func(self, *args, **kwargs)
        raise NotAuthenticated("Not authenticated to database.")
    return doit

# Be sure to end all these lists with a space.

_fileInfoFields = dedent(
    """
    N1.Name AS name, Inode AS inode, D1.VirtualID AS device, Dir AS dir, Link AS link, 
    Parent AS parent, D2.VirtualID AS parentdev, Files.RowId AS rowid, C1.Size AS size, 
    MTime AS mtime, CTime AS ctime, ATime AS atime, Mode AS mode, NLinks AS nlinks, 
    FirstSet AS firstset, LastSet AS lastset,
    C1.Checksum AS checksum, C1.ChainLength AS chainlength, C1.DiskSize AS disksize,
    C2.Checksum AS xattrs,
    C3.Checksum AS acl,
    N2.Name AS username,
    N3.Name AS groupname
    """)

_fileInfoJoin = dedent(
    """
    FROM Files
    JOIN Names N1 USING(NameID)
    LEFT OUTER JOIN Checksums AS C1 USING (ChecksumId)
    LEFT OUTER JOIN Checksums AS C2 ON Files.XattrId = C2.ChecksumId
    LEFT OUTER JOIN Checksums AS C3 ON Files.AclId = C3.ChecksumId
    JOIN Users USING (UserID)
    JOIN Groups USING (GroupID) 
    JOIN Devices D1 ON Files.Device = D1.DeviceID
    JOIN Devices D2 ON Files.ParentDev = D2.DeviceID
    JOIN Names N2 ON Users.NameID = N2.NameID
    JOIN Names N3 ON Groups.NameID = N3.NameID
    """)

_backupSetInfoFields = dedent(
    """
    BackupSet AS backupset, StartTime AS starttime, EndTime AS endtime, ClientTime AS clienttime,
    Priority AS priority, Completed AS completed, Session AS session, Name AS name, Locked AS locked,
    ClientVersion AS clientversion, ClientIP AS clientip, ServerVersion AS serverversion, Full AS full,
    FilesFull AS filesfull, FilesDelta AS filesdelta, BytesReceived AS bytesreceived, Checksum AS commandline,
    Exception AS exception, ErrorMsg AS errormsg
    """)

_backupSetInfoJoin = "FROM Backups LEFT OUTER JOIN Checksums ON Checksums.ChecksumID = Backups.CmdLineId "

_checksumInfoFields = dedent(
    """
    Checksum AS checksum, ChecksumID AS checksumid, Basis AS basis, Encrypted AS encrypted,
    Size AS size, DeltaSize AS deltasize, DiskSize AS disksize, IsFile AS isfile, Compressed AS compressed,
    ChainLength AS chainlength, Added AS added
    """)

_schemaVersion = 23

def _splitpath(path):
    """ Split a path into chunks, recursively """
    (head, tail) = os.path.split(path)
    return _splitpath(head) + [tail] if head and head != path else [head or tail]

def _fetchEm(cursor):
    while batch := cursor.fetchmany(10000):
        yield from batch

conversionModules = {}

# Class TardisDB

class TardisDB:
    """ Main source for all interaction with the Tardis DB """
    db              = None
    currBackupSet   = None
    prevBackupSet   = None
    clientId        = None

    def __init__(self, dbfile, backup=False, prevSet=None, initialize=False, connid=None, user=-1, group=-1, chunksize=1000, numbackups=2, allow_upgrade=False, check_threads=True):
        """ Initialize the connection to a per-machine Tardis Database"""
        self.logger  = logging.getLogger("DB")
        self.logger.debug("Initializing connection to %s", dbfile)
        self.dbfile = dbfile
        self.chunksize = chunksize
        self.prevSet = prevSet
        self.allow_upgrade = allow_upgrade
        self.authenticated = False

        self.srpSrv = None

        self.rootVId = Util.hashPath("/")

        if user is None:
            user = -1
        if group is None:
            group = -1

        self.user = user
        self.group = group

        if connid:
            self.logger = ConnIdLogAdapter.ConnIdLogAdapter(self.logger, connid)

        self.backup = backup
        self.numbackups = numbackups

        try:
            conn = sqlite3.connect(self.dbfile, check_same_thread=check_threads)
        except sqlite3.Error as e:
            self.logger.critical(f"Unable to open database: {e}")
            raise

        conn.text_factory = lambda x: x.decode('utf-8', 'backslashreplace')
        conn.row_factory = TardisRow

        self.conn = conn

        if initialize:
            self.logger.info("Creating database from schema: %s", initialize)
            try:
                # read the script from the package, and execute it.
                script = importlib.resources.files().joinpath('schema', 'tardis.sql').read_text()
                self.conn.executescript(script)
                # Insert an element 
                conn.execute("INSERT INTO Devices (DeviceID, VirtualID) VALUES (0, :virtid)", {"virtid": self.rootVId})
            except IOError:
                self.logger.critical("Could not read initialization script %s", initialize)
                raise
            except sqlite3.Error:
                self.logger.critical("Could not execute initialization script %s", initialize)
                raise
            self._setConfigValue('ClientID', str(uuid.uuid1()))
            newDB = True
        else:
            newDB = False

        # Start authentication here.
        self.logger.debug("Authentication status: %s %s", not newDB, self.needsAuthentication())
        if newDB or not self.needsAuthentication():
            self.logger.debug("Setting authenticated true")
            self.authenticated = True
            self._completeInit()
        else:
            self.logger.debug("Setting authenticated false")
            self.authenticated = False

    def needsAuthentication(self):
        """ Return true if a database needs to be authenticated """
        salt, _ = self.getSrpValues()
        return bool(salt)

    def authenticate1(self, uname, srpValueA):
        salt, vkey = self.getSrpValues()
        if salt is None or vkey is None:
            raise AuthenticationFailed("Password doesn't match")
        self.srpSrv = srp.Verifier(uname, salt, vkey, srpValueA)
        s, B = self.srpSrv.get_challenge()
        if s is None or B is None:
            raise AuthenticationFailed("Password doesn't match")
        return s, B

    def authenticate2(self, srpValueM):
        self.logger.debug("Authentication 2: Verify Session %s", hexlify(srpValueM))
        HAMK = self.srpSrv.verify_session(srpValueM)
        if HAMK is None:
            raise AuthenticationFailed("Password doesn't match")
        self.logger.debug("Authentication HAMK: %s", hexlify(HAMK))
        if not self.srpSrv.authenticated():
            raise AuthenticationFailed("Password doesn't match")
        self.authenticated = True
        self._completeInit()
        return HAMK

    def _completeInit(self):
        self.logger.debug("Completing DB Init")

        version = int(self._getConfigValue('SchemaVersion'))
        if version != _schemaVersion:
            if self.allow_upgrade:
                self.logger.warning("Schema version mismatch: Upgrading.  Database %s is %d:  Expected %d.", self.dbfile, int(version), _schemaVersion)
                self.upgradeSchema(version)
            else:
                self.logger.error("Schema version mismatch: Database %s is %d:  Expected %d.   Please convert", self.dbfile, int(version), _schemaVersion)
                raise Exception(f"Schema version mismatch: Database {self.dbfile} is {version}:  Expected {_schemaVersion}.   Please convert")

        if self.prevSet:
            f = self.getBackupSetInfo(self.prevSet)
            if f:
                self.prevBackupSet  = f['backupset']
                self.prevBackupDate = f['starttime']
                self.prevBackupName = self.prevSet
        else:
            b = self.lastBackupSet()
            self.prevBackupName = b['name']
            self.prevBackupSet  = b['backupset']
            self.prevBackupDate = b['starttime']

        self.clientId = self.getConfigValue('ClientID')

        self.logger.debug("Last Backup Set: %s %d ", self.prevBackupName, self.prevBackupSet)

        self.conn.commit()

        self.conn.execute("PRAGMA synchronous=false")
        self.conn.execute("PRAGMA foreignkeys=true")

        # Make sure the permissions are set the way we want, if that's specified.
        if self.user != -1 or self.group != -1:
            os.chown(self.dbfile, self.user, self.group)

    def _bset(self, current):
        """ Determine the backupset we're being asked about.
            True == current, False = previous, otherwise a number is returned
        """
        if isinstance(current, bool):
            return self.currBackupSet if current else self.prevBackupSet
        return current

    def _getConverter(self, name):
        try:
            converter = conversionModules[name]
        except KeyError:
            converter = importlib.import_module('Tardis.Converters.' + name)
            conversionModules[name] = converter
        return converter

    def upgradeSchema(self, baseVersion):
        for i in range(baseVersion, _schemaVersion):
            name = f'convert{i}to{i + 1}'
            converter = self._getConverter(name)
            self.logger.debug("Running conversion script from version %d, %s", i, name)
            converter.upgrade(self.conn, self.logger)
            self.logger.warning("Upgraded schema to version %d", i + 1)

    @authenticate
    def lastBackupSet(self, completed=True):
        """ Select the last backup set. """
        if completed:
            return self._executeWithResult(
                "SELECT " + _backupSetInfoFields + _backupSetInfoJoin +
                "WHERE Completed = 1 ORDER BY BackupSet DESC LIMIT 1"
            )
        return self._executeWithResult(
            "SELECT " + _backupSetInfoFields + _backupSetInfoJoin +
            "ORDER BY BackupSet DESC LIMIT 1"
        )

    def _execute(self, query, data=None):
        """ Execute a query, and return a cursor to the results """
        try:
            if data is None:
                data = {}
            ret = self.conn.execute(query, data)
            return ret
        except sqlite3.IntegrityError as e:
            self.logger.error("Error processing data: %s %s", data, e)
            raise e

    def _executeWithResult(self, query, data=None):
        """ Execute a query, and return the (first) result row. """
        c = self._execute(query, data)
        return c.fetchone()

    @authenticate
    def newBackupSet(self, name, session, priority, clienttime, version=None, ip=None, full=False, serverID=None):
        """ Create a new backupset.  Set the current backup set to be that set. """
        now = time.time()
        try:
            c = self._execute(
                "INSERT INTO Backups "
                "           (Name, Completed, StartTime, Session, Priority, Full, ClientTime, ClientVersion, ServerVersion, SchemaVersion, ClientIP, ServerSession) "
                "    VALUES (:name, 0, :now, :session, :priority, :full, :clienttime, :clientversion, :serverversion, :schemaversion, :clientip, :serversessionid)",
                {
                    "name": name,
                    "now": now,
                    "session": session,
                    "priority": priority,
                    "full": full,
                    "clienttime": clienttime,
                    "clientversion": version,
                    "clientip": ip,
                    "schemaversion": _schemaVersion,
                    "serversessionid": serverID,
                    "serverversion": (Tardis.__buildversion__ or Tardis.__version__)
                })
        except sqlite3.IntegrityError:
            self.logger.critical(f"Backupset {name} already exists")
            raise Exception(f"Backupset {name} already exists")

        self.currBackupSet = c.lastrowid

        if name is None:
            name = f"INCOMPLETE-{self.currBackupSet}"
            self.setBackupSetName(name, priority)

        self.conn.commit()
        self.logger.info("Created new backup set: %d: %s %s", self.currBackupSet, name, session)

        return self.currBackupSet

    @authenticate
    def setBackupSetName(self, name, priority, current=True):
        """ Change the name of a backupset.  Return True if it can be changed, false otherwise. """
        backupset = self._bset(current)
        try:
            self._execute("UPDATE Backups SET Name = :name, Priority = :priority WHERE BackupSet = :backupset",
                          {"name": name, "priority": priority, "backupset": backupset})
            return True
        except sqlite3.IntegrityError:
            return False

    @authenticate
    def setClientConfig(self, config, current=True):
        """ Store the full client configuration in the database """
        backupset = self._bset(current)
        r = self._executeWithResult("SELECT ClientConfigID FROM ClientConfig WHERE ClientConfig = :config",
                                    {"config": config})
        if r is None:
            c = self._execute("INSERT INTO ClientConfig (ClientConfig) VALUES (:config)",
                              {"config": config})
            clientConfigId = c.lastrowid
        else:
            clientConfigId = r[0]
        self._execute("UPDATE Backups SET ClientConfigID = :configId WHERE BackupSet = :backupset",
                      {"configId": clientConfigId, "backupset": backupset})

    @authenticate
    def setCommandLine(self, cksum, current=True):
        """ Set a command line variable in the database """
        backupset = self._bset(current)
        self._execute("UPDATE Backups SET CmdLineID = :cksid WHERE BackupSet = :backupset",
                      {'cksid': cksum, 'backupset': backupset})

    @authenticate
    def checkBackupSetName(self, name):
        """ Check to see if a backupset by this name exists. Return TRUE if it DOESN'T exist. """
        row = self._executeWithResult("SELECT COUNT(*) FROM Backups WHERE Name = :name",
                                      {"name": name})
        return row[0] == 0

    @authenticate
    def getFileInfoByName(self, name, parent, current=True):
        """ Lookup a file in a directory in the previous backup set"""
        backupset = self._bset(current)
        (inode, device) = parent
        device = self._getDeviceId(device)
        self.logger.debug(f"Looking up file by name {name} {parent} {backupset}")
        row = self._executeWithResult(
                  "SELECT " +
                  _fileInfoFields + _fileInfoJoin +
                  "WHERE N1.Name = :name AND Parent = :parent AND ParentDev = :parentDev AND "
                  ":backup BETWEEN FirstSet AND LastSet",
                  {"name": name, "parent": inode, "parentDev": device, "backup": backupset})
        return row

    @authenticate 
    def getRootDirectory(self, current=False):
        backupset = self._bset(current)
        r = self._executeWithResult("SELECT " + _fileInfoFields + _fileInfoJoin +
                                    "WHERE Inode = 0 AND :backupset BETWEEN FirstSet AND LastSet",
                                    {"backupset": backupset})
        return r

    @authenticate
    def getFileInfoByPath(self, path, current=False, permchecker=None):
        """ Lookup a file by a full path. """
        ### TODO: Could be a LOT faster without the repeated calls to getFileInfoByName
        backupset = self._bset(current)
        self.logger.debug("Looking up file by path %s %s", path, backupset)
        parent = (0, self.rootVId)
        info = None

        # Walk the path
        for name in _splitpath(path):
            if name == '/':
                continue
            info = self.getFileInfoByName(name, parent, backupset)
            if info:
                parent = (info["inode"], info["device"])
                if permchecker:
                    if not permchecker(info['user'], info['group'], info['mode']):
                        raise Exception("File permission denied: " + name)
            else:
                break
        return info

    @authenticate
    def getFileInfoByPathForRange(self, path, first, last, permchecker=None):
        sets = self._execute('SELECT BackupSet FROM Backups WHERE BackupSet BETWEEN :first AND :last ORDER BY BackupSet ASC', {'first': first, 'last': last})
        for row in sets.fetchall():
            yield (row[0], self.getFileInfoByPath(path, row[0], permchecker))

    @authenticate
    def getFileInfoForPath(self, path, current=False):
        """ Return the FileInfo structures for each file along a path """
        backupset = self._bset(current)
        parent = (0, 0)         # Root directory value
        info = None
        for name in _splitpath(path):
            if name == '/':
                continue
            info = self.getFileInfoByName(name, parent, backupset)
            if info:
                yield info
                parent = (info["inode"], info["device"])
            else:
                break

    @authenticate
    def getFileInfoByInode(self, info, current=False):
        backupset = self._bset(current)
        (inode, device) = info
        self.logger.debug("Looking up file by inode (%d %d) %d", inode, device, backupset)
        row = self._executeWithResult("SELECT " +
                      _fileInfoFields + _fileInfoJoin +
                      "WHERE Inode = :inode AND Files.Device = :device AND "
                      ":backup BETWEEN FirstSet AND LastSet",
                      {"inode": inode, "device": self._getDeviceId(device), "backup": backupset})
        return row

    @authenticate
    def getFileInfoBySimilar(self, fileInfo, current=False):
        """ Find a file which is similar, namely the same size, inode, and mtime.  Identifies files which have moved. """
        backupset = self._bset(current)
        self.logger.debug("Looking up file for similar info: %s", fileInfo)
        temp = fileInfo.copy()
        temp['dev'] = self._getDeviceId(temp['dev'])
        temp["backup"] = backupset
        row = self._executeWithResult("SELECT " +
                                      _fileInfoFields + _fileInfoJoin +
                                      "WHERE Inode = :inode AND Files.Device = :dev AND Mtime = :mtime AND C1.Size = :size AND "
                                      ":backup BETWEEN Files.FirstSet AND Files.LastSet",
                                      temp)
        return row

    @authenticate
    def getFileInfoByChecksum(self, checksum, current=False):
        """ Return a list of files that match the checksum """
        backupset = self._bset(current)
        self.logger.debug("Looking up file for similar info: %s", checksum)
        query = "SELECT " + _fileInfoFields + _fileInfoJoin + "WHERE C1.Checksum = :cksum"
        if current is not None:
            query += " AND :backup BETWEEN Files.FirstSet AND Files.LastSet"
        c = self._execute(query, {'cksum': checksum, 'backup': backupset})
        return _fetchEm(c)

    @authenticate
    def getFileFromPartialBackup(self, fileInfo):
        """ Find a file which is similar, namely the same size, inode, and mtime.  Identifies files which have moved. """
        temp = fileInfo.copy()
        temp["dev"] = self._getDeviceId(temp['dev'])
        temp["backup"] = self.prevBackupSet         ### Only look for things newer than the last backup set
        row = self._executeWithResult("SELECT " +
                                _fileInfoFields + _fileInfoJoin +
                                "WHERE Inode = :inode AND Files.Device = :dev AND Mtime = :mtime AND C1.Size = :size AND "
                                "Files.LastSet >= :backup "
                                "ORDER BY Files.LastSet DESC LIMIT 1",
                                temp)
        return row

    @authenticate
    def getFileInfoByInodeFromPartial(self, inode):
        (ino, dev) = inode
        r = self._executeWithResult("SELECT " +
                                _fileInfoFields + _fileInfoJoin +
                                "WHERE Inode = :inode AND Files.Device = :device AND "
                                "Files.LastSet >= :backup "
                                "ORDER BY Files.LastSet DESC LIMIT 1",
                                {"inode": ino, "device": self._getDeviceId(dev), "backup": self.prevBackupSet})

        return r

    @authenticate
    def setChecksum(self, inode, device, checksum):
        c = self._execute("UPDATE Files SET ChecksumId = (SELECT ChecksumId FROM CheckSums WHERE CheckSum = :checksum) "
                            "WHERE Inode = :inode AND Files.Device = :device AND "
                            ":backup BETWEEN FirstSet AND LastSet",
                            {"inode": inode, "device": self._getDeviceId(device), "checksum": checksum, "backup": self.currBackupSet})
        return c.rowcount

    @authenticate
    def setXattrs(self, inode, device, checksum):
        c = self._execute("UPDATE Files SET XattrId = (SELECT ChecksumId FROM CheckSums WHERE CheckSum = :checksum) "
                            "WHERE Inode = :inode AND Files.Device = :device AND "
                            ":backup BETWEEN FirstSet AND LastSet",
                            {"inode": inode, "device": self._getDeviceId(device), "checksum": checksum, "backup": self.currBackupSet})
        return c.rowcount

    @authenticate
    def setAcl(self, inode, device, checksum):
        c = self._execute("UPDATE Files SET AclId = (SELECT ChecksumId FROM CheckSums WHERE CheckSum = :checksum) "
                            "WHERE Inode = :inode AND Files.Device = :device AND "
                            ":backup BETWEEN FirstSet AND LastSet",
                            {"inode": inode, "device": self._getDeviceId(device), "checksum": checksum, "backup": self.currBackupSet})
        return c.rowcount


    @authenticate
    def getChecksumByInode(self, inode, device, current=True):
        backupset = self._bset(current)
        row = self._executeWithResult("SELECT "
                                "CheckSums.Checksum AS checksum "
                                "FROM Files JOIN CheckSums USING (ChecksumID) "
                                "WHERE Files.INode = :inode AND Files.Device = :device AND "
                                ":backup BETWEEN Files.FirstSet AND Files.LastSet",
                                {"backup" : backupset, "inode" : inode, "device": self._getDeviceId(device)})
        return row[0] if row else None

    @authenticate
    def getChecksumByName(self, name, parent, current=False):
        backupset = self._bset(current)
        (inode, device) = parent
        self.logger.debug("Looking up checksum for file %s (%d %d) in %d", name, inode, device, backupset)
        row = self._executeWithResult(
            "SELECT CheckSums.CheckSum AS checksum "
            "FROM Files "
            "JOIN Names USING (NameId) "
            "JOIN CheckSums USING (ChecksumId) "
            "WHERE Names.Name = :name AND Files.Parent = :parent AND ParentDev = :parentDev AND "
            ":backup BETWEEN Files.FirstSet AND Files.LastSet",
            {"name": name, "parent": inode, "parentDev": self._getDeviceId(device), "backup": backupset})
        return row[0] if row else None

    @authenticate
    def getChecksumByPath(self, name, current=False, permchecker=None):
        backupset = self._bset(current)
        self.logger.debug("Looking up checksum for path %s %d", name, backupset)
        f = self.getFileInfoByPath(name, current, permchecker=permchecker)
        if f:
            return self.getChecksumByName(f["name"], (f["parent"], f["parentdev"]), current)
        return None

    @authenticate
    def getChecksumInfoByPath(self, name, current=False, permchecker=None):
        backupset = self._bset(current)
        cksum = self.getChecksumByPath(name, backupset, permchecker)
        if cksum:
            return self.getChecksumInfo(cksum)
        return None

    @authenticate
    def getChecksumInfoChainByPath(self, name, current=False, permchecker=None):
        backupset = self._bset(current)
        self.logger.debug("Getting Checksum Info for %s", name)
        cksum = self.getChecksumByPath(name, backupset, permchecker)
        self.logger.debug("Got checksum %s", name)
        if cksum:
            return self.getChecksumInfoChain(cksum)
        return None

    @authenticate
    def getChecksumsByBasis(self, checksum):
        c = self._execute("SELECT Checksum FROM CheckSums WHERE BASIS = :basis", {'basis': checksum})
        return _fetchEm(c)

    @authenticate
    def getFirstBackupSet(self, name, current=False):
        backupset = self._bset(current)
        self.logger.debug("getFirstBackupSet (%d) %s", backupset, name)
        f = self.getFileInfoByPath(name, backupset)
        if f:
            c = self._execute("SELECT Name FROM Backups WHERE BackupSet >= :first ORDER BY BackupSet ASC LIMIT 1",
                              {"first": f["firstset"]})
            row = c.fetchone()
            if row:
                return row[0]
        # General purpose failure
        return None

    @functools.lru_cache
    def _getUserId(self, user):
        nameid = self._getNameId(user)
        row = self._executeWithResult("SELECT UserID FROM Users WHERE NameId = :nameid", {"nameid": nameid})
        if row:
            userid = row[0]
        else:
            self.logger.debug("Inserting username %s into Users Table", user)
            c = self._execute("INSERT INTO Users (NameID) VALUES (:nameid)", {"nameid": nameid})
            userid = c.lastrowid
        self.logger.debug("User ID %s -> %d", user, userid)
        return userid

    @functools.lru_cache
    def _getGroupId(self, group):
        nameid = self._getNameId(group)
        row = self._executeWithResult("SELECT GroupID FROM Groups WHERE NameId = :nameid", {"nameid": nameid})
        if row:
            groupid = row[0]
        else:
            self.logger.debug("Inserting groupname %s into Groups Table", group)
            c = self._execute("INSERT INTO Groups (NameID) VALUES (:nameid)", {"nameid": nameid})
            groupid = c.lastrowid
        self.logger.debug("Group ID %s -> %d", group, groupid)
        return groupid

    @functools.lru_cache
    def _getDeviceId(self, virtualDevice):
        if not isinstance(virtualDevice, str):
            raise Exception(f"Invalid argument type {type(virtualDevice)} {virtualDevice}")
        row = self._executeWithResult("SELECT DeviceID FROM Devices WHERE VirtualID = :virtualDev", {"virtualDev": virtualDevice})
        if row:
            deviceId = row[0]
        else:
            self.logger.debug("Inserting virtual device %s into Devices Table", virtualDevice)
            c = self._execute("INSERT INTO Devices (VirtualID) VALUES (:virtualDev)", {"virtualDev": virtualDevice})
            deviceId = c.lastrowid
        self.logger.debug("Device ID %s -> %d", virtualDevice, deviceId)
        return deviceId


    @functools.cache
    def _getUserAndGroup(self, user, group):
        return self._getUserId(user), self._getGroupId(group)

    @authenticate
    def insertFile(self, fileInfo, parent):
        self.logger.debug("Inserting file: %s", fileInfo)
        (parIno, parDev) = parent
        user, group = self._getUserAndGroup(fileInfo['user'], fileInfo['group'])
        deviceId = self._getDeviceId(fileInfo['dev'])
        parentDevId = self._getDeviceId(parDev)
        fields = {"backup": self.currBackupSet,
                  "parent": parIno,
                  "parentdevid": parentDevId,
                  "deviceid": deviceId,
                  "userid": user,
                  "groupid": group,
                  'nameid': self._getNameId(fileInfo['name'])}
        fields.update(fileInfo)
        self._execute("INSERT INTO Files "
                      "(NameId, FirstSet, LastSet, Inode, Device, Parent, ParentDev, Dir, Link, MTime, CTime, ATime,  Mode, UID, GID, UserID, GroupID, NLinks) "
                      "VALUES  "
                      "(:nameid, :backup, :backup, :inode, :deviceid, :parent, :parentdevid, :dir, :link, :mtime, :ctime, :atime, :mode, :uid, :gid, :userid, :groupid, :nlinks)",
                      fields)

    @authenticate
    def updateDirChecksum(self, directory, cksid, current=True):
        bset = self._bset(current)
        (inode, device) = directory
        deviceId = self._getDeviceId(device)
        self._execute("UPDATE FILES "
                      "SET ChecksumID = :cksid "
                      "WHERE Inode = :inode AND DEVICE = :device AND :bset BETWEEN FirstSet AND LastSet",
                      {"inode": inode, "device": deviceId, "cksid": cksid, "bset": bset})

    @authenticate
    def extendFile(self, parent, name, old=False, current=True):
        old = self._bset(old)
        current = self._bset(current)
        (parIno, parDev) = parent
        parDevId = self._getDeviceId(parDev)
        cursor = self._execute("UPDATE FILES "
                               "SET LastSet = :new "
                               "WHERE Parent = :parent AND ParentDev = :parentDev AND NameID = (SELECT NameID FROM Names WHERE Name = :name) AND "
                               ":old BETWEEN FirstSet AND LastSet",
                               {"parent": parIno, "parentDev": parDevId , "name": name, "old": old, "new": current })
        return cursor.rowcount

    @authenticate
    def extendFileRowID(self, rowid, current=True):
        """ Extend a file, based on the rowid (fileid) """
        current = self._bset(current)
        self._execute("UPDATE Files SET LastSet = :new WHERE RowID = :rowid", {"new": current, "rowid": rowid})

    @authenticate
    def extendFileRowIDs(self, rowids, current=True):
        """ extend a set of files based on a list of rowid's """
        current = self._bset(current)
        self.conn.executemany("UPDATE Files SET LASTSET = :lastset WHERE RowID = :rowid", map(lambda x: {"lastset": current, "rowid": x}, rowids))

    @authenticate
    def extendFileInode(self, parent, inode, old=False, current=True):
        old = self._bset(old)
        current = self._bset(current)
        (parIno, parDev) = parent
        (ino, dev) = inode
        parDevId = self._getDeviceId(parDev)
        devId = self._getDeviceId(dev)
        #self.logger.debug("ExtendFileInode: %s %s %s %s", parent, inode, current, old)
        cursor = self._execute("UPDATE FILES "
                               "SET LastSet = :new "
                               "WHERE Parent = :parent AND ParentDev = :parentDev AND Inode = :inode AND Device = :device AND "
                               ":old BETWEEN FirstSet AND LastSet",
                               {"parent": parIno, "parentDev": parDevId, "inode": ino, "device": devId, "old": old, "new": current})
        return cursor.rowcount

    @authenticate
    def cloneDir(self, parent, new=True, old=False):
        newBSet = self._bset(new)
        oldBSet = self._bset(old)
        (parIno, parDev) = parent
        parDev = self._getDeviceId(parDev)
        self.logger.debug("Cloning directory inode %d, %d from %d to %d", parIno, parDev, oldBSet, newBSet)
        cursor = self._execute("UPDATE FILES "
                               "SET LastSet = :new "
                               "WHERE Parent = :parent AND ParentDev = :parentDev AND "
                               ":old BETWEEN FirstSet AND LastSet",
                               {"new": newBSet, "old": oldBSet, "parent": parIno, "parentDev": parDev})
        return cursor.rowcount

    @functools.lru_cache(16 * 1024)
    def _getNameId(self, name, insert=True):
        row = self._executeWithResult("SELECT NameId FROM Names WHERE Name = :name", {"name": name})
        if row:
            return row['NameId']

        if insert:
            c = self._execute("INSERT INTO Names (Name) VALUES (:name)", {"name": name})
            return c.lastrowid

        return None

    @authenticate
    def insertChecksum(self, checksum, encrypted=False, size=0, basis=None, deltasize=None, compressed='None', disksize=None, current=True, isFile=True):
        self.logger.debug("Inserting checksum file: %s -- %d bytes, Compressed %s", checksum, size, str(compressed))
        added = self._bset(current)

        if basis is None:
            chainlength = 0
        else:
            chainlength = self.getChainLength(basis) + 1

        c =self._execute("INSERT INTO CheckSums (CheckSum,  Size,  Basis,  Encrypted,  DeltaSize,  Compressed,  DiskSize,  ChainLength,  Added,  IsFile) "
                            "VALUES                (:checksum, :size, :basis, :encrypted, :deltasize, :compressed, :disksize, :chainlength, :added, :isfile)",
                            {"checksum": checksum, "size": size, "basis": basis, "encrypted": encrypted, "deltasize": deltasize,
                             "compressed": str(compressed), "disksize": disksize, "chainlength": chainlength, "added": added, "isfile": int(isFile)})
        return c.lastrowid

    @authenticate
    def updateChecksumFile(self, checksum, encrypted=False, size=0, basis=None, deltasize=None, compressed=False, disksize=None, chainlength=0):
        self.logger.debug("Updating checksum file: %s -- %d bytes, Compressed %s", checksum, size, str(compressed))

        self._execute("UPDATE CheckSums SET "
                        "Size = :size, Encrypted = :encrypted, Basis = :basis, DeltaSize = :deltasize, ChainLength = :chainlength, "
                        "Compressed = :compressed, DiskSize = :disksize "
                        "WHERE Checksum = :checksum",
                        {"checksum": checksum, "size": size, "basis": basis, "encrypted": encrypted, "deltasize": deltasize,
                         "compressed": str(compressed), "chainlength": chainlength, "disksize": disksize})

    @authenticate
    def getChecksumInfo(self, checksum):
        self.logger.debug("Getting checksum info on: %s", checksum)
        row = self._executeWithResult("SELECT " +
                          _checksumInfoFields  +
                          "FROM Checksums WHERE CheckSum = :checksum",
                          {"checksum": checksum})
        if not row:
            self.logger.debug("No checksum found for %s", checksum)
        return row

    @authenticate
    def getChecksumInfoChain(self, checksum):
        """ Recover a list of all the checksums which need to be used to generate a file """
        self.logger.debug("Getting checksum info chain on: %s", checksum)
        chain = []
        while checksum:
            row = self.getChecksumInfo(checksum)
            if row:
                chain.append(row)
            else:
                return chain
            checksum = row['basis']

        return chain

    @authenticate
    def getNamesForChecksum(self, checksum):
        """ Recover a list of names that represent a checksum """
        self.logger.debug("Recovering name(s) for checksum %s", checksum)
        c = self._execute('SELECT Name FROM Names JOIN Files USING (NameId) JOIN Checksums USING (ChecksumID) '
                          'WHERE Checksums.Checksum = :checksum',
                          {'checksum': checksum})
        names = []
        for row in c.fetchall():
            self.logger.debug("Found name %s", row[0])
            names.append(row[0])
        return names

    @authenticate
    def getChainLength(self, checksum):
        data = self.getChecksumInfo(checksum)
        if data:
            return data['chainlength']
        return -1

        """
        Could do this, but not all versions of SQLite3 seem to support "WITH RECURSIVE" statements
        c = self._execute("WITH RECURSIVE x(n) AS (VALUES(:checksum) UNION SELECT Basis FROM Checksums, x WHERE x.n=Checksums.Checksum) "
                         "SELECT COUNT(*) FROM Checksums WHERE Checksum IN x",
                         {"checksum": checksum})
        r = c.fetchone()
        if r:
            return int(r[0])
        else:
            return -1
        """

    @authenticate
    def readDirectory(self, dirNode, current=False):
        (inode, device) = dirNode
        backupset = self._bset(current)
        device = self._getDeviceId(device)

        c = self._execute("SELECT " + _fileInfoFields + ", C1.Basis AS basis, C1.Encrypted AS encrypted " +
                          _fileInfoJoin +
                          "WHERE Parent = :parent AND ParentDev = :parentDev AND "
                          ":backup BETWEEN Files.FirstSet AND Files.LastSet",
                          {"parent": inode, "parentDev": device, "backup": backupset})
        return _fetchEm(c)

    @authenticate
    def getNumDeltaFilesInDirectory(self, dirNode, current=False):
        (inode, device) = dirNode
        backupset = self._bset(current)
        device = self._getDeviceId(device)
        row = self._executeWithResult("SELECT COUNT(*) FROM Files "
                                      "JOIN Names USING (NameID) "
                                      "LEFT OUTER JOIN Checksums AS C1 USING (ChecksumId) "
                                      "WHERE Parent = :parent AND ParentDev = :parentDev AND "
                                      ":backup BETWEEN Files.FirstSet AND Files.LastSet AND "
                                      "C1.ChainLength != 0",
                                      {"parent": inode, "parentDev": device, "backup": backupset})
        if row:
            return row[0]
        return 0

    @authenticate
    def getDirectorySize(self, dirNode, current=False):
        (inode, device) = dirNode
        backupset = self._bset(current)
        device = self._getDeviceId(device)
        row = self._executeWithResult("SELECT COUNT(*) FROM Files "
                                      "WHERE Parent = :parent AND ParentDev = :parentDev AND "
                                      ":backup BETWEEN Files.FirstSet AND Files.LastSet AND "
                                      "(Dir = 1 OR ChecksumId IS NOT NULL)",
                                      {"parent": inode, "parentDev": device, "backup": backupset})
        if row:
            return row[0]
        return 0

    @authenticate
    def readDirectoryForRange(self, dirNode, first, last):
        (inode, device) = dirNode
        device = self._getDeviceId(device)
        c = self._execute("SELECT " + _fileInfoFields + ", "
                          "C1.Basis AS basis, C1.Encrypted AS encrypted " +
                          _fileInfoJoin +
                          "WHERE Parent = :parent AND ParentDev = :parentDev AND "
                          "Files.LastSet >= :first AND Files.FirstSet <= :last",
                          {"parent": inode, "parentDev": device, "first": first, "last": last})
        return _fetchEm(c)

    @authenticate
    def listBackupSets(self):
        #                 "Name AS name, BackupSet AS backupset "
        c = self._execute("SELECT " +
                          _backupSetInfoFields +
                          _backupSetInfoJoin +
                          "ORDER BY backupset ASC", {})
        return _fetchEm(c)

    @authenticate
    def getBackupSetInfoById(self, bset):
        c = self._execute("SELECT " +
                          _backupSetInfoFields +
                          _backupSetInfoJoin +
                          "WHERE BackupSet = :bset",
                          {"bset": bset})
        row = c.fetchone()
        return row

    @authenticate
    def getBackupSetInfoByTag(self, tag):
        bset = self._executeWithResult("SELECT BackupSet FROM Tags JOIN Names USING (NameId) WHERE Names.name = :tag", {"tag": tag})
        if bset is None:
            # No such backup set.
            return None

        # Retrieve the data corresponding to that tag
        return self.getBackupSetInfoById(bset[0])

    @authenticate
    def getBackupSetInfo(self, name):
        c = self._execute("SELECT " +
                          _backupSetInfoFields +
                          _backupSetInfoJoin +
                          "WHERE Name = :name",
                          {"name": name})
        row = c.fetchone()
        return row

    @authenticate
    def getBackupSetInfoForTime(self, when):
        c = self._execute("SELECT " +
                          _backupSetInfoFields +
                          _backupSetInfoJoin +
                          "WHERE BackupSet = (SELECT MAX(BackupSet) FROM Backups WHERE StartTime <= :time)",
                          {"time": when})
        row = c.fetchone()
        return row

    @authenticate
    def getBackupSetDetails(self, bset):
        row = self._executeWithResult("SELECT COUNT(*), SUM(Size) FROM Files JOIN Checksums USING (ChecksumID) WHERE Dir = 0 AND :bset BETWEEN FirstSet AND LastSet", {'bset': bset})
        files = row[0]
        size = row[1] if row[1] else 0

        row = self._executeWithResult("SELECT COUNT(*) FROM Files WHERE Dir = 1 AND :bset BETWEEN FirstSet AND LastSet", {'bset': bset})
        dirs = row[0]

        # Figure out the first set after this one, and the last set before this one
        row = self._executeWithResult("SELECT MAX(BackupSet) FROM Backups WHERE BackupSet < :bset", {'bset': bset})
        prevSet = row[0] if row else 0

        row = self._executeWithResult("SELECT MIN(BackupSet) FROM Backups WHERE BackupSet > :bset", {'bset': bset})
        nextSet = row[0] if row[0] else sys.maxsize

        self.logger.debug("PrevSet: %s, NextSet: %s", prevSet, nextSet)
        # Count of files that first appeared in this version.  May be delta's
        row = self._executeWithResult("SELECT COUNT(*), SUM(Size), SUM(DiskSize) FROM Files JOIN Checksums USING (ChecksumID) "
                                      "WHERE Dir = 0 AND FirstSet > :prevSet",
                                      {'prevSet': prevSet})
        newFiles = row[0] if row[0] else 0
        newSize  = row[1] if row[1] else 0
        newSpace = row[2] if row[2] else 0

        # Count of files that are last seen in this set, and are not part of somebody else's basis
        row = self._executeWithResult("SELECT COUNT(*), SUM(Size), SUM(DiskSize) FROM Files JOIN Checksums USING (ChecksumID) "
                                      "WHERE Dir = 0 AND LastSet < :nextSet "
                                      "AND Checksum NOT IN (SELECT Basis FROM Checksums WHERE Basis IS NOT NULL)",
                                      {'nextSet': nextSet})
        endFiles = row[0] if row[0] else 0
        endSize  = row[1] if row[1] else 0
        endSpace = row[2] if row[2] else 0

        return (files, dirs, size, (newFiles, newSize, newSpace), (endFiles, endSize, endSpace))


    @authenticate
    def getNewFiles(self, bset, other):
        if other:
            row = self._executeWithResult("SELECT max(BackupSet) FROM Backups WHERE BackupSet < :bset", {'bset': bset})
            pset = row[0]
        else:
            pset = bset
        self.logger.debug("Getting new files for changesets %s -> %s", pset, bset)
        cursor = self._execute("SELECT " + _fileInfoFields + _fileInfoJoin +
                               "WHERE Files.FirstSet BETWEEN :pset AND :bset",
                               {'bset': bset, 'pset': pset})
        return _fetchEm(cursor)

    @authenticate
    def getFileSizes(self, minsize):
        cursor = self._execute("SELECT DISTINCT(Size) FROM Checksums WHERE Size > :minsize", {"minsize": minsize})
        return _fetchEm(cursor)

    @authenticate
    def setStats(self, newFiles, deltaFiles, bytesReceived, current=True):
        bset = self._bset(current)
        self._execute("UPDATE Backups SET FilesFull = :full, FilesDelta = :delta, BytesReceived = :bytes WHERE BackupSet = :bset",
                      {"bset": bset, "full": newFiles, "delta": deltaFiles, "bytes": bytesReceived})

    @authenticate
    def getConfigValue(self, key, default=None):
        return self._getConfigValue(key, default)

    def _getConfigValue(self, key, default=None):
        self.logger.debug("Getting Config Value %s", key)
        c = self._execute("SELECT Value FROM Config WHERE Key = :key", {'key': key})
        row = c.fetchone()
        return row[0] if row else default

    @authenticate
    def setConfigValue(self, key, value):
        self._setConfigValue(key, value)

    def _setConfigValue(self, key, value):
        if value is None:
            self._execute("DELETE FROM Config WHERE Key LIKE :key", {'key': key})
        else:
            self._execute("INSERT OR REPLACE INTO Config (Key, Value) VALUES(:key, :value)", {'key': key, 'value': value})

    @authenticate
    def delConfigValue(self, key):
        self._execute("DELETE FROM Config WHERE Key = :key", {'key': key})

    @authenticate
    def setPriority(self, bSet, priority):
        backup = self._bset(bSet)
        self.logger.debug("Setting backupset priority to %d for backupset %s", priority, backup)
        self._execute("UPDATE Backups SET Priority = :priority WHERE BackupSet = :backup",
                      {'priority': priority, 'backup': backup})

    @authenticate
    def setSrpValues(self, salt, vkey):
        self.setConfigValue('SRPSalt', hexlify(salt))
        self.setConfigValue('SRPVkey', hexlify(vkey))

    def getSrpValues(self):
        self.logger.debug("Getting SRP Values")
        salt = self._getConfigValue('SRPSalt')
        vkey = self._getConfigValue('SRPVkey')
        if salt:
            salt = unhexlify(salt)
        if vkey:
            vkey = unhexlify(vkey)
        return salt, vkey

    def getCryptoScheme(self):
        self.logger.debug("Getting CryptoScheme")
        return self._getConfigValue('CryptoScheme')

    @authenticate
    def setKeys(self, salt, vkey, filenameKey, contentKey, backup=True):
        try:
            self.beginTransaction()
            self.setSrpValues(salt, vkey)
            if filenameKey:
                self.setConfigValue('FilenameKey', filenameKey)
            else:
                self.delConfigValue('FilenameKey')
            if contentKey:
                self.setConfigValue('ContentKey', contentKey)
            else:
                self.delConfigValue('ContentKey')
            if backup:
                # Attempt to save the keys away
                backupName = self.dbfile + ".keys"
                r = Rotator.Rotator(rotations=0)
                r.backup(backupName)
                Util.saveKeys(backupName, self.clientId, filenameKey, contentKey, base64.b64encode(salt).decode('utf8'), base64.b64encode(vkey).decode('utf8'))
            self.commit()
            if backup:
                r.rotate(backupName)
            return True
        except Exception as e:
            self.logger.error("Setkeys failed: %s", e)
            self.logger.exception(e)
            return False

    @authenticate
    def getKeys(self):
        return (self.getConfigValue('FilenameKey'), self.getConfigValue('ContentKey'))

    @authenticate
    def beginTransaction(self):
        self._execute("BEGIN")

    @authenticate
    def commit(self):
        self.conn.commit()

    @authenticate
    def completeBackup(self):
        self._execute("UPDATE Backups SET Completed = 1 WHERE BackupSet = :backup", {"backup": self.currBackupSet})
        self.commit()

    def _purgeFiles(self):
        c = self._execute("DELETE FROM Files WHERE "
                            "0 = (SELECT COUNT(*) FROM Backups WHERE Backups.BackupSet BETWEEN Files.FirstSet AND Files.LastSet)")
        return c.rowcount

    @authenticate
    def listPurgeSets(self, priority, timestamp, current=False):
        """ List all backup older than the date """
        backupset = self._bset(current)
        # Select all sets that are purgeable.
        c = self._execute("SELECT " +
                          _backupSetInfoFields + _backupSetInfoJoin +
                          " WHERE Priority <= :priority AND EndTime <= :timestamp AND BackupSet < :backupset AND Locked = 0",
                          {"priority": priority, "timestamp": str(timestamp), "backupset": backupset})
        return _fetchEm(c)

    @authenticate
    def listPurgeIncomplete(self, priority, timestamp, current=False):
        """ List incomplete backupsets to purge """
        backupset = self._bset(current)
        # Select all sets that are both purgeable and incomplete
        # Note: For some reason that I don't understand, the timestamp must be cast into a string here, to work with the coalesce operator
        # If it comes from the HTTPInterface as a string, the <= timestamp doesn't seem to work.
        c = self._execute("SELECT " + _backupSetInfoFields + _backupSetInfoJoin +
                          "WHERE Priority <= :priority AND COALESCE(EndTime, StartTime) <= :timestamp AND BackupSet < :backupset AND Completed = 0",
                          {"priority": priority, "timestamp": str(timestamp), "backupset": backupset})
        return _fetchEm(c)

    @authenticate
    def purgeSets(self, priority, timestamp, current=False):
        """ Purge old files from the database.  Needs to be followed up with calls to remove the orphaned files """
        backupset = self._bset(current)
        self.logger.debug("Purging backupsets below priority %d, before %s, and backupset: %d", priority, timestamp, backupset)
        # First, purge out the backupsets that don't match
        c = self._execute("DELETE FROM Backups WHERE Priority <= :priority AND EndTime <= :timestamp AND BackupSet < :backupset AND Locked = 0",
                          {"priority": priority, "timestamp": str(timestamp), "backupset": backupset})
        setsDeleted = c.rowcount
        # Then delete the files which are no longer referenced
        filesDeleted = self._purgeFiles()

        return (filesDeleted, setsDeleted)

    @authenticate
    def purgeIncomplete(self, priority, timestamp, current=False):
        """ Purge old files from the database.  Needs to be followed up with calls to remove the orphaned files """
        backupset = self._bset(current)
        self.logger.debug("Purging incomplete backupsets below priority %d, before %s, and backupset: %d", priority, timestamp, backupset)
        # First, purge out the backupsets that don't match
        c = self._execute("DELETE FROM Backups WHERE Priority <= :priority AND COALESCE(EndTime, StartTime) <= :timestamp AND BackupSet < :backupset AND Completed = 0 AND Locked = 0",
                          {"priority": priority, "timestamp": str(timestamp), "backupset": backupset})
        setsDeleted = c.rowcount

        # Then delete the files which are no longer referenced
        filesDeleted = self._purgeFiles()

        return (filesDeleted, setsDeleted)

    @authenticate
    def deleteBackupSet(self, current=False):
        bset = self._bset(current)
        self._execute("DELETE FROM Tags WHERE BackupSet = :backupset", {"backupset": bset})
        self._execute("DELETE FROM Backups WHERE BackupSet = :backupset", {"backupset": bset})
        # TODO: Move this to the removeOrphans phase
        # Then delete the files which are no longer referenced
        filesDeleted = self._purgeFiles()

        return filesDeleted

    @authenticate
    def listOrphanChecksums(self, isFile):
        c = self._execute("SELECT Checksum FROM Checksums "
                              "WHERE ChecksumID NOT IN (SELECT DISTINCT(ChecksumID) FROM Files WHERE ChecksumID IS NOT NULL) "
                              "AND   ChecksumID NOT IN (SELECT DISTINCT(XattrId) FROM Files WHERE XattrID IS NOT NULL) "
                              "AND   ChecksumID NOT IN (SELECT DISTINCT(AclId) FROM Files WHERE AclId IS NOT NULL) "
                              "AND   ChecksumID NOT IN (SELECT DISTINCT(CmdLineID) FROM Backups WHERE CmdLineID IS NOT NULL) "
                              "AND   Checksum   NOT IN (SELECT DISTINCT(Basis) FROM Checksums WHERE Basis IS NOT NULL) "
                              "AND IsFile = :isfile",
                              {'isfile': int(isFile)})
        return map(lambda row: row[0], _fetchEm(c))

    @authenticate
    def deleteOrphanChecksums(self, isFile):
        c = self._execute("DELETE FROM Checksums "
                          "WHERE ChecksumID NOT IN (SELECT DISTINCT(ChecksumID) FROM Files WHERE ChecksumID IS NOT NULL) "
                          "AND   ChecksumID NOT IN (SELECT DISTINCT(XattrId) FROM Files WHERE XattrID IS NOT NULL) "
                          "AND   ChecksumID NOT IN (SELECT DISTINCT(AclId) FROM Files WHERE AclId IS NOT NULL) "
                          "AND   ChecksumID NOT IN (SELECT DISTINCT(CmdLineID) FROM Backups WHERE CmdLineID IS NOT NULL) "
                          "AND   Checksum   NOT IN (SELECT DISTINCT(Basis) FROM Checksums WHERE Basis IS NOT NULL) "
                          "AND IsFile = :isfile",
                          {'isfile': int(isFile)})
        return c.rowcount

    @authenticate
    def compact(self):
        self.logger.debug("Removing unused names")
        # Purge out any unused names
        c = self._execute("DELETE FROM Names WHERE NameID NOT IN (SELECT NameID FROM Files UNION SELECT NameID FROM Tags UNION SELECT NameID FROM Users UNION SELECT NameID FROM Groups)")
        rows = c.rowcount
        vacuumed = False

        # Check if we've hit an interval where we want to do a vacuum
        bset = self._bset(True)
        interval = self.getConfigValue("VacuumInterval")
        if interval and (bset % int(interval)) == 0:
            self.logger.debug("Vaccuuming database")
            # And clean up the database
            self.conn.commit()  # Just in case there's a transaction outstanding, for no apparent reason
            self._execute("VACUUM")
            vacuumed = True
        self._execute("UPDATE Backups SET Vacuumed = :vacuumed WHERE BackupSet = :backup", {"backup": self.currBackupSet, "vacuumed": vacuumed})

        return rows

    @authenticate
    def enumerateChecksums(self, isFile=True):
        c = self._execute("SELECT Checksum FROM Checksums WHERE IsFile = :isfile ORDER BY Checksum", {"isfile": int(isFile)})
        return map(lambda row: row[0], _fetchEm(c))

    @authenticate
    def getChecksumCount(self, isFile=True):
        r = self._executeWithResult("SELECT COUNT(*) FROM Checksums WHERE IsFile = :isfile", {"isfile": int(isFile)})
        return r[0]

    @authenticate
    def deleteChecksum(self, checksum):
        self.logger.debug("Deleting checksum: %s", checksum)
        c = self._execute("DELETE FROM Checksums WHERE Checksum = :checksum", {"checksum": checksum})
        return c.rowcount

    @authenticate
    def setClientEndTime(self):
        if self.currBackupSet:
            self._execute("UPDATE Backups SET ClientEndTime = :now WHERE BackupSet = :backup",
                          {"now": time.time(), "backup": self.currBackupSet})

    @authenticate
    def setTag(self, tag, current=False):
        backupset = self._bset(current)
        nameid = self._getNameId(tag)
        try:
            self._execute("INSERT INTO Tags (BackupSet, NameId) VALUES (:backup, :nameid)", {"backup": backupset, "nameid": nameid})
            return True
        except sqlite3.IntegrityError:
            return False

    @authenticate
    def removeTag(self, tag):
        nameid = self._getNameId(tag, False)
        if nameid:
            self._execute("DELETE FROM Tags WHERE NameID = :nameid", {"nameid": nameid})
            return True
        return False

    @authenticate
    def getTags(self, bset):
        c = self._execute("SELECT Name FROM Names JOIN Tags USING (NameId) WHERE Tags.Backupset = :bset", {"bset": bset})
        tags = []
        row = c.fetchone()
        while row:
            tags.append(row['Name'])
            row = c.fetchone()
        return tags

    @authenticate
    def getUsers(self):
        c = self._execute("SELECT UserID, Name, Users.NameId FROM Users LEFT OUTER JOIN Names USING(NameId)", {})
        return _fetchEm(c)

    @authenticate
    def setUserInfo(self, userId, name):
        nameId = self._getNameId(name)
        self._execute("UPDATE Users SET NameId = :nameid WHERE UserID = :userId", {"nameid": nameId, "userId": userId})
        # Not sure why we need this, but the remote interface gets cranky if we don't commit.
        self.commit()

    @authenticate
    def getGroups(self):
        c = self._execute("SELECT GroupId, Name, Groups.NameId FROM Groups LEFT OUTER JOIN Names USING(NameId)", {})
        return _fetchEm(c)

    @authenticate
    def setGroupInfo(self, groupId, name):
        nameId = self._getNameId(name)
        self._execute("UPDATE Groups SET NameId = :nameid WHERE GroupID = :groupId", {"nameid": nameId, "groupId": groupId})
        # Not sure why we need this, but the remote interface gets cranky if we don't commit.
        self.commit()

    @authenticate
    def setLock(self, locked, current=False):
        bset = self._bset(current)
        self._execute("UPDATE Backups SET Locked = :locked WHERE BackupSet = :bset", {"locked": locked, "bset": bset})

    @authenticate
    def setFailure(self, ex):
        if self.currBackupSet:
            self._execute("UPDATE Backups SET Exception = :ex, ErrorMsg = :msg WHERE BackupSet = :backup",
                          {"ex": type(ex).__name__, "msg": str(ex), "backup": self.currBackupSet})

    def close(self, completeBackup=False):
        if self._isAuthenticated():
            if self.currBackupSet:
                self._execute("UPDATE Backups SET EndTime = :now WHERE BackupSet = :backup",
                              {"now": time.time(), "backup": self.currBackupSet})
            self.conn.commit()

            if self.backup and completeBackup:
                r = Rotator.Rotator(rotations=self.numbackups)
                try:
                    r.backup(self.dbfile)
                    r.rotate(self.dbfile)
                except Exception as e:
                    self.logger.error("Error detected creating database backup: %s", e)

        # And close it
        if self.conn:
            self.conn.close()
            self.conn = None

    def __del__(self):
        if self.conn:
            self.close()

    def _isAuthenticated(self):
        if self.authenticated:
            return True
        if self.srpSrv is not None:
            return self.srpSrv.authenticated()
        return False
