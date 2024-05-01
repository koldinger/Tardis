# vim: set et sw=4 sts=4 fileencoding=utf-8:

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

import sqlite3
import logging
import os
import os.path
import time
import sys
import uuid
import functools
import importlib
import gzip
import base64
from binascii import hexlify, unhexlify

import srp

import Tardis
from . import ConnIdLogAdapter
from . import Rotator
from . import Util

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

# Utility functions
def authenticate(func):
    @functools.wraps(func)
    def doit(self, *args, **kwargs):
        if self._isAuthenticated():
            return func(self, *args, **kwargs)
        raise NotAuthenticated("Not authenticated to database.")
    return doit

# Be sure to end all these lists with a space.

_fileInfoFields =  "Name AS name, Inode AS inode, Device AS device, Dir AS dir, Link AS link, " \
                   "Parent AS parent, ParentDev AS parentdev, C1.Size AS size, " \
                   "MTime AS mtime, CTime AS ctime, ATime AS atime, Mode AS mode, UID AS uid, GID AS gid, NLinks AS nlinks, " \
                   "FirstSet AS firstset, LastSet AS lastset, C1.Checksum AS checksum, C1.ChainLength AS chainlength, C1.DiskSize AS disksize, " \
                   "C2.Checksum AS xattrs, C3.Checksum AS acl "

_fileInfoJoin =    "FROM Files " \
                   "JOIN Names ON Files.NameId = Names.NameId " \
                   "LEFT OUTER JOIN Checksums AS C1 ON Files.ChecksumId = C1.ChecksumId " \
                   "LEFT OUTER JOIN Checksums AS C2 ON Files.XattrId = C2.ChecksumId " \
                   "LEFT OUTER JOIN Checksums AS C3 ON Files.AclId = C3.ChecksumId "

_backupSetInfoFields = "BackupSet AS backupset, StartTime AS starttime, EndTime AS endtime, ClientTime AS clienttime, " \
                       "Priority AS priority, Completed AS completed, Session AS session, Name AS name, Locked AS locked, " \
                       "ClientVersion AS clientversion, ClientIP AS clientip, ServerVersion AS serverversion, Full AS full, " \
                       "FilesFull AS filesfull, FilesDelta AS filesdelta, BytesReceived AS bytesreceived, Checksum AS commandline, "\
                       "Exception AS exception, ErrorMsg AS errormsg "

_backupSetInfoJoin = "FROM Backups LEFT OUTER JOIN Checksums ON Checksums.ChecksumID = Backups.CmdLineId "

_checksumInfoFields = "Checksum AS checksum, ChecksumID AS checksumid, Basis AS basis, Encrypted AS encrypted, " \
                      "Size AS size, DeltaSize AS deltasize, DiskSize AS disksize, IsFile AS isfile, Compressed AS compressed, ChainLength AS chainlength "

_schemaVersion = 20

def _addFields(x, y):
    """ Add fields to the end of a dict """
    return dict(list(y.items()) + x)

def _splitpath(path):
    """ Split a path into chunks, recursively """
    (head, tail) = os.path.split(path)
    return _splitpath(head) + [ tail ] if head and head != path else [ head or tail ]

def _fetchEm(cursor):
    while True:
        batch = cursor.fetchmany(10000)
        if not batch:
            break
        for row in batch:
            yield row

conversionModules = {}

# Class TardisDB

class TardisDB:
    """ Main source for all interaction with the Tardis DB """
    conn    = None
    cursor  = None
    dbName  = None
    db              = None
    currBackupSet   = None
    prevBackupSet   = None
    dirinodes       = {}
    backup          = False
    clientId        = None
    chunksize       = 1000
    journal         = None
    srpSrv          = None
    authenticated   = False

    def __init__(self, dbname, backup=False, prevSet=None, initialize=None, connid=None, user=-1, group=-1, chunksize=1000, numbackups=2, journal=None, allow_upgrade=False, check_threads=True):
        """ Initialize the connection to a per-machine Tardis Database"""
        self.logger  = logging.getLogger("DB")
        self.logger.debug("Initializing connection to %s", dbname)
        self.dbName = dbname
        self.chunksize = chunksize
        self.prevSet = prevSet
        self.journalName = journal
        self.allow_upgrade = allow_upgrade

        if user  is None: user = -1
        if group is None: group = -1

        self.user = user
        self.group = group

        if connid:
            self.logger = ConnIdLogAdapter.ConnIdLogAdapter(self.logger, connid)

        self.backup = backup
        self.numbackups = numbackups

        conn = sqlite3.connect(self.dbName, check_same_thread=check_threads)
        conn.text_factory = lambda x: x.decode('utf-8', 'backslashreplace')
        conn.row_factory = TardisRow

        self.conn = conn
        self.cursor = self.conn.cursor()

        if initialize:
            self.logger.info("Creating database from schema: %s", initialize)
            try:
                with open(initialize, "r") as f:
                    script = f.read()
                    self.conn.executescript(script)
            except IOError:
                self.logger.error("Could not read initialization script %s", initialize)
                #self.logger.exception(e)
                raise
            except sqlite3.Error:
                self.logger.error("Could not execute initialization script %s", initialize)
                #self.logger.exception(e)
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
        #self.logger.debug("Beginning authentication: %s %s %s %s", hexlify(uname), hexlify(salt), hexlify(vkey), hexlify(srpValueA))
        self.srpSrv = srp.Verifier(uname, salt, vkey, srpValueA)
        s, B = self.srpSrv.get_challenge()
        if s is None or B is None:
            raise AuthenticationFailed("Password doesn't match")
        #self.logger.debug("Authentication Challenge: %s %s", hexlify(s), hexlify(B))
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

        version = self._getConfigValue('SchemaVersion')
        if int(version) != _schemaVersion:
            if self.allow_upgrade:
                self.logger.warning("Schema version mismatch: Upgrading.  Database %s is %d:  Expected %d.", self.dbName, int(version), _schemaVersion)
                self.upgradeSchema(int(version))
            else:
                self.logger.error("Schema version mismatch: Database %s is %d:  Expected %d.   Please convert", self.dbName, int(version), _schemaVersion)
                raise Exception(f"Schema version mismatch: Database {self.dbName} is {version}:  Expected {_schemaVersion}.   Please convert")

        if self.prevSet:
            f = self.getBackupSetInfo(self.prevSet)
            if f:
                self.prevBackupSet  = f['backupset']
                self.prevBackupDate = f['starttime']
                self.lastClientTime = f['clienttime']
                self.prevBackupName = self.prevSet
            #self.cursor.execute = ("SELECT Name, BackupSet FROM Backups WHERE Name = :backup", {"backup": prevSet})
        else:
            b = self.lastBackupSet()
            self.prevBackupName = b['name']
            self.prevBackupSet  = b['backupset']
            self.prevBackupDate = b['starttime']
            self.lastClientTime = b['clienttime']
            #self.cursor.execute("SELECT Name, BackupSet FROM Backups WHERE Completed = 1 ORDER BY BackupSet DESC LIMIT 1")

        self.clientId = self.getConfigValue('ClientID')

        self.logger.debug("Last Backup Set: %s %d ", self.prevBackupName, self.prevBackupSet)

        self.conn.commit()

        self.conn.execute("PRAGMA synchronous=false")
        self.conn.execute("PRAGMA foreignkeys=true")

        if self.journalName:
            if self.journalName.endswith('.gz'):
                self.journal = gzip.open(self.journalName, 'at')
            else:
                self.journal = open(self.journalName, 'a')

        # Make sure the permissions are set the way we want, if that's specified.
        if self.user != -1 or self.group != -1:
            os.chown(self.dbName, self.user, self.group)

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
            name = f'convert{i}to{i+1}'
            #from schema import name name
            converter = self._getConverter(name)
            self.logger.debug("Running conversion script from version %d, %s", i, name)
            converter.upgrade(self.conn, self.logger)
            self.logger.warning("Upgraded schema to version %d", i + 1)

    @authenticate
    def lastBackupSet(self, completed=True):
        """ Select the last backup set. """
        if completed:
            c = self.cursor.execute("SELECT " +
                                    _backupSetInfoFields +
                                    _backupSetInfoJoin +
                                    "WHERE Completed = 1 ORDER BY BackupSet DESC LIMIT 1")
        else:
            c = self.cursor.execute("SELECT " +
                                    _backupSetInfoFields +
                                    _backupSetInfoJoin +
                                    "ORDER BY BackupSet DESC LIMIT 1")
        row = c.fetchone()
        return row

    def _execute(self, query, data):
        try:
            ret = self.conn.execute(query, data)
            return ret
        except sqlite3.IntegrityError as e:
            self.logger.warning("Error processing data: %s %s", data, e)
            raise e

    def _executeWithResult(self, query, data):
        c = self._execute(query, data)
        r = c.fetchone()
        return r

    @authenticate
    def newBackupSet(self, name, session, priority, clienttime, version=None, ip=None, full=False, serverID=None):
        """ Create a new backupset.  Set the current backup set to be that set. """
        c = self.cursor
        now = time.time()
        try:
            c.execute("INSERT INTO Backups "
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
                        }
                    )
        except sqlite3.IntegrityError:
            raise Exception(f"Backupset {name} already exists")

        self.currBackupSet = c.lastrowid

        if name is None:
            name = f"INCOMPLETE-{self.currBackupSet}"
            self.setBackupSetName(name, priority)

        self.currBackupName = name
        self.conn.commit()
        self.logger.info("Created new backup set: %d: %s %s", self.currBackupSet, name, session)
        if self.journal:
            # self.journal.write("===== S: {} {} {} D: {} V:{} {}\n".format(self.currBackupSet, name, session, time.strftime("%Y-%m-%d %H:%M:%S"), version, Tardis.__buildversion__))
            self.journal.write(f"===== S: {self.currBackupSet} {name} {session} D: {time.strftime('%Y-%m-%d %H:%M:%S')} V:{version} {Tardis.__buildversion__}\n")

        return self.currBackupSet

    @authenticate
    def setBackupSetName(self, name, priority, current=True):
        """ Change the name of a backupset.  Return True if it can be changed, false otherwise. """
        backupset = self._bset(current)
        try:
            self.conn.execute("UPDATE Backups SET Name = :name, Priority = :priority WHERE BackupSet = :backupset",
                              {"name": name, "priority": priority, "backupset": backupset})
            return True
        except sqlite3.IntegrityError:
            return False

    @authenticate
    def setClientConfig(self, config, current=True):
        """ Store the full client configuration in the database """
        backupset = self._bset(current)
        r = self._executeWithResult("SELECT ClientConfigID FROM ClientConfig WHERE ClientConfig = :config", {"config": config})
        if r is None:
            c = self._execute("INSERT INTO ClientConfig (ClientConfig) VALUES (:config)", {"config": config})
            clientConfigId = c.lastrowid
        else:
            clientConfigId = r[0]
        self._execute("UPDATE Backups SET ClientConfigID = :configId WHERE BackupSet = :backupset", {"configId": clientConfigId, "backupset": backupset})

    @authenticate
    def setCommandLine(self, cksum, current=True):
        """ Set a command line variable in the database """
        backupset = self._bset(current)
        self._execute("UPDATE Backups SET CmdLineID = :cksid WHERE BackupSet = :backupset", {'cksid': cksum, 'backupset': backupset})

    @authenticate
    def checkBackupSetName(self, name):
        """ Check to see if a backupset by this name exists. Return TRUE if it DOESN'T exist. """
        c = self.conn.execute("SELECT COUNT(*) FROM Backups WHERE Name = :name",
                              { "name": name })
        row = c.fetchone()
        return (row[0] == 0)

    @authenticate
    def getFileInfoByName(self, name, parent, current=True):
        """ Lookup a file in a directory in the previous backup set"""
        backupset = self._bset(current)
        (inode, device) = parent
        self.logger.debug(f"Looking up file by name {name} {parent} {backupset}")
        c = self.cursor
        c.execute("SELECT " +
                  _fileInfoFields +
                  #"FROM Files "
                  #"JOIN Names ON Files.NameId = Names.NameId "
                  #"LEFT OUTER JOIN Checksums ON Files.ChecksumId = Checksums.ChecksumId "
                  _fileInfoJoin +
                  "WHERE Name = :name AND Parent = :parent AND ParentDev = :parentDev AND "
                  ":backup BETWEEN FirstSet AND LastSet",
                  {"name": name, "parent": inode, "parentDev": device, "backup": backupset})
        return c.fetchone()

    @authenticate
    def getFileInfoByPath(self, path, current=False, permchecker=None):
        """ Lookup a file by a full path. """
        ### TODO: Could be a LOT faster without the repeated calls to getFileInfoByName
        backupset = self._bset(current)
        self.logger.debug(f"Looking up file by path {path} {backupset}")
        parent = (0, 0)         # Root directory value
        info = None

        #(dirname, name) = os.path.split(path)
        # Walk the path
        for name in _splitpath(path):
            if name == '/':
                continue
            info = self.getFileInfoByName(name, parent, backupset)
            if info:
                parent = (info["inode"], info["device"])
                if permchecker:
                    if not permchecker(info['uid'], info['gid'], info['mode']):
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
        #self.logger.debug("Looking up file by path {} {}".format(path, backupset))
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
        c = self.cursor
        c.execute("SELECT " +
                  _fileInfoFields + _fileInfoJoin +
                  "WHERE Inode = :inode AND Device = :device AND "
                  ":backup BETWEEN FirstSet AND LastSet",
                  {"inode": inode, "device": device, "backup": backupset})
        return c.fetchone()

    @authenticate
    def getFileInfoBySimilar(self, fileInfo, current=False):
        """ Find a file which is similar, namely the same size, inode, and mtime.  Identifies files which have moved. """
        backupset = self._bset(current)
        self.logger.debug("Looking up file for similar info: %s", fileInfo)
        temp = fileInfo.copy()
        temp["backup"] = backupset
        c = self.cursor.execute("SELECT " +
                                _fileInfoFields + _fileInfoJoin +
                                "WHERE Inode = :inode AND Device = :dev AND Mtime = :mtime AND C1.Size = :size AND "
                                ":backup BETWEEN Files.FirstSet AND Files.LastSet",
                                temp)
        return c.fetchone()

    @authenticate
    def getFileInfoByChecksum(self, checksum, current=False):
        """ Find a file which is similar, namely the same size, inode, and mtime.  Identifies files which have moved. """
        backupset = self._bset(current)
        self.logger.debug("Looking up file for similar info: %s", checksum)
        c = self.cursor.execute("SELECT " +
                                 _fileInfoFields + _fileInfoJoin +
                                 "WHERE C1.Checksum = :cksum AND :backup BETWEEN Files.FirstSet AND Files.LastSet",
                                 {'cksum': checksum, 'backup': backupset})
        while True:
            batch = c.fetchmany(self.chunksize)
            if not batch:
                break
            for row in batch:
                yield row

    @authenticate
    def getFileFromPartialBackup(self, fileInfo):
        """ Find a file which is similar, namely the same size, inode, and mtime.  Identifies files which have moved. """
        #self.logger.debug("Looking up file for similar info: %s", fileInfo)
        temp = fileInfo.copy()
        temp["backup"] = self.prevBackupSet         ### Only look for things newer than the last backup set
        #self.logger.info("getFileFromPartialBackup: %s", str(fileInfo))
        c = self.cursor.execute("SELECT " +
                                _fileInfoFields + _fileInfoJoin +
                                "WHERE Inode = :inode AND Device = :dev AND Mtime = :mtime AND C1.Size = :size AND "
                                "Files.LastSet >= :backup "
                                "ORDER BY Files.LastSet DESC LIMIT 1",
                                temp)
        return c.fetchone()

    @authenticate
    def getFileInfoByInodeFromPartial(self, inode):
        (ino, dev) = inode
        c = self.cursor.execute("SELECT " +
                                _fileInfoFields + _fileInfoJoin +
                                "WHERE Inode = :inode AND Device = :device AND "
                                "Files.LastSet >= :backup "
                                "ORDER BY Files.LastSet DESC LIMIT 1",
                                {"inode": ino, "device": dev, "backup": self.prevBackupSet })

        return c.fetchone()

    @authenticate
    def setChecksum(self, inode, device, checksum):
        self.cursor.execute("UPDATE Files SET ChecksumId = (SELECT ChecksumId FROM CheckSums WHERE CheckSum = :checksum) "
                            "WHERE Inode = :inode AND Device = :device AND "
                            ":backup BETWEEN FirstSet AND LastSet",
                            {"inode": inode, "device": device, "checksum": checksum, "backup": self.currBackupSet})
        return self.cursor.rowcount

    @authenticate
    def setXattrs(self, inode, device, checksum):
        self.cursor.execute("UPDATE Files SET XattrId = (SELECT ChecksumId FROM CheckSums WHERE CheckSum = :checksum) "
                            "WHERE Inode = :inode AND Device = :device AND "
                            ":backup BETWEEN FirstSet AND LastSet",
                            {"inode": inode, "device": device, "checksum": checksum, "backup": self.currBackupSet})
        #self.logger.info("Setting XAttr ID for %d to %s, %d rows changed", inode, checksum, self.cursor.rowcount)
        return self.cursor.rowcount

    @authenticate
    def setAcl(self, inode, device, checksum):
        self.cursor.execute("UPDATE Files SET AclId = (SELECT ChecksumId FROM CheckSums WHERE CheckSum = :checksum) "
                            "WHERE Inode = :inode AND Device = :device AND "
                            ":backup BETWEEN FirstSet AND LastSet",
                            {"inode": inode, "device": device, "checksum": checksum, "backup": self.currBackupSet})
        #self.logger.info("Setting ACL ID for %d to %s, %d rows changed", inode, checksum, self.cursor.rowcount)
        return self.cursor.rowcount


    @authenticate
    def getChecksumByInode(self, inode, device, current=True):
        backupset = self._bset(current)
        c = self.cursor.execute("SELECT "
                                "CheckSums.Checksum AS checksum "
                                "FROM Files JOIN CheckSums ON Files.ChecksumId = Checksums.ChecksumId "
                                "WHERE Files.INode = :inode AND Device = :device AND "
                                ":backup BETWEEN Files.FirstSet AND Files.LastSet",
                                { "backup" : backupset, "inode" : inode, "device": device })
        row = c.fetchone()
        return row[0] if row else None
        #if row: return row[0] else: return None

    @authenticate
    def getChecksumByName(self, name, parent, current=False):
        backupset = self._bset(current)
        (inode, device) = parent
        self.logger.debug("Looking up checksum for file %s (%d %d) in %d", name, inode, device, backupset)
        c = self._execute("SELECT CheckSums.CheckSum AS checksum "
                          "FROM Files "
                          "JOIN Names ON Files.NameID = Names.NameId "
                          "JOIN CheckSums ON Files.ChecksumId = CheckSums.ChecksumId "
                          "WHERE Names.Name = :name AND Files.Parent = :parent AND ParentDev = :parentDev AND "
                          ":backup BETWEEN Files.FirstSet AND Files.LastSet",
                          { "name": name, "parent": inode, "parentDev": device, "backup": backupset })
        row = c.fetchone()
        return row[0] if row else None
        #if row: return row[0] else: return None

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
    def getFirstBackupSet(self, name, current=False):
        backupset = self._bset(current)
        self.logger.debug("getFirstBackupSet (%d) %s", backupset, name)
        f = self.getFileInfoByPath(name, backupset)
        if f:
            c = self.conn.execute("SELECT Name FROM Backups WHERE BackupSet >= :first ORDER BY BackupSet ASC LIMIT 1",
                                  {"first": f["firstset"]})
            row = c.fetchone()
            if row:
                return row[0]
        # General purpose failure
        return None

    @authenticate
    def insertFile(self, fileInfo, parent):
        self.logger.debug("Inserting file: %s", fileInfo)
        (parIno, parDev) = parent
        fields = list({"backup": self.currBackupSet, "parent": parIno, "parentDev": parDev}.items())
        temp = _addFields(fields, fileInfo)
        self.setNameID([temp])
        self._execute("INSERT INTO Files "
                      "(NameId, FirstSet, LastSet, Inode, Device, Parent, ParentDev, Dir, Link, MTime, CTime, ATime,  Mode, UID, GID, NLinks) "
                      "VALUES  "
                      "(:nameid, :backup, :backup, :inode, :dev, :parent, :parentDev, :dir, :link, :mtime, :ctime, :atime, :mode, :uid, :gid, :nlinks)",
                      temp)

    @authenticate
    def updateDirChecksum(self, directory, cksid, current=True):
        bset = self._bset(current)
        (inode, device) = directory
        self._execute("UPDATE FILES "
                      "SET ChecksumID = :cksid "
                      "WHERE Inode = :inode AND DEVICE = :device AND :bset BETWEEN FirstSet AND LastSet",
                      {"inode": inode, "device": device, "cksid": cksid, "bset": bset})

    @authenticate
    def extendFile(self, parent, name, old=False, current=True):
        old = self._bset(old)
        current = self._bset(current)
        (parIno, parDev) = parent
        cursor = self._execute("UPDATE FILES "
                               "SET LastSet = :new "
                               "WHERE Parent = :parent AND ParentDev = :parentDev AND NameID = (SELECT NameID FROM Names WHERE Name = :name) AND "
                               ":old BETWEEN FirstSet AND LastSet",
                               { "parent": parIno, "parentDev": parDev , "name": name, "old": old, "new": current })
        return cursor.rowcount

    @authenticate
    def extendFileInode(self, parent, inode, old=False, current=True):
        old = self._bset(old)
        current = self._bset(current)
        (parIno, parDev) = parent
        (ino, dev) = inode
        #self.logger.debug("ExtendFileInode: %s %s %s %s", parent, inode, current, old)
        cursor = self._execute("UPDATE FILES "
                               "SET LastSet = :new "
                               "WHERE Parent = :parent AND ParentDev = :parentDev AND Inode = :inode AND Device = :device AND "
                               ":old BETWEEN FirstSet AND LastSet",
                               { "parent": parIno, "parentDev": parDev , "inode": ino, "device": dev, "old": old, "new": current })
        return cursor.rowcount

    @authenticate
    def cloneDir(self, parent, new=True, old=False):
        newBSet = self._bset(new)
        oldBSet = self._bset(old)
        (parIno, parDev) = parent
        self.logger.debug("Cloning directory inode %d, %d from %d to %d", parIno, parDev, oldBSet, newBSet)
        cursor = self._execute("UPDATE FILES "
                               "SET LastSet = :new "
                               "WHERE Parent = :parent AND ParentDev = :parentDev AND "
                               ":old BETWEEN FirstSet AND LastSet",
                               { "new": newBSet, "old": oldBSet, "parent": parIno, "parentDev": parDev })
        return cursor.rowcount

    def _getNameId(self, name, insert=True):
        c = self.cursor.execute("SELECT NameId FROM Names WHERE Name = :name", {"name": name})
        row = c.fetchone()
        if row:
            return row[0]
        if insert:
            self.cursor.execute("INSERT INTO Names (Name) VALUES (:name)", {"name": name})
            return self.cursor.lastrowid
        return None

    @authenticate
    def setNameID(self, files):
        for f in files:
            f['nameid'] = self._getNameId(f['name'])

    @authenticate
    def insertChecksum(self, checksum, encrypted=False, size=0, basis=None, deltasize=None, compressed='None', disksize=None, current=True, isFile=True):
        self.logger.debug("Inserting checksum file: %s -- %d bytes, Compressed %s", checksum, size, str(compressed))
        added = self._bset(current)

        def _xstr(x):
            return x if x is not None else ''

        if self.journal:
            self.journal.write(f"{checksum}:{_xstr(basis)}:{int(encrypted)}:{compressed}\n")

        if basis is None:
            chainlength = 0
        else:
            chainlength = self.getChainLength(basis) + 1

        self.cursor.execute("INSERT INTO CheckSums (CheckSum,  Size,  Basis,  Encrypted,  DeltaSize,  Compressed,  DiskSize,  ChainLength,  Added,  IsFile) "
                            "VALUES                (:checksum, :size, :basis, :encrypted, :deltasize, :compressed, :disksize, :chainlength, :added, :isfile)",
                            {"checksum": checksum, "size": size, "basis": basis, "encrypted": encrypted, "deltasize": deltasize,
                             "compressed": str(compressed), "disksize": disksize, "chainlength": chainlength, "added": added, "isfile": int(isFile)})
        return self.cursor.lastrowid

    @authenticate
    def updateChecksumFile(self, checksum, encrypted=False, size=0, basis=None, deltasize=None, compressed=False, disksize=None, chainlength=0):
        self.logger.debug("Updating checksum file: %s -- %d bytes, Compressed %s", checksum, size, str(compressed))

        self.cursor.execute("UPDATE CheckSums SET "
                            "Size = :size, Encrypted = :encrypted, Basis = :basis, DeltaSize = :deltasize, ChainLength = :chainlength, "
                            "Compressed = :compressed, DiskSize = :disksize "
                            "WHERE Checksum = :checksum",
                            {"checksum": checksum, "size": size, "basis": basis, "encrypted": encrypted, "deltasize": deltasize,
                             "compressed": str(compressed), "chainlength": chainlength, "disksize": disksize})

    @authenticate
    def getChecksumInfo(self, checksum):
        self.logger.debug("Getting checksum info on: %s", checksum)
        c = self._execute("SELECT " +
                          _checksumInfoFields  +
                          "FROM Checksums WHERE CheckSum = :checksum",
                          {"checksum": checksum})
        row = c.fetchone()
        if row:
            return row
        else:
            self.logger.debug("No checksum found for %s", checksum)
            return None

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
        c = self._execute('SELECT DISTINCT Name FROM Names JOIN Files ON Names.NameID = Files.NameID JOIN Checksums ON Checksums.ChecksumID = Files.ChecksumID '
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
        #self.logger.debug("Reading directory values for (%d, %d) %d", inode, device, backupset)

        c = self._execute("SELECT " + _fileInfoFields + ", C1.Basis AS basis, C1.Encrypted AS encrypted " +
                          _fileInfoJoin +
                          "WHERE Parent = :parent AND ParentDev = :parentDev AND "
                          ":backup BETWEEN Files.FirstSet AND Files.LastSet",
                          {"parent": inode, "parentDev": device, "backup": backupset})
        return _fetchEm(c)
        #while True:
        #    batch = c.fetchmany(self.chunksize)
        #    if not batch:
        #        break
        #    for row in batch:
        #        yield row

    @authenticate
    def getNumDeltaFilesInDirectory(self, dirNode, current=False):
        (inode, device) = dirNode
        backupset = self._bset(current)
        row = self._executeWithResult("SELECT COUNT(*) FROM Files " \
                                      "JOIN Names ON Files.NameId = Names.NameId " \
                                      "LEFT OUTER JOIN Checksums AS C1 ON Files.ChecksumId = C1.ChecksumId " \
                                      "WHERE Parent = :parent AND ParentDev = :parentDev AND "
                                      ":backup BETWEEN Files.FirstSet AND Files.LastSet AND "
                                      "C1.ChainLength != 0",
                                      {"parent": inode, "parentDev": device, "backup": backupset})
        if row:
            return row[0]
        else:
            return 0

    @authenticate
    def getDirectorySize(self, dirNode, current=False):
        (inode, device) = dirNode
        backupset = self._bset(current)
        row = self._executeWithResult("SELECT COUNT(*) FROM Files "
                                      "WHERE Parent = :parent AND ParentDev = :parentDev AND "
                                      ":backup BETWEEN Files.FirstSet AND Files.LastSet AND "
                                      "(Dir = 1 OR ChecksumId IS NOT NULL)",
                                      { "parent": inode, "parentDev": device, "backup": backupset })
        if row:
            return row[0]
        else:
            return 0

    @authenticate
    def readDirectoryForRange(self, dirNode, first, last):
        (inode, device) = dirNode
        #self.logger.debug("Reading directory values for (%d, %d) in range (%d, %d)", inode, device, first, last)
        c = self._execute("SELECT " + _fileInfoFields + ", "
                          "C1.Basis AS basis, C1.Encrypted AS encrypted " +
                          _fileInfoJoin +
                          "WHERE Parent = :parent AND ParentDev = :parentDev AND "
                          "Files.LastSet >= :first AND Files.FirstSet <= :last",
                          {"parent": inode, "parentDev": device, "first": first, "last": last})
        while True:
            batch = c.fetchmany(self.chunksize)
            if not batch:
                break
            for row in batch:
                yield row

    @authenticate
    def listBackupSets(self):
        #self.logger.debug("list backup sets")
        #                 "Name AS name, BackupSet AS backupset "
        c = self._execute("SELECT " +
                          _backupSetInfoFields +
                          _backupSetInfoJoin +
                          "ORDER BY backupset ASC", {})
        while True:
            batch = c.fetchmany(self.chunksize)
            if not batch:
                break
            for row in batch:
                yield row

    @authenticate
    def getBackupSetInfoById(self, bset):
        c = self._execute("SELECT " +
                          _backupSetInfoFields +
                          _backupSetInfoJoin +
                          "WHERE BackupSet = :bset",
                          { "bset": bset })
        row = c.fetchone()
        return row

    @authenticate
    def getBackupSetInfoByTag(self, tag):
        bset = self._executeWithResult("SELECT BackupSet FROM Tags JOIN Names on Tags.NameId = Names.NameId WHERE Names.name = :tag", {"tag": tag})
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
                          { "name": name })
        row = c.fetchone()
        return row

    @authenticate
    def getBackupSetInfoForTime(self, time):
        c = self._execute("SELECT " +
                          _backupSetInfoFields +
                          _backupSetInfoJoin +
                          "WHERE BackupSet = (SELECT MAX(BackupSet) FROM Backups WHERE StartTime <= :time)",
                          { "time": time })
        row = c.fetchone()
        return row

    @authenticate
    def getBackupSetDetails(self, bset):
        row = self._executeWithResult("SELECT COUNT(*), SUM(Size) FROM Files JOIN Checksums ON Files.ChecksumID = Checksums.ChecksumID WHERE Dir = 0 AND :bset BETWEEN FirstSet AND LastSet", {'bset': bset})
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
        row = self._executeWithResult("SELECT COUNT(*), SUM(Size), SUM(DiskSize) FROM Files JOIN Checksums ON Files.ChecksumID = Checksums.ChecksumID "
                                      "WHERE Dir = 0 AND FirstSet > :prevSet",
                                      {'prevSet': prevSet})
        newFiles = row[0] if row[0] else 0
        newSize  = row[1] if row[1] else 0
        newSpace = row[2] if row[2] else 0

        # Count of files that are last seen in this set, and are not part of somebody else's basis
        row = self._executeWithResult("SELECT COUNT(*), SUM(Size), SUM(DiskSize) FROM Files JOIN Checksums ON Files.ChecksumID = Checksums.ChecksumID "
                                      "WHERE Dir = 0 AND LastSet < :nextSet "
                                      "AND Checksum NOT IN (SELECT Basis FROM Checksums WHERE Basis IS NOT NULL)",
                                      {'nextSet': nextSet})
        endFiles = row[0] if row[0] else 0
        endSize  = row[1] if row[1] else 0
        endSpace = row[2] if row[2] else 0

        return (files, dirs, size, (newFiles, newSize, newSpace), (endFiles, endSize, endSpace))


    @authenticate
    def getNewFiles(self, bSet, other):
        if other:
            row = self._executeWithResult("SELECT max(BackupSet) FROM Backups WHERE BackupSet < :bset", {'bset': bSet})
            pSet = row[0]
        else:
            pSet = bSet
        self.logger.debug("Getting new files for changesets %s -> %s", pSet, bSet)
        cursor = self._execute("SELECT " + _fileInfoFields + _fileInfoJoin +
                               "WHERE Files.FirstSet >= :pSet AND Files.LastSet <= :bSet",
                               {'bSet': bSet, 'pSet': pSet})
        return _fetchEm(cursor)

    @authenticate
    def getFileSizes(self, minsize):
        cursor = self._execute("SELECT DISTINCT(Size) FROM Checksums WHERE Size > :minsize", {"minsize": minsize })
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
        c = self._execute("SELECT Value FROM Config WHERE Key = :key", {'key': key })
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
                backupName = self.dbName + ".keys"
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
        self.cursor.execute("BEGIN")

    @authenticate
    def commit(self):
        self.conn.commit()


    @authenticate
    def completeBackup(self):
        self._execute("UPDATE Backups SET Completed = 1 WHERE BackupSet = :backup", { "backup": self.currBackupSet })
        self.commit()

    def _purgeFiles(self):
        self.cursor.execute("DELETE FROM Files WHERE "
                            "0 = (SELECT COUNT(*) FROM Backups WHERE Backups.BackupSet BETWEEN Files.FirstSet AND Files.LastSet)")
        filesDeleted = self.cursor.rowcount
        return filesDeleted

    @authenticate
    def listPurgeSets(self, priority, timestamp, current=False):
        backupset = self._bset(current)
        # Select all sets that are purgeable.
        c = self.cursor.execute("SELECT " +
                                _backupSetInfoFields +
                                _backupSetInfoJoin +
                                " WHERE Priority <= :priority AND EndTime <= :timestamp AND BackupSet < :backupset AND Locked = 0",
                                {"priority": priority, "timestamp": str(timestamp), "backupset": backupset})
        for row in c:
            yield row

    @authenticate
    def listPurgeIncomplete(self, priority, timestamp, current=False):
        backupset = self._bset(current)
        # Select all sets that are both purgeable and incomplete
        # Note: For some reason that I don't understand, the timestamp must be cast into a string here, to work with the coalesce operator
        # If it comes from the HTTPInterface as a string, the <= timestamp doesn't seem to work.
        c = self.cursor.execute("SELECT " +
                                _backupSetInfoFields +
                                _backupSetInfoJoin +
                                "WHERE Priority <= :priority AND COALESCE(EndTime, StartTime) <= :timestamp AND BackupSet < :backupset AND Completed = 0",
                                {"priority": priority, "timestamp": str(timestamp), "backupset": backupset})
        for row in c:
            yield row

    @authenticate
    def purgeSets(self, priority, timestamp, current=False):
        """ Purge old files from the database.  Needs to be followed up with calls to remove the orphaned files """
        backupset = self._bset(current)
        self.logger.debug("Purging backupsets below priority %d, before %s, and backupset: %d", priority, timestamp, backupset)
        # First, purge out the backupsets that don't match
        self.cursor.execute("DELETE FROM Backups WHERE Priority <= :priority AND EndTime <= :timestamp AND BackupSet < :backupset AND Locked = 0",
                            {"priority": priority, "timestamp": str(timestamp), "backupset": backupset})
        setsDeleted = self.cursor.rowcount
        # Then delete the files which are no longer referenced
        filesDeleted = self._purgeFiles()

        return (filesDeleted, setsDeleted)

    @authenticate
    def purgeIncomplete(self, priority, timestamp, current=False):
        """ Purge old files from the database.  Needs to be followed up with calls to remove the orphaned files """
        backupset = self._bset(current)
        self.logger.debug("Purging incomplete backupsets below priority %d, before %s, and backupset: %d", priority, timestamp, backupset)
        # First, purge out the backupsets that don't match
        self.cursor.execute("DELETE FROM Backups WHERE Priority <= :priority AND COALESCE(EndTime, StartTime) <= :timestamp AND BackupSet < :backupset AND Completed = 0 AND Locked = 0",
                            {"priority": priority, "timestamp": str(timestamp), "backupset": backupset})
        setsDeleted = self.cursor.rowcount

        # Then delete the files which are no longer referenced
        filesDeleted = self._purgeFiles()

        return (filesDeleted, setsDeleted)

    @authenticate
    def deleteBackupSet(self, current=False):
        bset = self._bset(current)
        self.cursor.execute("DELETE FROM Tags WHERE BackupSet = :backupset", {"backupset": bset})
        self.cursor.execute("DELETE FROM Backups WHERE BackupSet = :backupset", {"backupset": bset})
        # TODO: Move this to the removeOrphans phase
        # Then delete the files which are no longer referenced
        filesDeleted = self._purgeFiles()

        return filesDeleted

    @authenticate
    def listOrphanChecksums(self, isFile):
        c = self.conn.execute("SELECT Checksum FROM Checksums "
                              "WHERE ChecksumID NOT IN (SELECT DISTINCT(ChecksumID) FROM Files WHERE ChecksumID IS NOT NULL) "
                              "AND   ChecksumID NOT IN (SELECT DISTINCT(XattrId) FROM Files WHERE XattrID IS NOT NULL) "
                              "AND   ChecksumID NOT IN (SELECT DISTINCT(AclId) FROM Files WHERE AclId IS NOT NULL) "
                              "AND   ChecksumID NOT IN (SELECT DISTINCT(CmdLineID) FROM Backups WHERE CmdLineID IS NOT NULL) "
                              "AND   Checksum   NOT IN (SELECT DISTINCT(Basis) FROM Checksums WHERE Basis IS NOT NULL) "
                              "AND IsFile = :isfile",
                              { 'isfile': int(isFile)} )
        while True:
            batch = c.fetchmany(self.chunksize)
            if not batch:
                break
            for row in batch:
                yield row[0]

    @authenticate
    def deleteOrphanChecksums(self, isFile):
        self.cursor.execute("DELETE FROM Checksums "
                            "WHERE ChecksumID NOT IN (SELECT DISTINCT(ChecksumID) FROM Files WHERE ChecksumID IS NOT NULL) "
                            "AND   ChecksumID NOT IN (SELECT DISTINCT(XattrId) FROM Files WHERE XattrID IS NOT NULL) "
                            "AND   ChecksumID NOT IN (SELECT DISTINCT(AclId) FROM Files WHERE AclId IS NOT NULL) "
                            "AND   ChecksumID NOT IN (SELECT DISTINCT(CmdLineID) FROM Backups WHERE CmdLineID IS NOT NULL) "
                            "AND   Checksum   NOT IN (SELECT DISTINCT(Basis) FROM Checksums WHERE Basis IS NOT NULL) "
                            "AND IsFile = :isfile",
                            { 'isfile': int(isFile)} )
        return self.cursor.rowcount

    @authenticate
    def compact(self):
        self.logger.debug("Removing unused names")
        # Purge out any unused names
        self.conn.execute("DELETE FROM Names WHERE NameID NOT IN (SELECT NameID FROM Files) AND NameID NOT IN (SELECT NameID FROM Tags)")
        vacuumed = False

        # Check if we've hit an interval where we want to do a vacuum
        bset = self._bset(True)
        interval = self.getConfigValue("VacuumInterval")
        if interval and (bset % int(interval)) == 0:
            self.logger.debug("Vaccuuming database")
            # And clean up the database
            self.conn.commit()  # Just in case there's a transaction outstanding, for no apparent reason
            self.conn.execute("VACUUM")
            vacuumed = True
        self.conn.execute("UPDATE Backups SET Vacuumed = :vacuumed WHERE BackupSet = :backup", {"backup": self.currBackupSet, "vacuumed": vacuumed})

    @authenticate
    def enumerateChecksums(self, isFile=True):
        c = self.conn.execute("SELECT Checksum FROM Checksums WHERE IsFile = :isfile", {"isfile": int(isFile)})

        while True:
            batch = c.fetchmany(self.chunksize)
            if not batch:
                break
            for row in batch:
                yield row[0]

    @authenticate
    def getChecksumCount(self, isFile=True):
        r = self._executeWithResult("SELECT COUNT(*) FROM Checksums WHERE IsFile = :isfile", {"isfile": int(isFile)})
        return r[0]

    @authenticate
    def deleteChecksum(self, checksum):
        self.logger.debug("Deleting checksum: %s", checksum)
        self.cursor.execute("DELETE FROM Checksums WHERE Checksum = :checksum", {"checksum": checksum})
        return self.cursor.rowcount

    @authenticate
    def setClientEndTime(self):
        if self.currBackupSet:
            self.conn.execute("UPDATE Backups SET ClientEndTime = :now WHERE BackupSet = :backup",
                              { "now": time.time(), "backup": self.currBackupSet })

    @authenticate
    def setTag(self, tag, current=False):
        backupset = self._bset(current)
        nameid = self._getNameId(tag)
        try:
            self.conn.execute("INSERT INTO Tags (BackupSet, NameId) VALUES (:backup, :nameid)", {"backup": backupset, "nameid": nameid})
            return True
        except sqlite3.IntegrityError:
            return False

    @authenticate
    def removeTag(self, tag):
        nameid = self._getNameId(tag, False)
        if nameid:
            self.conn.execute("DELETE FROM Tags WHERE NameID = :nameid", {"nameid": nameid})
            return True
        return False

    @authenticate
    def getTags(self, bset):
        c = self._execute("SELECT Name FROM Names JOIN Tags ON Tags.NameId = Names.NameId WHERE Tags.Backupset = :bset", {"bset": bset})
        tags = []
        row = c.fetchone()
        while row:
            tags.append(row['Name'])
            row = c.fetchone()
        return tags

    @authenticate
    def setLock(self, locked, current=False):
        bset = self._bset(current)
        self._execute("UPDATE Backups SET Locked = :locked WHERE BackupSet = :bset", { "locked": locked, "bset": bset })

    @authenticate
    def setFailure(self, ex):
        if self.currBackupSet:
            self.conn.execute("UPDATE Backups SET Exception = :ex, ErrorMsg = :msg WHERE BackupSet = :backup",
                              { "ex": type(ex).__name__, "msg": str(ex), "backup": self.currBackupSet})

    def close(self, completeBackup=False):
        if self._isAuthenticated():
            #self.logger.debug("Closing DB: %s", self.dbName)
            # Apparently logger will get shut down if we're executing in __del__, so leave the debugging message out
            if self.currBackupSet:
                self.conn.execute("UPDATE Backups SET EndTime = :now WHERE BackupSet = :backup",
                                  { "now": time.time(), "backup": self.currBackupSet })
            self.conn.commit()

            if self.backup and completeBackup:
                r = Rotator.Rotator(rotations=self.numbackups)
                try:
                    r.backup(self.dbName)
                    r.rotate(self.dbName)
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

if __name__ == "__main__":
    db = TardisDB(sys.argv[1])
    db.newBackupSet(sys.argv[2], str(uuid.uuid1()), 25, time.time())
    rec =  db.getFileInfoByName("File1", 1)
    print(rec)
    print(db.getFileInfoByInode(2))
    info = {
        "name"  : "Dir",
        "inode" : 1,
        "dir"   : 0,
        "size"  : 1,
        "mtime" : 1111,
        "ctime" : 1111,
        "atime" : 1111,
        "mode"  : 666,
        "uid"   : 99,
        "gid"   : 100,
        "cksum" : None
        }
    db.insertFile(info)
    info = {
        "name"  : "File1",
        "inode" : 2,
        "dir"   : 1,
        "size"  : 1,
        "mtime" : 2222,
        "ctime" : 2222,
        "atime" : 2222,
        "mode"  : 444,
        "uid"   : 99,
        "gid"   : 100,
        "cksum" : None
        }
    db.insertFile(info)
    db.completeBackup()
    db.commit()
