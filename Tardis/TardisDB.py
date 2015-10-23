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

import sqlite3
import shutil
import logging
import os, os.path
import functools
import time
import hashlib
import sys
import Tardis
import array
import uuid

import ConnIdLogAdapter
import Rotator

# Utility functions

_fieldInfoFields = "Name AS name, Inode AS inode, Device AS device, Dir AS dir, Link AS link, " \
                   "Parent AS parent, ParentDev AS parentdev, C1.Size AS size, " \
                   "MTime AS mtime, CTime AS ctime, ATime AS atime, Mode AS mode, UID AS uid, GID AS gid, NLinks AS nlinks, " \
                   "FirstSet AS firstset, LastSet AS lastset, C1.Checksum AS checksum, C1.ChainLength AS chainlength, " \
                   "C2.Checksum AS xattrs, C3.Checksum AS acl "

_fileInfoJoin =    "FROM Files " \
                   "JOIN Names ON Files.NameId = Names.NameId " \
                   "LEFT OUTER JOIN Checksums AS C1 ON Files.ChecksumId = C1.ChecksumId " \
                   "LEFT OUTER JOIN Checksums AS C2 ON Files.XattrId = C2.ChecksumId " \
                   "LEFT OUTER JOIN Checksums AS C3 ON Files.AclId = C3.ChecksumId "

_backupSetInfoFields = "BackupSet AS backupset, StartTime AS starttime, EndTime AS endtime, ClientTime AS clienttime, " \
                       "Priority AS priority, Completed AS completed, Session AS session, Name AS name, " \
                       "ClientVersion AS clientversion, ClientIP AS clientip, ServerVersion AS serverversion "

_schemaVersion = 5

def addFields(x, y):
    """ Add fields to the end of a dict """
    return dict(y.items() + x)

def splitpath(path):
    """ Split a path into chunks, recursively """
    (head, tail) = os.path.split(path)
    return splitpath(head) + [ tail ] if head and head != path else [ head or tail ]

# Class TardisDB

class TardisDB(object):
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

    def __init__(self, dbname, backup=False, prevSet=None, initialize=None, connid=None, token=None, user=-1, group=-1, chunksize=1000, numbackups=2, journal=None, clientId=None):
        """ Initialize the connection to a per-machine Tardis Database"""
        self.logger  = logging.getLogger("DB")
        self.logger.debug("Initializing connection to {}".format(dbname))
        self.dbName = dbname
        self.chunksize = chunksize

        if user  is None: user = -1
        if group is None: group = -1

        if connid:
            self.logger = ConnIdLogAdapter.ConnIdLogAdapter(self.logger, connid)

        self.backup = backup
        self.numbackups = numbackups

        conn = sqlite3.connect(self.dbName)
        conn.text_factory = str
        conn.row_factory= sqlite3.Row

        self.conn = conn
        self.cursor = self.conn.cursor()

        if (initialize):
            self.logger.info("Creating database from schema: {}".format(initialize))
            try:
                with open(initialize, "r") as f:
                    script = f.read()
                    self.conn.executescript(script)
            except IOError as e:
                self.logger.error("Could not read initialization script {}".format(initialize))
                self.logger.exception(e)
                raise
            except sqlite3.Error as e:
                self.logger.error("Could not execute initialization script {}".format(initialize))
                self.logger.exception(e)
                raise
            if token:
                self.setToken(token)
            self.setConfigValue('ClientID', str(uuid.uuid1()))

        if token:
            if not self.checkToken(token):
                self.logger.error("Token/password does not match")
                raise Exception("Password does not match")
        else:
            if self.getToken() is not None:
                self.logger.error("No token/password specified")
                raise Exception("No password specified")

        version = self.getConfigValue('SchemaVersion')
        if int(version) != _schemaVersion:
            self.logger.error("Schema version mismatch: Database %s is %d:  Expected %d.   Please convert", dbname, int(version), _schemaVersion)
            raise Exception("Schema version mismatch: Database {} is {}:  Expected {}.   Please convert".format(dbname, version, _schemaVersion))

        if (prevSet):
            f = self.getBackupSetInfo(prevSet)
            if f:
                self.prevBackupSet = f['backupset']
                self.prevBackupDate = f['starttime']
                self.lastClientTime = f['clienttime']
                self.prevBackupName = prevSet
            #self.cursor.execute = ("SELECT Name, BackupSet FROM Backups WHERE Name = :backup", {"backup": prevSet})
        else:
            b = self.lastBackupSet()
            self.prevBackupName = b['name']
            self.prevBackupSet  = b['backupset']
            self.prevBackupDate = b['starttime']
            self.lastClientTime = b['clienttime']
            #self.cursor.execute("SELECT Name, BackupSet FROM Backups WHERE Completed = 1 ORDER BY BackupSet DESC LIMIT 1")

        self.clientId = self.getConfigValue('ClientID')

        #row = self.cursor.fetchone()
        #self.prevBackupName = row[0]
        #self.prevBackupSet = row[1]
        self.logger.debug("Last Backup Set: {} {} ".format(self.prevBackupName, self.prevBackupSet))

        self.conn.commit()

        self.conn.execute("PRAGMA synchronous=false")
        self.conn.execute("PRAGMA foreignkeys=true")
        self.conn.execute("PRAGMA journal_mode=truncate")

        if journal:
            self.journal = file(journal, 'a')

        # Make sure the permissions are set the way we want, if that's specified.
        if user != -1 or group != -1:
            os.chown(self.dbName, user, group)

    def _bset(self, current):
        """ Determine the backupset we're being asked about.
            True == current, False = previous, otherwise a number is returned
        """
        if type(current) is bool:
            return self.currBackupSet if current else self.prevBackupSet
        else:
            return current

    def lastBackupSet(self, completed=True):
        """ Select the last backup set. """
        if completed:
            c = self.cursor.execute("SELECT " +
                                     _backupSetInfoFields +
                                    "FROM Backups WHERE Completed = 1 ORDER BY BackupSet DESC LIMIT 1")
        else:
            c = self.cursor.execute("SELECT " +
                                     _backupSetInfoFields +
                                    "FROM Backups ORDER BY BackupSet DESC LIMIT 1")
        row = c.fetchone()
        return row

    def execute(self, query, data):
        try:
            ret = self.conn.execute(query, data)
            return ret
        except sqlite3.IntegrityError as e:
            self.logger.warning("Error processing data: %s %s", data, e)
            raise e

    def getResult(self, query, data):
        c = self.execute(query, data)
        r = c.fetchone()
        return r

    def newBackupSet(self, name, session, priority, clienttime, version=None, ip=None):
        """ Create a new backupset.  Set the current backup set to be that set. """
        c = self.cursor
        now = time.time()
        try:
            c.execute("INSERT INTO Backups (Name, Completed, StartTime, Session, Priority, ClientTime, ClientVersion, ServerVersion, ClientIP) "
                      "            VALUES (:name, 0, :now, :session, :priority, :clienttime, :clientversion, :serverversion, :clientip)",
                      {"name": name, "now": now, "session": session, "priority": priority,
                       "clienttime": clienttime, "clientversion": version, "clientip": ip,
                       "serverversion": Tardis.__version__})
        except sqlite3.IntegrityError as e:
            raise Exception("Backupset {} already exists".format(name))

        self.currBackupSet = c.lastrowid
        self.currBackupName = name
        self.conn.commit()
        self.logger.info("Created new backup set: %d: %s %s", self.currBackupSet, name, session)
        if self.journal:
            self.journal.write("===== S: {} {} {} D: {} V:{} {}\n".format(self.currBackupSet, name, session, time.strftime("%Y-%m-%d %H:%M:%S"), version, Tardis.__version__))

        return self.currBackupSet

    def setBackupSetName(self, name, priority, current=True):
        """ Change the name of a backupset.  Return True if it can be changed, false otherwise. """
        backupset = self._bset(current)
        try:
            self.conn.execute("UPDATE Backups SET Name = :name, Priority = :priority WHERE BackupSet = :backupset",
                      {"name": name, "priority": priority, "backupset": backupset})
            return True
        except sqlite3.IntegrityError as e:
            return False

    def checkBackupSetName(self, name):
        """ Check to see if a backupset by this name exists. Return TRUE if it DOESN'T exist. """
        c = self.conn.execute("SELECT COUNT(*) FROM Backups WHERE Name = :name",
                              { "name": name })
        row = c.fetchone()
        return True if row[0] == 0 else False;

    def getFileInfoByName(self, name, parent, current=True):
        """ Lookup a file in a directory in the previous backup set"""
        backupset = self._bset(current)
        (inode, device) = parent
        #self.logger.debug("Looking up file by name {} {} {}".format(name, parent, backupset))
        c = self.cursor
        c.execute("SELECT " +
                  _fieldInfoFields +
                  #"FROM Files "
                  #"JOIN Names ON Files.NameId = Names.NameId "
                  #"LEFT OUTER JOIN Checksums ON Files.ChecksumId = Checksums.ChecksumId "
                  _fileInfoJoin +
                  "WHERE Name = :name AND Parent = :parent AND ParentDev = :parentDev AND "
                  ":backup BETWEEN FirstSet AND LastSet",
                  {"name": name, "parent": inode, "parentDev": device, "backup": backupset})
        return c.fetchone()

    def getFileInfoByPath(self, path, current=False, permchecker=None):
        """ Lookup a file by a full path. """
        ### TODO: Could be a LOT faster without the repeated calls to getFileInfoByName
        backupset = self._bset(current)
        #self.logger.debug("Looking up file by path {} {}".format(path, backupset))
        parent = (0, 0)         # Root directory value
        info = None

        #(dirname, name) = os.path.split(path)
        # Walk the path
        for name in splitpath(path):
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

    def getFileInfoForPath(self, path, current=False):
        """ Return the FileInfo structures for each file along a path """
        backupset = self._bset(current)
        #self.logger.debug("Looking up file by path {} {}".format(path, backupset))
        parent = (0, 0)         # Root directory value
        info = None
        for name in splitpath(path):
            if name == '/':
                continue
            info = self.getFileInfoByName(name, parent, backupset)
            if info:
                yield info
                parent = (info["inode"], info["device"])
            else:
                break

    def getFileInfoByInode(self, info, current=False):
        backupset = self._bset(current)
        (inode, device) = info
        self.logger.debug("Looking up file by inode (%d %d) %d", inode, device, backupset)
        c = self.cursor
        c.execute("SELECT " +
                  _fieldInfoFields + _fileInfoJoin +
                  "WHERE Inode = :inode AND Device = :device AND "
                  ":backup BETWEEN FirstSet AND LastSet",
                  {"inode": inode, "device": device, "backup": backupset})
        return c.fetchone()

    def getFileInfoBySimilar(self, fileInfo, current=False):
        """ Find a file which is similar, namely the same size, inode, and mtime.  Identifies files which have moved. """
        backupset = self._bset(current)
        self.logger.debug("Looking up file for similar info: %s", fileInfo)
        temp = fileInfo.copy()
        temp["backup"] = backupset
        c = self.cursor.execute("SELECT " + 
                                _fieldInfoFields + _fileInfoJoin +
                                "WHERE Inode = :inode AND Device = :dev AND Mtime = :mtime AND C1.Size = :size AND "
                                ":backup BETWEEN Files.FirstSet AND Files.LastSet",
                                temp)
        return c.fetchone()

    def getFileFromPartialBackup(self, fileInfo):
        """ Find a file which is similar, namely the same size, inode, and mtime.  Identifies files which have moved. """
        #self.logger.debug("Looking up file for similar info: %s", fileInfo)
        temp = fileInfo.copy()
        temp["backup"] = self.prevBackupSet         ### Only look for things newer than the last backup set
        #self.logger.info("getFileFromPartialBackup: %s", str(fileInfo))
        c = self.cursor.execute("SELECT " +
                                _fieldInfoFields + _fileInfoJoin +
                                "WHERE Inode = :inode AND Device = :dev AND Mtime = :mtime AND C1.Size = :size AND "
                                "Files.LastSet >= :backup "
                                "ORDER BY Files.LastSet DESC LIMIT 1",
                                temp)
        return c.fetchone()

    def getFileInfoByInodeFromPartial(self, inode):
        (ino, dev) = inode
        c = self.cursor.execute("SELECT " +
                                _fieldInfoFields + _fileInfoJoin +
                                "WHERE Inode = :inode AND Device = :device AND "
                                "Files.LastSet >= :backup "
                                "ORDER BY Files.LastSet DESC LIMIT 1",
                                {"inode": ino, "device": dev, "backup": self.prevBackupSet })

        return c.fetchone()

    """
    def copyChecksum(self, old_inode, new_inode):
        self.cursor.execute("UPDATE Files SET ChecksumId = (SELECT CheckSumID FROM Files WHERE Inode = :oldInode AND BackupSet = :prev) "
                            "WHERE INode = :newInode AND BackupSet = :backup",
                            {"oldInode": old_inode, "newInode": new_inode, "prev": self.prevBackupSet, "backup": self.currBackupSet})
        return self.cursor.rowcount
    """

    def setChecksum(self, inode, device, checksum):
        self.cursor.execute("UPDATE Files SET ChecksumId = (SELECT ChecksumId FROM CheckSums WHERE CheckSum = :checksum) "
                            "WHERE Inode = :inode AND Device = :device AND "
                            ":backup BETWEEN FirstSet AND LastSet",
                            {"inode": inode, "device": device, "checksum": checksum, "backup": self.currBackupSet})
        return self.cursor.rowcount

    def setXattrs(self, inode, device, checksum):
        self.cursor.execute("UPDATE Files SET XattrId = (SELECT ChecksumId FROM CheckSums WHERE CheckSum = :checksum) "
                            "WHERE Inode = :inode AND Device = :device AND "
                            ":backup BETWEEN FirstSet AND LastSet",
                            {"inode": inode, "device": device, "checksum": checksum, "backup": self.currBackupSet})
        #self.logger.info("Setting XAttr ID for %d to %s, %d rows changed", inode, checksum, self.cursor.rowcount)
        return self.cursor.rowcount

    def setAcl(self, inode, device, checksum):
        self.cursor.execute("UPDATE Files SET AclId = (SELECT ChecksumId FROM CheckSums WHERE CheckSum = :checksum) "
                            "WHERE Inode = :inode AND Device = :device AND "
                            ":backup BETWEEN FirstSet AND LastSet",
                            {"inode": inode, "device": device, "checksum": checksum, "backup": self.currBackupSet})
        #self.logger.info("Setting ACL ID for %d to %s, %d rows changed", inode, checksum, self.cursor.rowcount)
        return self.cursor.rowcount


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

    def getChecksumByName(self, name, parent, current=False):
        backupset = self._bset(current)
        (inode, device) = parent
        self.logger.debug("Looking up checksum for file %s (%d %d) in %d", name, inode, device, backupset)
        c = self.execute("SELECT CheckSums.CheckSum AS checksum "
                         "FROM Files "
                         "JOIN Names ON Files.NameID = Names.NameId "
                         "JOIN CheckSums ON Files.ChecksumId = CheckSums.ChecksumId "
                         "WHERE Names.Name = :name AND Files.Parent = :parent AND ParentDev = :parentDev AND "
                         ":backup BETWEEN Files.FirstSet AND Files.LastSet",
                         { "name": name, "parent": inode, "parentDev": device, "backup": backupset })
        row = c.fetchone()
        return row[0] if row else None
        #if row: return row[0] else: return None

    def getChecksumByPath(self, name, current=False, permchecker=None):
        backupset = self._bset(current)
        self.logger.debug("Looking up checksum for path %s %d", name, backupset)
        f = self.getFileInfoByPath(name, current, permchecker=permchecker)
        if f:
            return self.getChecksumByName(f["name"], (f["parent"], f["parentdev"]), current)
        else:
            return None

    def getChecksumInfoByPath(self, name, current=False, permchecker=None):
        backupset = self._bset(current)
        cksum = self.getChecksumByPath(name, backupset, permchecker)
        if cksum:
            return self.getChecksumInfo(cksum)
        else:
            return None

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

    def insertFile(self, fileInfo, parent):
        self.logger.debug("Inserting file: %s", fileInfo)
        (parIno, parDev) = parent
        fields = {"backup": self.currBackupSet, "parent": parIno, "parentDev": parDev}.items()
        temp = addFields(fields, fileInfo)
        self.setNameID([temp])
        self.execute("INSERT INTO Files "
                     "(NameId, FirstSet, LastSet, Inode, Device, Parent, ParentDev, Dir, Link, MTime, CTime, ATime,  Mode, UID, GID, NLinks) "
                     "VALUES  "
                     "(:nameid, :backup, :backup, :inode, :dev, :parent, :parentDev, :dir, :link, :mtime, :ctime, :atime, :mode, :uid, :gid, :nlinks)",
                     temp)

    def updateDirChecksum(self, directory, cksid, current=True):
        bset = self._bset(current)
        (inode, device) = directory
        self.execute("UPDATE FILES "
                     "SET ChecksumID = :cksid "
                     "WHERE Inode = :inode AND DEVICE = :device AND :bset BETWEEN FirstSet AND LastSet",
                     {"inode": inode, "device": device, "cksid": cksid, "bset": bset})

    def extendFile(self, parent, name, old=False, current=True):
        old = self._bset(old)
        (parIno, parDev) = parent
        current = self._bset(current)
        cursor = self.execute("UPDATE FILES "
                              "SET LastSet = :new "
                              "WHERE Parent = :parent AND ParentDev = :parentDev AND NameID = (SELECT NameID FROM Names WHERE Name = :name) AND "
                              ":old BETWEEN FirstSet AND LastSet",
                              { "parent": parIno, "parentDev": parDev , "name": name, "old": old, "new": current })
        return cursor.rowcount

    def cloneDir(self, parent, new=True, old=False):
        newBSet = self._bset(new)
        oldBSet = self._bset(old)
        (parIno, parDev) = parent
        self.logger.debug("Cloning directory inode %d, %d from %d to %d", parIno, parDev, oldBSet, newBSet)
        cursor = self.execute("UPDATE FILES "
                              "SET LastSet = :new "
                              "WHERE Parent = :parent AND ParentDev = :parentDev AND "
                              ":old BETWEEN FirstSet AND LastSet",
                              { "new": newBSet, "old": oldBSet, "parent": parIno, "parentDev": parDev })
        return cursor.rowcount

    def setNameID(self, files):
        for f in files:
            c = self.cursor.execute("SELECT NameId FROM Names WHERE Name = :name", f)
            row = c.fetchone()
            if row:
                f["nameid"] = row[0]
            else:
                self.cursor.execute("INSERT INTO Names (Name) VALUES (:name)", f)
                f["nameid"] = self.cursor.lastrowid

    def insertChecksumFile(self, checksum, iv=None, size=0, basis=None, deltasize=None, compressed=False, disksize=None, current=True, isFile=True):
        self.logger.debug("Inserting checksum file: %s -- %d bytes, Compressed %s", checksum, size, str(compressed))
        added = self._bset(current)

        if self.journal:
            self.journal.write("{}:{}:{}\n".format(checksum, basis, iv))

        if basis is None:
            chainlength = 0
        else:
            chainlength = self.getChainLength(basis) + 1
        self.cursor.execute("INSERT INTO CheckSums (CheckSum, Size, Basis, InitVector, DeltaSize, Compressed, DiskSize, ChainLength, Added, IsFile) "
                            "VALUES                (:checksum, :size, :basis, :iv, :deltasize, :compressed, :disksize, :chainlength, :added, :isfile)",
                            {"checksum": checksum, "size": size, "basis": basis, "iv": iv, "deltasize": deltasize,
                             "compressed": int(compressed), "disksize": disksize, "chainlength": chainlength, "added": added, "isfile": int(isFile)})
        return self.cursor.lastrowid

    def updateChecksumFile(self, checksum, iv=None, size=0, basis=None, deltasize=None, compressed=False, disksize=None):
        self.logger.debug("Updating checksum file: %s -- %d bytes, Compressed %s", checksum, size, str(compressed))

        self.cursor.execute("UPDATE CheckSums SET "
                            "Size = :size, InitVector = :iv, Basis = :basis, DeltaSize = :deltasize, "
                            "Compressed = :compressed, DiskSize = :disksize "
                            "WHERE Checksum = :checksum",
                            {"checksum": checksum, "size": size, "basis": basis, "iv": iv, "deltasize": deltasize,
                             "compressed": int(compressed), "disksize": disksize})

    def getChecksumInfo(self, checksum):
        self.logger.debug("Getting checksum info on: %s", checksum)
        c = self.execute("SELECT "
                         "Checksum AS checksum, ChecksumID AS checksumid, Basis AS basis, InitVector AS iv, "
                         "Size AS size, DeltaSize AS deltasize, Compressed as compressed, ChainLength as chainlength "
                         "FROM Checksums WHERE CheckSum = :checksum",
                         {"checksum": checksum})
        row = c.fetchone()
        if row:
            return row
        else:
            self.logger.debug("No checksum found for %s", checksum)
            return None

    def getChainLength(self, checksum):
        data = self.getChecksumInfo(checksum)
        if data:
            return data['chainlength']
        else:
            return -1
        """
        Could do this, but not all versions of SQLite3 seem to support "WITH RECURSIVE" statements
        c = self.execute("WITH RECURSIVE x(n) AS (VALUES(:checksum) UNION SELECT Basis FROM Checksums, x WHERE x.n=Checksums.Checksum) "
                         "SELECT COUNT(*) FROM Checksums WHERE Checksum IN x",
                         {"checksum": checksum});
        r = c.fetchone()
        if r:
            return int(r[0])
        else:
            return -1
        """

    def readDirectory(self, dirNode, current=False):
        (inode, device) = dirNode
        backupset = self._bset(current)
        #self.logger.debug("Reading directory values for (%d, %d) %d", inode, device, backupset)

        c = self.execute("SELECT " + _fieldInfoFields + ", C1.Basis AS basis, C1.InitVector AS iv " +
                         _fileInfoJoin +
                         "WHERE Parent = :parent AND ParentDev = :parentDev AND "
                         ":backup BETWEEN Files.FirstSet AND Files.LastSet",
                         {"parent": inode, "parentDev": device, "backup": backupset})
        while True:
            batch = c.fetchmany(self.chunksize)
            if not batch:
                break
            for row in batch:
                yield row

    def readDirectoryForRange(self, dirNode, first, last):
        (inode, device) = dirNode
        #self.logger.debug("Reading directory values for (%d, %d) in range (%d, %d)", inode, device, first, last)
        c = self.execute("SELECT " + _fieldInfoFields + ", "
                         "C1.Basis AS basis, C1.InitVector AS iv " + 
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

    def listBackupSets(self):
        #self.logger.debug("list backup sets")
        #                 "Name AS name, BackupSet AS backupset "
        c = self.execute("SELECT " +
                         _backupSetInfoFields +
                         "FROM Backups "
                         "ORDER BY backupset ASC", {})
        while True:
            batch = c.fetchmany(self.chunksize)
            if not batch:
                break
            for row in batch:
                yield row

    def getBackupSetInfoById(self, bset):
        c = self.execute("SELECT " + 
                         _backupSetInfoFields +
                         "FROM Backups WHERE BackupSet = :bset",
                         { "bset": bset })
        row = c.fetchone()
        return row

    def getBackupSetInfo(self, name):
        c = self.execute("SELECT " + 
                         _backupSetInfoFields +
                         "FROM Backups WHERE Name = :name",
                         { "name": name })
        row = c.fetchone()
        return row

    def getBackupSetInfoForTime(self, time):
        c = self.execute("SELECT " + 
                         _backupSetInfoFields +
                         "FROM Backups WHERE BackupSet = (SELECT MAX(BackupSet) FROM Backups WHERE StartTime <= :time)",
                         { "time": time })
        row = c.fetchone()
        return row

    def getBackupSetDetails(self, bset):

        row = self.getResult("SELECT COUNT(*), SUM(Size) FROM Files JOIN Checksums ON Files.ChecksumID = Checksums.ChecksumID WHERE Dir = 0 AND :bset BETWEEN FirstSet AND LastSet", {'bset': bset})
        files = row[0]
        size = row[1] if row[1] else 0

        row = self.getResult("SELECT COUNT(*) FROM Files WHERE Dir = 1 AND :bset BETWEEN FirstSet AND LastSet", {'bset': bset})
        dirs = row[0]

        # Figure out the first set after this one, and the last set before this one
        row = self.getResult("SELECT MAX(BackupSet) FROM Backups WHERE BackupSet < :bset", {'bset': bset})
        prevSet = row[0] if row else 0

        row = self.getResult("SELECT MIN(BackupSet) FROM Backups WHERE BackupSet > :bset", {'bset': bset})
        nextSet = row[0] if row[0] else sys.maxint

        self.logger.debug("PrevSet: %s, NextSet: %s", prevSet, nextSet)
        # Count of files that first appeared in this version.  May be delta's
        row = self.getResult("SELECT COUNT(*), SUM(Size), SUM(DiskSize) FROM Files JOIN Checksums ON Files.ChecksumID = Checksums.ChecksumID "
                             "WHERE Dir = 0 AND FirstSet > :prevSet",
                             {'prevSet': prevSet})
        newFiles = row[0] if row[0] else 0
        newSize  = row[1] if row[1] else 0
        newSpace = row[2] if row[2] else 0

        # Count of files that are last seen in this set, and are not part of somebody else's basis
        row = self.getResult("SELECT COUNT(*), SUM(Size), SUM(DiskSize) FROM Files JOIN Checksums ON Files.ChecksumID = Checksums.ChecksumID "
                             "WHERE Dir = 0 AND LastSet < :nextSet "
                             "AND Checksum NOT IN (SELECT Basis FROM Checksums WHERE Basis IS NOT NULL)",
                             {'nextSet': nextSet})
        endFiles = row[0] if row[0] else 0
        endSize  = row[1] if row[1] else 0
        endSpace = row[2] if row[2] else 0

        return (files, dirs, size, (newFiles, newSize, newSpace), (endFiles, endSize, endSpace))

    def getConfigValue(self, key):
        c = self.execute("SELECT Value FROM Config WHERE Key = :key", {'key': key })
        row = c.fetchone()
        return row[0] if row else None

    def setConfigValue(self, key, value):
        c = self.execute("INSERT OR REPLACE INTO Config (Key, Value) VALUES(:key, :value)", {'key': key, 'value': value})

    def getToken(self):
        return self.getConfigValue('Token')

    def setToken(self, token):
        s = hashlib.sha1()
        s.update(token)
        tokenhash = s.hexdigest()
        self.setConfigValue('Token', tokenhash)

    def checkToken(self, token):
        dbToken = self.getToken()
        s = hashlib.sha1()
        s.update(token)
        tokenhash = s.hexdigest()
        if dbToken == tokenhash:
            return True
        else:
            return False

    def setKeys(self, token, filenameKey, contentKey):
        try:
            self.beginTransaction()
            self.setToken(token)
            self.setConfigValue('FilenameKey', filenameKey)
            self.setConfigValue('ContentKey', contentKey)
            self.commit()
            return True
        except Exception as e:
            self.logger.error("Setkeys failed: %s", e)
            return False

    def getKeys(self):
        return (self.getConfigValue('FilenameKey'), self.getConfigValue('ContentKey'))

    def beginTransaction(self):
        self.cursor.execute("BEGIN")

    def completeBackup(self):
        self.execute("UPDATE Backups SET Completed = 1 WHERE BackupSet = :backup", { "backup": self.currBackupSet })
        self.commit()

    def _purgeFiles(self):
        self.cursor.execute("DELETE FROM Files WHERE "
                            "0 = (SELECT COUNT(*) FROM Backups WHERE Backups.BackupSet BETWEEN Files.FirstSet AND Files.LastSet)")
        filesDeleted = self.cursor.rowcount
        return filesDeleted

    def listPurgeSets(self, priority, timestamp, current=False):
        backupset = self._bset(current)
        # First, purge out the backupsets that don't match
        c = self.cursor.execute("SELECT " + _backupSetInfoFields + " FROM Backups WHERE Priority <= :priority AND EndTime <= :timestamp AND BackupSet < :backupset",
                            {"priority": priority, "timestamp": timestamp, "backupset": backupset})
        for row in c:
            yield(row)

    def listPurgeIncomplete(self, priority, timestamp, current=False):
        backupset = self._bset(current)
        # First, purge out the backupsets that don't match
        c = self.cursor.execute("SELECT " + _backupSetInfoFields +
                                " FROM Backups WHERE Priority <= :priority AND COALESCE(EndTime, StartTime) <= :timestamp AND BackupSet < :backupset AND Completed = 0",
                            {"priority": priority, "timestamp": timestamp, "backupset": backupset})
        for row in c:
            yield(row)

    def purgeSets(self, priority, timestamp, current=False):
        """ Purge old files from the database.  Needs to be followed up with calls to remove the orphaned files """
        backupset = self._bset(current)
        self.logger.debug("Purging backupsets below priority {}, before {}, and backupset: {}".format(priority, timestamp, backupset))
        # First, purge out the backupsets that don't match
        self.cursor.execute("DELETE FROM Backups WHERE Priority <= :priority AND EndTime <= :timestamp AND BackupSet < :backupset",
                            {"priority": priority, "timestamp": timestamp, "backupset": backupset})
        setsDeleted = self.cursor.rowcount
        # Then delete the files which are no longer referenced
        filesDeleted = self._purgeFiles()

        return (filesDeleted, setsDeleted)

    def purgeIncomplete(self, priority, timestamp, current=False):
        """ Purge old files from the database.  Needs to be followed up with calls to remove the orphaned files """
        backupset = self._bset(current)
        self.logger.debug("Purging files below priority {}, before {}, and backupset: {}".format(priority, timestamp, backupset))
        # First, purge out the backupsets that don't match
        self.cursor.execute("DELETE FROM Backups WHERE Priority <= :priority AND COALESCE(EndTime, StartTime) <= :timestamp AND BackupSet < :backupset AND Completed = 0",
                            {"priority": priority, "timestamp": timestamp, "backupset": backupset})
        setsDeleted = self.cursor.rowcount

        # Then delete the files which are no longer referenced
        filesDeleted = self._purgeFiles()

        return (filesDeleted, setsDeleted)

    def deleteBackupSet(self, current=False):
        bset = self._bset(current)
        self.cursor.execute("DELETE FROM Backups WHERE BackupSet = :backupset", {"backupset": bset});
        # TODO: Move this to the removeOrphans phase
        # Then delete the files which are no longer referenced
        filesDeleted = self._purgeFiles()

        return filesDeleted

    def listOrphanChecksums(self):
        c = self.conn.execute("SELECT Checksum FROM Checksums "
                              "WHERE ChecksumID NOT IN (SELECT DISTINCT(ChecksumID) FROM Files WHERE ChecksumID IS NOT NULL) "
                              "AND ChecksumID NOT IN (SELECT DISTINCT(XattrId) FROM Files WHERE XattrID IS NOT NULL) "
                              "AND ChecksumID NOT IN (SELECT DISTINCT(AclId) FROM Files WHERE AclId IS NOT NULL) "
                              "AND Checksum NOT IN (SELECT DISTINCT(Basis) FROM Checksums WHERE Basis IS NOT NULL)")
        while True:
            batch = c.fetchmany(self.chunksize)
            if not batch:
                break
            for row in batch:
                yield row[0]

    def compact(self):
        self.logger.debug("Removing unused names")
        # Purge out any unused names
        c = self.conn.execute("DELETE FROM Names WHERE NameID NOT IN (SELECT NameID FROM Files)");

        # Check if we've hit an interval where we want to do a vacuum
        bset = self._bset(True)
        interval = self.getConfigValue("VacuumInterval")
        if interval and bset % int(interval):
            self.logger.debug("Vaccuuming database")
            # And clean up the database
            c = self.conn.execute("VACUUM")

    def deleteChecksum(self, checksum):
        self.logger.debug("Deleting checksum: %s", checksum)
        c = self.cursor.execute("DELETE FROM Checksums WHERE Checksum = :checksum", {"checksum": checksum})
        return self.cursor.rowcount

    def commit(self):
        self.conn.commit()

    def close(self, completeBackup=True):
        self.logger.debug("Closing DB: {}".format(self.dbName))
        if self.currBackupSet:
            self.conn.execute("UPDATE Backups SET EndTime = :now WHERE BackupSet = :backup",
                                { "now": time.time(), "backup": self.currBackupSet })
        self.conn.commit()
        self.conn.close()
        self.conn = None

        if self.backup and completeBackup:
            r = Rotator.Rotator(rotations=self.numbackups)
            try:
                r.backup(self.dbName)
                r.rotate(self.dbName)
            except Exception as e:
                self.logger.error("Error detected creating database backup: %s", e)

    def __del__(self):
        if self.conn:
            self.close()

if __name__ == "__main__":
    import sys
    import uuid
    x = TardisDB(sys.argv[1])
    x.newBackupSet(sys.argv[2], str(uuid.uuid1()))
    rec =  x.getFileInfoByName("File1", 1)
    print rec
    print x.getFileInfoByInode(2)
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
    x.insertFile(info)
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
    x.insertFile(info)
    x.completeBackup()
    x.commit()
