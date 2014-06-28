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

import sqlite3
import shutil
import logging
import os.path
import functools
import time

import ConnIdLogAdapter

import TardisDaemon

# Expected SQL Schema
"""
CREATE TABLE IF NOT EXISTS Config (
    Key             CHARACTER PRIMARY KEY,
    Value           CHARACTER NOT NULL
);

CREATE TABLE IF NOT EXISTS Backups (
    Name            CHARACTER UNIQUE,
    BackupSet       INTEGER PRIMARY KEY AUTOINCREMENT,
    StartTime       CHARACTER,
    EndTime         CHARACTER,
    ClientTime      CHARACTER,
    Session         CHARACTER UNIQUE,
    Completed       INTEGER,
    Priority        INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS CheckSums (
    Checksum    CHARACTER UNIQUE NOT NULL,
    ChecksumId  INTEGER PRIMARY KEY AUTOINCREMENT,
    Size        INTEGER,
    Basis       INTEGER,
    DeltaSize   INTEGER,
    InitVector  BLOB,
    FOREIGN KEY(Basis) REFERENCES CheckSums(Checksum)
);

CREATE TABLE IF NOT EXISTS Names (
    Name        CHARACTER UNIQUE NOT NULL,
    NameId      INTEGER PRIMARY KEY AUTOINCREMENT
);

CREATE TABLE IF NOT EXISTS Devices (
    DeviceId    INTEGER PRIMARY KEY AUTOICREMENT,
    MountPoint  CHARACTER UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS Files (
    NameId      INTEGER   NOT NULL,
    FirstSet    INTEGER   NOT NULL,
    LastSet     INTEGER   NOT NULL,
    Inode       INTEGER   NOT NULL,
    Device      INTEGER   NOT NULL
    Parent      INTEGER   NOT NULL,
    ParentDev   INTEGER   NOT NULL,
    ChecksumId  INTEGER,
    Dir         INTEGER,
    Link        INTEGER,
    MTime       INTEGER,
    CTime       INTEGER,
    ATime       INTEGER,
    Mode        INTEGER,
    UID         INTEGER,
    GID         INTEGER, 
    NLinks      INTEGER,
    PRIMARY KEY(NameId, FirstSet, LastSet, Parent),
    FOREIGN KEY(NameId)      REFERENCES Names(NameId),
    FOREIGN KEY(ChecksumId)  REFERENCES CheckSums(ChecksumIdD),
    FOREIGN KEY(Device)      REFERENCES Devices(DeviceId),
    FOREIGN KEY(ParentDev)   REFERENCES Devices(DeviceId)
);

CREATE INDEX IF NOT EXISTS CheckSumIndex ON CheckSums(Checksum);

CREATE INDEX IF NOT EXISTS InodeFirstIndex ON Files(Inode ASC, FirstSet ASC);
CREATE INDEX IF NOT EXISTS ParentFirstIndex ON Files(Parent ASC, FirstSet ASC);
CREATE INDEX IF NOT EXISTS InodeLastIndex ON Files(Inode ASC, LastSet ASC);
CREATE INDEX IF NOT EXISTS ParentLastndex ON Files(Parent ASC, LastSet ASC);
CREATE INDEX IF NOT EXISTS NameIndex ON Names(Name ASC);

-- CREATE INDEX IF NOT EXISTS NameIndex ON Files(Name ASC, BackupSet ASC, Parent ASC);

INSERT OR IGNORE INTO Backups (Name, StartTime, EndTime, ClientTime, Completed, Priority) VALUES (".Initial", 0, 0, 0, 1, 0);

INSERT OR REPLACE INTO Config (Key, Value) VALUES ("SchemaVersion", "1");

CREATE VIEW IF NOT EXISTS VFiles AS
    SELECT Names.Name AS Name, Inode, Device, Parent, ParentDev, Dir, Link, Size, MTime, CTime, ATime, Mode, UID, GID, NLinks, Checksum, Backups.BackupSet, Backups.Name AS Backup
    FROM Files
    JOIN Names ON Files.NameId = Names.NameId
    JOIN Backups ON Backups.BackupSet BETWEEN Files.FirstSet AND Files.LastSet
    LEFT OUTER JOIN Checksums ON Files.ChecksumId = Checksums.ChecksumId;
"""

# End of schema

# Utility functions

def makeDict(cursor, row):
    """ Convert a row from the db into a dict """
    if row != None and cursor != None and len(row) != 0:
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d
    else:
        return None

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
    logger  = logging.getLogger("DB")
    conn    = None
    cursor  = None
    dbName  = None
    db      = None
    currBackupSet = None
    dirinodes = {}

    def __init__(self, dbname, backup=True, prevSet=None, initialize=None, extra=None):
        """ Initialize the connection to a per-machine Tardis Database"""
        self.logger.debug("Initializing connection to {}".format(dbname))
        self.dbName = dbname

        if extra:
            self.logger = ConnIdLogAdapter.ConnIdLogAdapter(self.logger, extra)

        if backup:
            backup = dbname + ".bak"
            try:
                self.logger.debug("Backing up {}".format(dbname))
                shutil.copyfile(dbname, backup)
            except IOError:
                pass

        self.conn = sqlite3.connect(self.dbName)
        self.conn.text_factory = str

        if (initialize):
            self.logger.info("Creating database: {}".format(initialize))
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

        self.cursor = self.conn.cursor()
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

        #row = self.cursor.fetchone()
        #self.prevBackupName = row[0]
        #self.prevBackupSet = row[1]
        self.logger.info("Last Backup Set: {} {} ".format(self.prevBackupName, self.prevBackupSet))

        self.conn.execute("PRAGMA synchronous=false")
        self.conn.execute("PRAGMA foreignkeys=true")
        self.conn.execute("PRAGMA journal_mode=truncate")

    def bset(self, current):
        """ Determine the backupset we're being asked about.  True == current, false = previous, otherwise a number is returned """
        if type(current) is bool:
            return self.currBackupSet if current else self.prevBackupSet
        else:
            return current

    def lastBackupSet(self, completed=True):
        """ Select the last backup set. """
        if completed:
            c = self.cursor.execute("SELECT Name AS name, BackupSet AS backupset, StartTime AS starttime, ClientTime AS clienttime, Priority AS priority "
                                    "FROM Backups WHERE Completed = 1 ORDER BY BackupSet DESC LIMIT 1")
        else:
            c = self.cursor.execute("SELECT Name AS name, BackupSet AS backupset, StartTime AS starttime, ClientTime AS clienttime , Priority AS priority "
                                    "FROM Backups ORDER BY BackupSet DESC LIMIT 1")
        row = c.fetchone()
        if row:
            return makeDict(c, row)
        else:
            return None

    def execute(self, query, data):
        try:
            ret = self.conn.execute(query, data)
            return ret
        except sqlite3.IntegrityError as e:
            self.logger.warning("Error processing data: %s %s", data, e)
            raise e

    def newBackupSet(self, name, session, priority, clienttime):
        """ Create a new backupset.  Set the current backup set to be that set. """
        c = self.cursor
        c.execute("INSERT INTO Backups (Name, Completed, StartTime, Session, Priority, ClientTime) VALUES (:name, 0, :now, :session, :priority, :clienttime)",
                  {"name": name, "now": time.time(), "session": session, "priority": priority, "clienttime": clienttime})
        self.currBackupSet = c.lastrowid
        self.currBackupName = name
        self.conn.commit()
        self.logger.info("Created new backup set: {}: {} {}".format(self.currBackupSet, name, session))
        return self.currBackupSet

    def getFileInfoByName(self, name, parent, current=True):
        """ Lookup a file in a directory in the previous backup set"""
        backupset = self.bset(current)
        (inode, device) = parent
        #self.logger.debug("Looking up file by name {} {} {}".format(name, parent, self.prevBackupSet))
        c = self.cursor
        c.execute("SELECT "
                  "Name AS name, Inode AS inode, Device AS device, Dir AS dir, "
                  "Parent AS parent, ParentDev AS ParentDev, Size AS size, "
                  "MTime AS mtime, CTime AS ctime, Mode AS mode, UID AS uid, GID AS gid, NLinks AS nlinks "
                  "FROM Files "
                  "JOIN Names ON Files.NameId = Names.NameId "
                  "LEFT OUTER JOIN Checksums ON Files.ChecksumId = Checksums.ChecksumId "
                  "WHERE Name = :name AND Parent = :parent AND ParentDev = :parentDev AND "
                  ":backup BETWEEN FirstSet AND LastSet",
                  {"name": name, "parent": inode, "parentDev": device, "backup": backupset})
        return makeDict(c, c.fetchone())

        """ Lookup a file by a full path. """
    def getFileInfoByPath(self, path, current=False):
        ### TODO: Could be a LOT faster without the repeated calls to getFileInfoByName
        backupset = self.bset(current)
        #self.logger.debug("Looking up file by path {} {}".format(path, backupset))
        parent = 0              # Root directory value
        info = None

        (dirname, name) = os.path.split(path)
        # Walk the path
        for name in splitpath(path):
            info = self.getFileInfoByName(name, parent, backupset)
            if info:
                parent = info["inode"]
            else:
                break
        return info

    """
    def __getFileInfoByPath(self, path, backupset):
        try:
            (dirname, filename) = os.path.split(path)
            try:
                parent = self.dirinodes[(backupset, dirname)]
                return self.getFileInfoByName(name, parent, backupset)
            except KeyError:
                parentInfo = self.__getFileInfoByPath(dirname, backupset)
                parent = parentInfo['inode']
                self.dirinodes[(backupset, dirname)] = parent
                return self.getFileInfoByName(name, parent, backupset)
        except:
            return self.getFileInfoByName(path, 0, backupset)

    def getFileInfoByPath(self, path, current=False):
        backupset = self.bset(current)
        return self.__getFileInfoByPath(path, backupset)
    """

    def getFileInfoByInode(self, inode, current=False):
        backupset = self.bset(current)
        self.logger.debug("Looking up file by inode %d %d", inode, backupset)
        c = self.cursor
        c.execute("SELECT "
                  "Name AS name, Inode AS inode, Device AS device, Dir AS dir, "
                  "Parent AS parent, ParentDev AS ParentDev, Size AS size, "
                  "MTime AS mtime, CTime AS ctime, Mode AS mode, UID AS uid, GID AS gid, NLinks AS nlinks "
                  "FROM Files "
                  "JOIN Names ON Files.NameId = Names.NameId "
                  "LEFT OUTER JOIN Checksums ON Files.ChecksumId = Checksums.ChecksumId "
                  "WHERE Inode = :inode AND "
                  ":backup BETWEEN FirstSet AND LastSet",
                  {"inode": inode, "backup": backupset})
        return makeDict(c, c.fetchone())

    def getNewFileInfoByInode(self, inode):
        self.logger.debug("Looking up file by inode %d %d", inode, self.currBackupSet)
        c = self.cursor
        c.execute("SELECT "
                  "Name AS name, Inode AS inode, Dir AS dir, Parent AS parent, Size AS size, "
                  "MTime AS mtime, CTime AS ctime, Mode AS mode, UID AS uid, GID AS gid, NLinks AS nlinks "
                  "FROM Files "
                  "JOIN Names ON Files.NameId = Names.NameId "
                  "LEFT OUTER JOIN Checksums ON Files.ChecksumId = Checksums.ChecksumId "
                  "WHERE Inode = :inode AND "
                  ":backup BETWEEN FirstSet AND LastSet",
                  {"inode": inode, "backup": self.currBackupSet})
        return makeDict(c, c.fetchone())

    def getFileInfoBySimilar(self, fileInfo, current=False):
        """ Find a file which is similar, namely the same size, inode, and mtime.  Identifies files which have moved. """
        backupset = self.bset(current)
        self.logger.debug("Looking up file for similar info: %s", fileInfo)
        temp = fileInfo.copy()
        temp["backup"] = backupset
        c = self.cursor.execute("SELECT "
                                "Name AS name, Inode AS inode, Dir AS dir, Parent AS parent, Size AS size, "
                                "MTime AS mtime, CTime AS ctime, Mode AS mode, UID AS uid, GID AS gid, Checksum AS checksum "
                                "FROM Files "
                                "JOIN Names ON Files.NameId = Names.NameId "
                                "JOIN Checksums ON Files.ChecksumId = Checksums.ChecksumId "
                                "WHERE Inode = :inode AND Mtime = :mtime AND Size = :size AND "
                                ":backup BETWEEN Files.FirstSet AND Files.LastSet",
                                temp)
        return makeDict(c, c.fetchone())

    def getFileFromPartialBackup(self, fileInfo):
        """ Find a file which is similar, namely the same size, inode, and mtime.  Identifies files which have moved. """
        self.logger.debug("Looking up file for similar info: %s", fileInfo)
        temp = fileInfo.copy()
        temp["backup"] = self.prevBackupSet         ### Only look for things newer than the last backup set
        c = self.cursor.execute("SELECT "
                                "Name AS name, Inode AS inode, Dir AS dir, Parent AS parent, Size AS size, "
                                "MTime AS mtime, CTime AS ctime, Mode AS mode, UID AS uid, GID AS gid, Checksum AS checksum "
                                "FROM Files "
                                "JOIN Names ON Files.NameId = Names.NameId "
                                "JOIN Checksums ON Files.ChecksumId = Checksums.ChecksumId "
                                "WHERE Inode = :inode AND Mtime = :mtime AND Size = :size AND "
                                "Files.LastSet >= :backup",
                                temp)
        return makeDict(c, c.fetchone())

    def copyChecksum(self, old_inode, new_inode):
        self.cursor.execute("UPDATE Files SET ChecksumId = (SELECT CheckSumID FROM Files WHERE Inode = :oldInode AND BackupSet = :prev) "
                            "WHERE INode = :newInode AND BackupSet = :backup",
                            {"oldInode": old_inode, "newInode": new_inode, "prev": self.prevBackupSet, "backup": self.currBackupSet})
        return self.cursor.rowcount

    def setChecksum(self, inode, checksum):
        self.cursor.execute("UPDATE Files SET ChecksumId = (SELECT ChecksumId FROM CheckSums WHERE CheckSum = :checksum) "
                            "WHERE Inode = :inode AND "
                            ":backup BETWEEN FirstSet AND LastSet",
                            {"inode": inode, "checksum": checksum, "backup": self.currBackupSet})
        return self.cursor.rowcount

    def getChecksumByInode(self, inode, current=True):
        backupset = self.bset(current)
        c = self.cursor.execute("SELECT "
                                "CheckSums.Checksum AS checksum "
                                "FROM Files JOIN CheckSums ON Files.ChecksumId = Checksums.ChecksumId "
                                "WHERE Files.INode = :inode AND "
                                ":backup BETWEEN Files.FirstSet AND Files.LastSet",
                                { "backup" : backupset, "inode" : inode })
        row = c.fetchone()
        if row:
            return row[0]
        else:
            return None

    def getChecksumByName(self, name, parent, current=False):
        backupset = self.bset(current)
        (inode, device) = parent
        self.logger.debug("Looking up checksum for file %s %d %d", name, parent, backupset)
        c = self.execute("SELECT CheckSums.CheckSum AS checksum "
                         "FROM Files "
                         "JOIN Names ON Files.NameID = Names.NameId "
                         "JOIN CheckSums ON Files.ChecksumId = CheckSums.ChecksumId "
                         "WHERE Names.Name = :name AND Files.Parent = :parent AND ParentDev = :parentDev AND "
                         ":backup BETWEEN Files.FirstSet AND Files.LastSet",
                         { "name": name, "parent": inode, "parentDev": device, "backup": backupset })
        row = c.fetchone()
        if row:
            return row[0]
        else:
            return None

    def getChecksumByPath(self, name, current=False):
        backupset = self.bset(current)
        self.logger.debug("Looking up checksum for path %s %d", name, backupset)
        f = self.getFileInfoByPath(name, current)
        if f:
            return self.getChecksumByName(f["name"], f["parent"], current)
        else:
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

    """
    def insertFiles(self, files, parent):
        self.logger.debug("Inserting files: %d", len(files))
        fields = {"backup": self.currBackupSet, "parent": parent}.items()
        f = functools.partial(addFields, fields)
        self.setNameID(files)
        
        self.conn.executemany("INSERT INTO Files "
                              "(NameId, FirstSet, LastSet, Inode, Parent, Dir, Link, MTime, CTime, ATime, Mode, UID, GID, NLinks) "
                              "VALUES "
                              "(:nameid, :backup, :backup, :inode, :parent, :dir, :link, :mtime, :ctime, :atime, :mode, :uid, :gid, :nlinks)",
                              map(f, files))
    """

    def extendFile(self, parent, name, old=False, current=True):
        old = self.bset(old)
        (parIno, parDev) = parent
        current = self.bset(current)
        cursor = self.execute("UPDATE FILES "
                              "SET LastSet = :new "
                              "WHERE Parent = :parent AND ParentDev = :parentDev AND NameID = (SELECT NameID FROM Names WHERE Name = :name) AND "
                              ":old BETWEEN FirstSet AND LastSet",
                              { "parent": parIno, "parentDev": parDev , "name": name, "old": old, "new": current })
        return cursor.rowcount

    def cloneDir(self, parent, new=True, old=False):
        newBSet = self.bset(new)
        oldBSet = self.bset(old)
        (parIno, parDev) = parent
        self.logger.debug("Cloning directory inode %d, %d from %d to %d", parIno, parDev, oldBSet, newBSet)
        cursor = self.execute("UPDATE FILES "
                              "SET LastSet = :new "
                              "WHERE Parent = :parent AND ParentDev = :parentDev AND "
                              ":old BETWEEN FirstSet AND LastSet",
                              { "new": newBSet, "old": oldBSet, "parent": parIno, "parentDev": parDev })
        return cursor.rowcount

    """
    def cloneDirs(self, parents, new=True, old=False):
       newBSet = self.bset(new)
       oldBSet = self.bset(old)
       self.logger.debug("Cloning directory inodes %s from %d to %d", parents, oldBSet, newBSet)

       self.cursor.executemany("UPDATE Files "
                               "SET LastSet = :new "
                               "WHERE "
                               "Parent = :parent AND ParentDev = :parentDev AND "
                               ":old BETWEEN FirstSet AND LastSet",
                               map(lambda x:{"new": newBSet, "old": oldBSet, "parent": x}, parents))
       return self.cursor.rowcount
    """

    def setNameID(self, files):
        for f in files:
            c = self.cursor.execute("SELECT NameId FROM Names WHERE Name = :name", f)
            row = c.fetchone()
            if row:
                f["nameid"] = row[0]
            else:
                self.cursor.execute("INSERT INTO Names (Name) VALUES (:name)", f)
                f["nameid"] = self.cursor.lastrowid

    def insertChecksumFile(self, checksum, iv=None, size=0, basis=None, deltasize=None):
        self.logger.debug("Inserting checksum file: %s -- %d bytes", checksum, size)

        self.cursor.execute("INSERT INTO CheckSums (CheckSum, Size, Basis, InitVector, DeltaSize) "
                             "VALUES                (:checksum, :size, :basis, :iv, :deltasize)",
                             {"checksum": checksum, "size": size, "basis": basis, "iv": iv, "deltasize": deltasize})
        return self.cursor.lastrowid

    def getChecksumInfo(self, checksum):
        self.logger.debug("Getting checksum info on: %s", checksum)
        c = self.execute("SELECT Checksum AS checksum, ChecksumID AS checksumid, Basis AS basis, InitVector AS iv, Size AS size, DeltaSize AS deltasize "
                  "FROM Checksums WHERE CheckSum = :checksum",
                  {"checksum": checksum})
        row = c.fetchone()
        if row:
            return makeDict(c, row)
        else:
            return None

    def getChainLength(self, checksum):
        data = self.getChecksumInfo(checksum)
        if data:
            if data['basis'] is None:
                return 0
            else:
                return self.getChainLength(data['basis']) + 1
        else:
            return -1

    def readDirectory(self, dirNode, current=False):
        (inode, device) = dirNode
        backupset = self.bset(current)
        self.logger.debug("Reading directory values for (%d, %d) %d", inode, device, backupset)
        c = self.execute("SELECT "
                         "Name AS name, Inode AS inode, Device AS device, Dir AS dir, "
                         "Parent AS parent, ParentDev AS ParentDev, Size AS size, "
                         "MTime AS mtime, CTime AS ctime, Mode AS mode, UID AS uid, GID AS gid, Checksum AS checksum "
                         "FROM Files "
                         "JOIN Names ON Files.NameId = Names.NameId "
                         "LEFT OUTER JOIN Checksums ON Files.ChecksumId = Checksums.ChecksumId "
                         "WHERE Parent = :parent AND ParentDev = :parentDev AND "
                         ":backup BETWEEN Files.FirstSet AND Files.LastSet",
                         {"parent": inode, "parentDev": device, "backup": backupset})
        for row in c.fetchall():
            yield makeDict(c, row)

    """
    def getPathForFileByName(self, name, parent, current=False):
        backupSet = self.bset(current)
        self.logger.debug("Extracting path for file %s %d %d", name, parent, backupSet)
        return None
    """

    def listBackupSets(self):
        c = self.execute("SELECT "
                         "Name AS name, BackupSet AS backupset "
                         "FROM Backups")
        for row in c.fetchall():
            yield makeDict(c, row)

    def getBackupSetInfo(self, name):
        c = self.execute("SELECT "
                          "BackupSet AS backupset, StartTime AS starttime, ClientTime AS clienttime, Priority AS priority, "
                          "Completed AS completed, Session AS session "
                          "FROM Backups WHERE name = :name",
                          { "name": name })
        row = c.fetchone()
        if row:
            return makeDict(c, row)
        else:
            return None

    def getBackupSetInfoForTime(self, time):
        c = self.execute("SELECT "
                         "BackupSet AS backupset, StartTime AS starttime, ClientTime AS clienttime, Priority AS priority, "
                         "Completed AS completed, Session AS session "
                         "FROM Backups WHERE BackupSet = (SELECT MAX(BackupSet) FROM Backups WHERE StartTime <= :time)",
                         { "time": time })
        row = c.fetchone()
        if row:
            return makeDict(c, row)
        else:
            return None

    def beginTransaction(self):
        self.cursor.execute("BEGIN")


    def completeBackup(self):
        self.execute("UPDATE Backups SET Completed = 1 WHERE BackupSet = :backup", { "backup": self.currBackupSet })
        self.commit()

    def purgeFiles(self, priority, timestamp, current=False):
        """ Purge old files from the database.  Needs to be followed up with calls to remove the orphaned files """
        backupset = self.bset(current)
        self.logger.debug("Purging files below priority {}, before {}, and backupset: {}".format(priority, timestamp, backupset))
        # First, purge out the backupsets that don't match
        self.cursor.execute("DELETE FROM Backups WHERE Priority <= :priority AND EndTime <= :timestamp AND BackupSet < :backupset",
                            {"priority": priority, "timestamp": timestamp, "backupset": backupset})
        setsDeleted = self.cursor.rowcount
        # Then delete the files which are 
        # TODO: Move this to the removeOrphans phase
        self.cursor.execute("DELETE FROM Files WHERE "
                            "0 = (SELECT COUNT(*) FROM Backups WHERE Backups.BackupSet BETWEEN Files.FirstSet AND Files.LastSet)")
        #self.cursor.execute("DELETE FROM Files WHERE Files.BackupSet IN "
        #                    "(SELECT BackupSet FROM Backups WHERE Priority <= :priority AND EndTime <= :timestamp AND BackupSet < :backupset)",
        #                    {"priority": priority, "timestamp": timestamp, "backupset": backupset})
        filesDeleted = self.cursor.rowcount

        return (filesDeleted, setsDeleted)

    def listOrphanChecksums(self):
        c = self.conn.execute("SELECT Checksum FROM Checksums "
                              "WHERE ChecksumID NOT IN (SELECT DISTINCT(ChecksumID) FROM Files WHERE ChecksumID IS NOT NULL) "
                              "AND Checksum NOT IN (SELECT DISTINCT(Basis) FROM Checksums WHERE Basis IS NOT NULL)")
        for row in c.fetchall():
            yield row[0]

    def compact(self):
        c = self.conn.execute("VACUUM")

    def deleteChecksum(self, checksum):
        self.logger.debug("Deleting checksum: %s", checksum)
        c = self.cursor.execute("DELETE FROM Checksums WHERE Checksum = :checksum", {"checksum": checksum})
        return self.cursor.rowcount

    def commit(self):
        self.conn.commit()

    def __del__(self):
        self.logger.info("Closing DB: {}".format(self.dbName))
        if self.conn:
            if self.currBackupSet:
                self.conn.execute("UPDATE Backups SET EndTime = :now WHERE BackupSet = :backup",
                                    { "now": time.time(), "backup": self.currBackupSet })
            self.conn.commit()
            self.conn.close()

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
