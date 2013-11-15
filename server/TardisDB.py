import sqlite3
import shutil
import logging
from datetime import datetime


#CREATE TABLE IF NOT EXISTS Backups (
#    Name        CHARACTER UNIQUE,
#    Completed   INTEGER,
#    BackupSet   INTEGER UNIQUE);
#
#CREATE TABLE IF NOT EXISTS CheckSums (
#    Checksum    CHARACTER NOT NULL,
#    Based       CHARACTER
#);
#
#CREATE TABLE IF NOT EXISTS Files (
#    Name        CHARACTER NOT NULL,
#    BackupSet   INTEGER   NOT NULL,
#    Inode       INTEGER   NOT NULL,
#    CheckSum    CHARACTER NOT NULL,
#    Dir         INTEGER,
#    Size        INTEGER,
#    MTime       INTEGER,
#    CTime       INTEGER,
#    ATime       INTEGER,
#    Mode        INTEGER,
#    UID         INTEGER,
#    GID         INTEGER);

def makeDict(cursor, row):
    if row != None and cursor != None and len(row) != 0:
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d
    else:
        return None

class TardisDB(object):
    logger = logging.getLogger("DB")
    conn = None
    dbName = None

    def __init__(self, dbname):
        """ Initialize the connection to a per-machine Tardis Database"""
        self.logger.debug("Initializing connection to {}".format(dbname))
        self.dbName = dbname
        backup = dbname + ".bak"
        try:
            self.logger.debug("Backing up {}".format(dbname))
            shutil.copyfile(dbname, backup)
        except IOError:
            pass
        self.conn = sqlite3.connect(self.dbName)
        # TODO: Load the tables?????
        # TODO: Set last complete backup set
        c = self.conn.cursor()
        c.execute("SELECT Name, BackupSet FROM Backups WHERE Completed = 1 ORDER BY BackupSet DESC LIMIT 1")
        row = c.fetchone()
        self.prevBackupName = row[0]
        self.prevBackupSet = row[1]
        self.logger.info("Last Backup Set: {} {} ".format(self.prevBackupName, self.prevBackupSet))

    def newBackupSet(self, name, session):
        """ Create a new backupset.  Set the current backup set to be that set. """
        c = self.conn.cursor()
        c.execute("INSERT INTO Backups (Name, Completed, Timestamp, Session) VALUES (:name, 0, :now, :session)",
                  {"name": name, "now": datetime.now(), "session": session})
        self.backupSet = c.lastrowid
        self.backupName = name
        self.conn.commit()
        self.logger.info("Created new backup set: {}: {} {}".format(self.backupSet, name, session))
        return self.backupSet

    def getFileInfoByName(self, name, parent):
        """ Lookup a file in a directory in the previous backup set"""
        self.logger.debug("Looking up file by name {} {} {}".format(name, parent, self.prevBackupSet))
        c = self.conn.cursor()
        c.execute("SELECT "
                  "Name AS name, Inode AS inode, Dir AS dir, Parent AS parent, Size AS size, MTime AS mtime, CTime AS ctime, Mode AS mode, UID AS uid, GID AS gid, NLinks AS nlinks "
                  "FROM Files WHERE Name = :name AND Parent = :parent AND BackupSet = :backup",
                  {"name": name, "parent": parent, "backup": self.prevBackupSet})
        return makeDict(c, c.fetchone())

    def getFileInfoByInode(self, inode):
        self.logger.debug("Looking up file by inode {} {}".format(inode, self.prevBackupSet))
        c = self.conn.cursor()
        c.execute("SELECT "
                  "Name AS name, Inode AS inode, Dir AS dir, Parent AS parent, Size AS size, MTime AS mtime, CTime AS ctime, Mode AS mode, UID AS uid, GID AS gid, NLinks AS nlinks "
                  "FROM Files WHERE Inode = :inode AND BackupSet = :backup",
                  {"inode": inode, "backup": self.prevBackupSet})
        return makeDict(c, c.fetchone())

    def getFileInfoBySimilar(self, fileInfo):
        """ Find a file which is similar, namely the same size, inode, and mtime.  Identifies files which have moved. """
        self.logger.debug("Looking up file for similar info")
        c = self.conn.cursor()
        temp = fileInfo.copy()
        temp["backup"] = self.prevBackupSet
        c.execute("SELECT "
                  "Name AS name, Inode AS inode, Dir AS dir, Parent AS parent, Size AS size, MTime AS mtime, CTime AS ctime, Mode AS mode, UID AS uid, GID AS gid, Checksum AS cksum "
                  "FROM Files WHERE Inode = :inode AND Mtime = :mtime AND SIZE = :size AND CheckSum IS NOT NULL AND BackupSet = :backup",
                  temp)
        return makeDict(c, c.fetchone())

    def copyChecksum(self, old_inode, new_inode):
        c = self.conn.cursor()
        c.execute("UPDATE Files SET Checksum = (SELECT CheckSum FROM Files WHERE Inode = :oldInode AND BackupSet = :prev) "
                  "WHERE INode = :newInode AND BackupSet = :backup",
                  {"oldInode": old_inode, "newInode": new_inode, "prev": self.prevBackupSet, "backup": self.backupSet})

    def setChecksum(self, inode, checksum):
        c = self.conn.cursor()
        c.execute("UPDATE Files SET Checksum = :checksum WHERE Inode = :inode AND BackupSet = :backup",
                  {"inode": inode, "checksum": checksum, "backup": self.backupSet})


    def insertFile(self, fileInfo, parent):
        self.logger.debug("Inserting file: {}".format(str(fileInfo)))
        c = self.conn.cursor()
        temp = fileInfo.copy()
        temp["backup"] = self.backupSet
        temp["parent"] = parent
        c.execute("INSERT INTO Files (Name, BackupSet, Inode, Parent, Dir, Size, MTime, CTime, ATime, Mode, UID, GID, NLinks) "
                  "VALUES            (:name, :backup, :inode, :parent, :dir, :size, :mtime, :ctime, :atime, :mode, :uid, :gid, :nlinks)",
                  temp)

    def insertChecksumFile(self, checksum, basis=None):
        self.logger.debug("Inserting checksum file: {}".format(checksum))
        c = self.conn.cursor()
        c.execute("INSERT INTO CheckSums (CheckSum, Size, Basis) "
                  "VALUES                (:checksum, :size, :basis)",
                  {"checksum": checksum, "size": 0, "basis": basis })

    def completeBackup(self):
        self.conn.execute("UPDATE Backups SET Completed = 1 WHERE BackupSet = :backup", {"backup": self.backupSet})
        self.commit()

    def commit(self):
        self.conn.commit()

    def __del__(self):
        self.logger.info("Closing DB: {}".format(self.dbName))
        if self.conn:
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
    file = {
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
    x.insertFile(file)
    file = {
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
    x.insertFile(file)
    x.completeBackup()
    x.commit()

