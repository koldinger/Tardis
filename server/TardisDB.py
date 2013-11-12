import sqlite3
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

class TardisDB(object):
    def __init__(self, dbname):
        """ Initialize the connection to a per-machine Tardis Database"""
        self.dbName = dbname
        self.conn = sqlite3.connect(self.dbName)
        # TODO: Load the tables?????
        # TODO: Set last complete backup set
        c = self.conn.cursor()
        c.execute("SELECT Name, BackupSet FROM Backups WHERE Completed = 1 ORDER BY BackupSet DESC LIMIT 1")
        row = c.fetchone()
        self.prevBackupName = row[0]
        self.prevBackupSet = row[1]
        print "Last Backup Set: {} {} ".format(self.prevBackupName, self.prevBackupSet)

    def newBackupSet(self, name, session):
        """ Create a new backupset.  Set the current backup set to be that set. """
        c = self.conn.cursor()
        c.execute("INSERT INTO Backups (Name, Completed, Timestamp, Session) VALUES (:name, 0, :now, :session)",
                  {"name": name, "now": datetime.now(), "session": session})
        self.backupSet = c.lastrowid
        self.backupName = name
        self.conn.commit()
        return self.backupSet

    def getFileInfoByName(self, name, parent):
        """ Lookup a file in a directory in the previous backup set"""
        c = self.conn.cursor()
        c.execute("SELECT "
                  "Name as name, Inode as inode, Dir as dir, Size as size, MTime as mtime, CTime as ctime, Mode as mode, UID as uid, GID as gid "
                  "FROM Files WHERE Name =:name AND Dir =:parent AND BackupSet =:backup",
                  {"name": name, "parent": parent, "backup": self.backupSet})
        return c.fetchone()

    def getFileByInode(self, inode):
        c = self.conn.cursor()
        c.execute("SELECT "
                  "Name as name, Inode as inode, Dir as dir, Size as size, MTime as mtime, CTime as ctime, Mode as mode, UID as uid, GID as gid "
                  "FROM Files WHERE Inode = :inode AND BackupSet = :backup",
                  {"inode": inode, "backup": self.backupSet})
        return c.fetchone()


    def copyChecksum(self, name, parent):
        c = self.conn.cursor()
        c.execute("UPDATE Files SET Checksum = (SELECT CheckSum FROM Files WHERE Dir = :parent AND Name = :name AND BackupSet := :prev) "
                  "WHERE Dir = :parent AND Name = :name AND BackupSet := :backup)",
                  {"name": name, "parent": parent, "prev": self.prevBackupSet, "backup": self.backupSet})

    def insertFile(self, fileInfo):
        c = self.conn.cursor()
        temp = fileInfo
        temp["backup"] = self.backupSet
        c.execute("INSERT INTO Files (Name, BackupSet, Inode, CheckSum, Dir, Size, MTime, CTime, ATime, Mode, UID, GID) "
                  "VALUES            (:name, :backup, :inode, :cksum, :dir, :size, :mtime, :ctime, :atime, :mode, :uid, :gid)",
                  temp)

    def completeBackup(self):
        self.conn.execute("UPDATE Backups SET Completed = 1 WHERE BackupSet = :backup", self.backupSet)
        self.commit()

    def commit(self):
        self.conn.commit()

    def __del__(self):
        print "Closing DB"
        self.conn.commit()
        self.conn.close()

if __name__ == "__main__":
    import sys
    import uuid
    x = TardisDB(sys.argv[1])
    x.newBackupSet(sys.argv[2], str(uuid.uuid1()))
    print x.getFileInfoByName("File1", 1)
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
    x.commit()
