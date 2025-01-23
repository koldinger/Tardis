-- vim: set et sw=4 sts=4 fileencoding=utf-8:
--
-- Tardis: A Backup System
-- Copyright 2013-2025, Eric Koldinger, All Rights Reserved.
-- kolding@washington.edu
--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions are met:
--
--     * Redistributions of source code must retain the above copyright
--       notice, this list of conditions and the following disclaimer.
--     * Redistributions in binary form must reproduce the above copyright
--       notice, this list of conditions and the following disclaimer in the
--       documentation and/or other materials provided with the distribution.
--     * Neither the name of the copyright holder nor the
--       names of its contributors may be used to endorse or promote products
--       derived from this software without specific prior written permission.
--
-- THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
-- AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-- IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-- ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
-- LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
-- CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
-- SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
-- INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
-- CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
-- ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
-- POSSIBILITY OF SUCH DAMAGE.

PRAGMA journal_mode=truncate;

CREATE TABLE IF NOT EXISTS Config (
    Key             TEXT PRIMARY KEY,
    Value           TEXT NOT NULL,
    Timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP

);

CREATE TABLE IF NOT EXISTS ClientConfig (
    ClientConfigId  INTEGER PRIMARY KEY AUTOINCREMENT,
    ClientConfig    TEXT
);


CREATE TABLE IF NOT EXISTS Backups (
    Name            TEXT UNIQUE,
    BackupSet       INTEGER PRIMARY KEY AUTOINCREMENT,
    StartTime       TEXT,
    EndTime         TEXT,
    PurgeTime       TEXT,
    ClientEndTime   TEXT,
    ClientTime      TEXT,
    Session         TEXT UNIQUE,
    Completed       INTEGER DEFAULT 0,
    Priority        INTEGER DEFAULT 1,
    Full            INTEGER DEFAULT 0,
    Vacuumed        INTEGER DEFAULT 0,
    Locked          INTEGER DEFAULT 0,
    
    ClientVersion   TEXT,
    ServerVersion   TEXT,
    SchemaVersion   INTEGER,
    ClientIP        TEXT,
    FilesFull       INTEGER,
    FilesDelta      INTEGER,
    BytesReceived   INTEGER,
    ClientConfigId  INTEGER,
    CmdLineId       INTEGER,
    ServerSession   TEXT,
    Exception       TEXT,
    ErrorMsg        TEXT,
    FOREIGN KEY(ClientConfigId) REFERENCES ClientConfig(ClientConfigId),
    FOREIGN KEY(CmdLineId) REFERENCES Checksums(ChecksumId)
);

CREATE TABLE IF NOT EXISTS CheckSums (
    Checksum    TEXT UNIQUE NOT NULL,
    ChecksumId  INTEGER PRIMARY KEY AUTOINCREMENT,
    Size        INTEGER,
    Basis       INTEGER,
    DeltaSize   INTEGER,
    DiskSize    INTEGER,
    Compressed  TEXT,
    Encrypted   INTEGER,            -- Boolean
    ChainLength INTEGER,
    Added       INTEGER,            -- References BackupSet, but not foreign key, as sets can be deleted.
    IsFile      INTEGER,            -- Boolean, is there a file backing this checksum
    FOREIGN KEY(Basis) REFERENCES CheckSums(Checksum)
);

CREATE TABLE IF NOT EXISTS Names (
    Name        TEXT UNIQUE NOT NULL,
    NameId      INTEGER PRIMARY KEY AUTOINCREMENT
);

CREATE TABLE IF NOT EXISTS Users (
    UserId      INTEGER PRIMARY KEY AUTOINCREMENT,
    NameId      INTEGER REFERENCES Names(NameId)
);

CREATE TABLE IF NOT EXISTS Groups (
    GroupId     INTEGER PRIMARY KEY AUTOINCREMENT,
    NameId      INTEGER REFERENCES Names(NameId)
);

CREATE TABLE IF NOT EXISTS Files (
    NameId      INTEGER  NOT NULL,
    FirstSet    INTEGER  NOT NULL,
    LastSet     INTEGER  NOT NULL,
    Inode       INTEGER  NOT NULL,
    Device      INTEGER  NOT NULL,
    Parent      INTEGER  NOT NULL,
    ParentDev   INTEGER  NOT NULL,
    ChecksumId  INTEGER,            -- On a file, represents the file data.  On a directory, the hash of the filenames in the directory.
                                    -- On a directory, this can be rewritten over time, and is the most recent hash.
    Dir         INTEGER,
    Link        INTEGER,
    MTime       INTEGER,
    CTime       INTEGER,
    ATime       INTEGER,
    Mode        INTEGER,
    UID         INTEGER,
    GID         INTEGER, 
    UserId      INTEGER,
    GroupId     INTEGER,
    NLinks      INTEGER,
    XattrID     INTEGER,
    AclID       INTEGER,

    PRIMARY KEY(NameId, FirstSet, LastSet, Parent, ParentDev),
    FOREIGN KEY(NameId)      REFERENCES Names(NameId),
    FOREIGN KEY(ChecksumId)  REFERENCES CheckSums(ChecksumId)
    FOREIGN KEY(XattrID)     REFERENCES CheckSums(ChecksumId)
    FOREIGN KEY(AclID)       REFERENCES CheckSums(ChecksumId)
    FOREIGN KEY(UserID)      REFERENCES Users(UserId)
    FOREIGN KEY(GroupID)     REFERENCES Groups(GroupID)
);

CREATE TABLE IF NOT EXISTS Tags (
    TagId       INTEGER PRIMARY KEY AUTOINCREMENT,
    BackupSet   INTEGER NOT NULL,
    NameId      INTEGER UNIQUE NOT NULL,
    FOREIGN KEY(BackupSet)   REFERENCES Backups(BackupSet),
    FOREIGN KEY(NameId)      REFERENCES Names(NameId)
);

CREATE INDEX IF NOT EXISTS CheckSumIndex ON CheckSums(Checksum);

CREATE INDEX IF NOT EXISTS InodeFirstIndex ON Files(Inode ASC, Device ASC, FirstSet ASC);
CREATE INDEX IF NOT EXISTS ParentFirstIndex ON Files(Parent ASC, ParentDev ASC, FirstSet ASC);
CREATE INDEX IF NOT EXISTS InodeLastIndex ON Files(Inode ASC, Device ASC, LastSet ASC);
CREATE INDEX IF NOT EXISTS ParentLastndex ON Files(Parent ASC, ParentDev ASC, LastSet ASC);
CREATE INDEX IF NOT EXISTS NameIndex ON Names(Name ASC);
CREATE INDEX IF NOT EXISTS InodeIndex ON Files(Inode ASC, Device ASC, Parent ASC, ParentDev ASC, FirstSet ASC, LastSet ASC);
CREATE INDEX IF NOT EXISTS FileChksumIndex ON Files(ChecksumID ASC);

INSERT OR IGNORE INTO Backups (Name, StartTime, EndTime, ClientTime, Completed, Priority, FilesFull, FilesDelta, BytesReceived) VALUES (".Initial", 0, 0, 0, 1, 0, 0, 0, 0);
    
CREATE VIEW IF NOT EXISTS VFiles AS
    SELECT Names.Name AS Name, Inode, Device, Parent, ParentDev, Dir, Link, Size, MTime, CTime, ATime, Mode, UID, GID, NLinks, Checksum, Backups.BackupSet, Backups.Name AS Backup
    FROM Files
    JOIN Names ON Files.NameId = Names.NameId
    JOIN Backups ON Backups.BackupSet BETWEEN Files.FirstSet AND Files.LastSet
    LEFT OUTER JOIN CheckSums ON Files.ChecksumId = CheckSums.ChecksumId;

INSERT OR REPLACE INTO Config (Key, Value) VALUES ("SchemaVersion", "22");

INSERT OR REPLACE INTO Config (Key, Value) VALUES ("VacuumInterval", "5");
