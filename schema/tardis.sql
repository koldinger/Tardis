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
    Completed       INTEGER DEFAULT 0,
    Priority        INTEGER DEFAULT 1,
    Full            INTEGER DEFAULT 0,
    ClientVersion   CHARACTER,
    ServerVersion   CHARACTER,
    ClientIP        CHARACTER
);

CREATE TABLE IF NOT EXISTS CheckSums (
    Checksum    CHARACTER UNIQUE NOT NULL,
    ChecksumId  INTEGER PRIMARY KEY AUTOINCREMENT,
    Size        INTEGER,
    Basis       INTEGER,
    DeltaSize   INTEGER,
    DiskSize    INTEGER,
    Compressed  INTEGER,            -- Boolean
    ChainLength INTEGER,
    InitVector  BLOB,
    Added       INTEGER,            -- References BackupSet, but not foreign key, as sets can be deleted.
    IsFile      INTEGER,            -- Boolean, is there a file backing this checksum
    FOREIGN KEY(Basis) REFERENCES CheckSums(Checksum)
);

CREATE TABLE IF NOT EXISTS Names (
    Name        CHARACTER UNIQUE NOT NULL,
    NameId      INTEGER PRIMARY KEY AUTOINCREMENT
);

CREATE TABLE IF NOT EXISTS Files (
    NameId      INTEGER   NOT NULL,
    FirstSet    INTEGER   NOT NULL,
    LastSet     INTEGER   NOT NULL,
    Inode       INTEGER   NOT NULL,
    Device      INTEGER   NOT NULL,
    Parent      INTEGER   NOT NULL,
    ParentDev   INTEGER   NOT NULL,
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
    NLinks      INTEGER,
    XattrID     INTEGER,
    AclID       INTEGER,

    PRIMARY KEY(NameId, FirstSet, LastSet, Parent, ParentDev),
    FOREIGN KEY(NameId)      REFERENCES Names(NameId),
    FOREIGN KEY(ChecksumId)  REFERENCES CheckSums(ChecksumIdD)
    FOREIGN KEY(XattrID)     REFERENCES CheckSums(ChecksumIdD)
    FOREIGN KEY(AclID)       REFERENCES CheckSums(ChecksumIdD)
);

CREATE INDEX IF NOT EXISTS CheckSumIndex ON CheckSums(Checksum);

CREATE INDEX IF NOT EXISTS InodeFirstIndex ON Files(Inode ASC, Device ASC, FirstSet ASC);
CREATE INDEX IF NOT EXISTS ParentFirstIndex ON Files(Parent ASC, ParentDev ASC, FirstSet ASC);
CREATE INDEX IF NOT EXISTS InodeLastIndex ON Files(Inode ASC, Device ASC, LastSet ASC);
CREATE INDEX IF NOT EXISTS ParentLastndex ON Files(Parent ASC, ParentDev ASC, LastSet ASC);
CREATE INDEX IF NOT EXISTS NameIndex ON Names(Name ASC);
CREATE INDEX IF NOT EXISTS InodeIndex ON Files(Inode ASC, Device ASC, Parent ASC, ParentDev ASC, FirstSet ASC, LastSet ASC);

INSERT OR IGNORE INTO Backups (Name, StartTime, EndTime, ClientTime, Completed, Priority) VALUES (".Initial", 0, 0, 0, 1, 0);

CREATE VIEW IF NOT EXISTS VFiles AS
    SELECT Names.Name AS Name, Inode, Device, Parent, ParentDev, Dir, Link, Size, MTime, CTime, ATime, Mode, UID, GID, NLinks, Checksum, Backups.BackupSet, Backups.Name AS Backup
    FROM Files
    JOIN Names ON Files.NameId = Names.NameId
    JOIN Backups ON Backups.BackupSet BETWEEN Files.FirstSet AND Files.LastSet
    LEFT OUTER JOIN Checksums ON Files.ChecksumId = Checksums.ChecksumId;

INSERT OR REPLACE INTO Config (Key, Value) VALUES ("SchemaVersion", "7");
INSERT OR REPLACE INTO Config (Key, Value) VALUES ("VacuumInterval", "5");
