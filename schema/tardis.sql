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
    Compressed  INTEGER,            -- Boolean
    InitVector  BLOB,
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
    PRIMARY KEY(NameId, FirstSet, LastSet, Parent, ParentDev),
    FOREIGN KEY(NameId)      REFERENCES Names(NameId),
    FOREIGN KEY(ChecksumId)  REFERENCES CheckSums(ChecksumIdD)
);

CREATE INDEX IF NOT EXISTS CheckSumIndex ON CheckSums(Checksum);

CREATE INDEX IF NOT EXISTS InodeFirstIndex ON Files(Inode ASC, FirstSet ASC);
CREATE INDEX IF NOT EXISTS ParentFirstIndex ON Files(Parent ASC, FirstSet ASC);
CREATE INDEX IF NOT EXISTS InodeLastIndex ON Files(Inode ASC, LastSet ASC);
CREATE INDEX IF NOT EXISTS ParentLastndex ON Files(Parent ASC, LastSet ASC);
CREATE INDEX IF NOT EXISTS NameIndex ON Names(Name ASC);

-- CREATE INDEX IF NOT EXISTS NameIndex ON Files(Name ASC, BackupSet ASC, Parent ASC);

INSERT OR IGNORE INTO Backups (Name, StartTime, EndTime, ClientTime, Completed, Priority) VALUES (".Initial", 0, 0, 0, 1, 0);

INSERT OR REPLACE INTO Config (Key, Value) VALUES ("SchemaVersion", "2");

CREATE VIEW IF NOT EXISTS VFiles AS
    SELECT Names.Name AS Name, Inode, Device, Parent, ParentDev, Dir, Link, Size, MTime, CTime, ATime, Mode, UID, GID, NLinks, Checksum, Backups.BackupSet, Backups.Name AS Backup
    FROM Files
    JOIN Names ON Files.NameId = Names.NameId
    JOIN Backups ON Backups.BackupSet BETWEEN Files.FirstSet AND Files.LastSet
    LEFT OUTER JOIN Checksums ON Files.ChecksumId = Checksums.ChecksumId;
