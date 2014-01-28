CREATE TABLE IF NOT EXISTS Backups (
    Name            CHARACTER UNIQUE,
    StartTime       CHARACTER,
    EndTime         CHARACTER,
    ClientTime      CHARACTER,
    Session         CHARACTER UNIQUE,
    Completed       INTEGER,
    Priority        INTEGER DEFAULT 1,
    BackupSet       INTEGER PRIMARY KEY AUTOINCREMENT
);

CREATE TABLE IF NOT EXISTS CheckSums (
    Checksum    CHARACTER UNIQUE NOT NULL,
    ChecksumId  INTEGER PRIMARY KEY AUTOINCREMENT,
    Size        INTEGER,
    Basis       INTEGER,
    FOREIGN KEY(Basis) REFERENCES CheckSums(Checksum)
);

CREATE TABLE IF NOT EXISTS Names (
    Name        CHARACTER UNIQUE NOT NULL,
    NameId      INTEGER PRIMARY KEY AUTOINCREMENT
);

CREATE TABLE IF NOT EXISTS Files (
    NameId      INTEGER   NOT NULL,
    BackupSet   INTEGER   NOT NULL,
    Inode       INTEGER   NOT NULL,
    Parent      INTEGER   NOT NULL,
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
    PRIMARY KEY(NameId, BackupSet, Parent),
    FOREIGN KEY(NameId)      REFERENCES Names(NameId),
    FOREIGN KEY(ChecksumId)  REFERENCES CheckSums(ChecksumIdD),
    FOREIGN KEY(BackupSet)   REFERENCES Backups(BackupSet)
);

CREATE INDEX IF NOT EXISTS CheckSumIndex ON CheckSums(Checksum);

CREATE INDEX IF NOT EXISTS InodeIndex ON Files(Inode ASC, BackupSet ASC);
CREATE INDEX IF NOT EXISTS ParentIndex ON Files(Parent ASC, BackupSet ASC);
CREATE INDEX IF NOT EXISTS NameIndex ON Names(Name ASC);

-- CREATE INDEX IF NOT EXISTS NameIndex ON Files(Name ASC, BackupSet ASC, Parent ASC);

INSERT OR IGNORE INTO Backups (Name, StartTime, EndTime, ClientTime, Completed, Priority) VALUES (".Initial", 0, 0, 0, 1, 0);

CREATE VIEW IF NOT EXISTS VFiles AS
    SELECT Name, Inode, Parent, Dir, Link, Size, MTime, CTime, ATime, Mode, UID, GID, NLinks, Checksum, BackupSet
    FROM Files
    JOIN Names ON Files.NameId = Names.NameId
    LEFT OUTER JOIN Checksums ON Files.ChecksumId = Checksums.ChecksumId;
