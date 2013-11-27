CREATE TABLE IF NOT EXISTS Backups (
    Name        CHARACTER UNIQUE,
    Timestamp   CHARACTER,
    Session     CHARACTER UNIQUE,
    Completed   INTEGER,
    BackupSet   INTEGER PRIMARY KEY AUTOINCREMENT
);

CREATE TABLE IF NOT EXISTS CheckSums (
    Checksum    CHARACTER UNIQUE NOT NULL,
    ChecksumId  INTEGER PRIMARY KEY AUTOINCREMENT,
    Size        INTEGER,
    Basis       CHARACTER,
    FOREIGN KEY(Basis) REFERENCES CheckSums(Checksum)
);

CREATE INDEX IF NOT EXISTS CheckSumIndex ON CheckSums(Checksum);

CREATE TABLE IF NOT EXISTS Files (
    Name        CHARACTER NOT NULL,
    BackupSet   INTEGER   NOT NULL,
    Inode       INTEGER   NOT NULL,
    Parent      INTEGER   NOT NULL,
    ChecksumId  INTEGER,
    Dir         INTEGER,
    Size        INTEGER,
    MTime       INTEGER,
    CTime       INTEGER,
    ATime       INTEGER,
    Mode        INTEGER,
    UID         INTEGER,
    GID         INTEGER, 
    NLinks      INTEGER,
    FOREIGN KEY(ChecksumId)  REFERENCES CheckSums(ChecksumIdD),
    FOREIGN KEY(BackupSet)   REFERENCES Backups(BackupSet)
);

CREATE INDEX IF NOT EXISTS FilesID ON Files(Parent ASC, Name ASC, BackupSet ASC);

INSERT INTO Backups (Name, Timestamp, Completed) VALUES ("Initial", NULL, 1);
