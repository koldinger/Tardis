CREATE TABLE IF NOT EXISTS Backups (
    Name        CHARACTER UNIQUE,
    Timestamp   CHARACTER,
    Session     CHARACTER UNIQUE,
    Completed   INTEGER,
    BackupSet   INTEGER PRIMARY KEY AUTOINCREMENT
);

CREATE TABLE IF NOT EXISTS CheckSums (
    Checksum    CHARACTER UNIQUE NOT NULL,
    Id          INTEGER PRIMARY KEY AUTOINCREMENT,
    Size        INTEGER,
    Basis       CHARACTER
);

CREATE INDEX IF NOT EXISTS CheckSums.CheckSumIndex ON CheckSums(Checksum);

CREATE TABLE IF NOT EXISTS Files (
    Name        CHARACTER NOT NULL,
    BackupSet   INTEGER   NOT NULL,
    Inode       INTEGER   NOT NULL,
    Parent      INTEGER   NOT NULL,
    CheckSum    CHARACTER,
    Dir         INTEGER,
    Size        INTEGER,
    MTime       INTEGER,
    CTime       INTEGER,
    ATime       INTEGER,
    Mode        INTEGER,
    UID         INTEGER,
    GID         INTEGER, 
    NLinks      INTEGER,
    FOREIGN KEY(BackupSet) REFERENCES Backups(BackupSet)
);

INSERT INTO Backups (Name, Timestamp, Completed) VALUES ("Initial", NULL, 1);
