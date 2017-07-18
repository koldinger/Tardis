import sqlite3
import sys
import os.path
import logging

import convertutils

version = 7

def upgrade(conn, logger):
    convertutils.checkVersion(conn, version, logger)

    conn.execute("ALTER TABLE Backups ADD COLUMN FilesFull INTEGER")
    conn.execute("ALTER TABLE Backups ADD COLUMN FilesDelta INTEGER")
    conn.execute("ALTER TABLE Backups ADD COLUMN BytesReceived INTEGER")

    conn.execute("ALTER TABLE CheckSums ADD COLUMN Encrypted INTEGER")

    conn.execute("UPDATE CheckSums SET Encrypted = 1 WHERE InitVector IS NOT NULL")
    conn.execute("UPDATE CheckSums SET Encrypted = 0 WHERE InitVector IS NULL")

    convertutils.updateVersion(conn, version, logger)
    conn.commit()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger('')

    if len(sys.argv) > 1:
        db = sys.argv[1]
    else:
        db = "tardis.db"

    conn = sqlite3.connect(db)
    upgrade(conn, logger)
