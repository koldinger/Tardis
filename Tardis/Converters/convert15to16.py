import sqlite3
import sys
import os.path
import logging

from . import convertutils

version = 15

def upgrade(conn, logger):
    convertutils.checkVersion(conn, version, logger)

    conn.execute("ALTER TABLE Backups ADD COLUMN PurgeTime TEXT")
    conn.execute("ALTER TABLE Backups ADD COLUMN ClientEndTime TEXT")
    conn.execute("ALTER TABLE Backups ADD COLUMN Vacuumed INTEGER DEFAULT 0")

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
