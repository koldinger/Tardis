import sqlite3
import sys
import os.path
import logging

import convertutils

version = 8

def upgrade(conn, logger):
    convertutils.checkVersion(conn, version, logger)

    conn.execute("ALTER TABLE Backups ADD COLUMN ClientConfigId INTEGER")
    conn.execute(
    """
        CREATE TABLE IF NOT EXISTS ClientConfig (
            ClientConfigID  INTEGER PRIMARY KEY AUTOINCREMENT,
            ClientConfig    TEXT
        )
    """
    )

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
