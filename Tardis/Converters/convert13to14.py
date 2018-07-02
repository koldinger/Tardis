import sqlite3
import sys
import os.path
import logging

from . import convertutils

version = 13

def upgrade(conn, logger):
    convertutils.checkVersion(conn, version, logger)

    conn.execute("ALTER TABLE Config RENAME TO _Config_Orig")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS Config (
    Key             TEXT PRIMARY KEY,
    Value           TEXT NOT NULL,
    Timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.execute("INSERT INTO Config (Key, Value, Timestamp) " + 
                 "  SELECT Key, Value, NULL FROM _Config_Orig")

    conn.execute("DROP TABLE _Config_Orig")

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
