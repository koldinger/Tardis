import sqlite3
import sys
import os.path
import logging

import convertutils

version = 10

def upgrade(conn, logger):
    convertutils.checkVersion(conn, version, logger)

    conn.execute('UPDATE Checksums SET Compressed = "zlib" WHERE Compressed IS 1')
    conn.execute('UPDATE Checksums SET Compressed = "none" WHERE Compressed IS 0')

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
