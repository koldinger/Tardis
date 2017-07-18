import sqlite3
import sys
import os.path
import logging
import convertutils

version = 4

def upgrade(conn, logger):
    convertutils.checkVersion(conn, version, logger)

    conn.execute("ALTER TABLE Checksums ADD COLUMN Added INTEGER")
    conn.execute("ALTER TABLE Checksums ADD COLUMN IsFile INTEGER")         # Old version only uses checksums for files.

    conn.execute("UPDATE Checksums SET IsFile = 1")

    # This can be really slow.  Only enable it if you really want it.
    # conn.execute("UPDATE Checksums SET Added = (SELECT MIN(FirstSet) FROM Files WHERE Files.ChecksumID = Checksums.ChecksumID OR Files.XattrID = Checksums.ChecksumID OR Files.AclID = Checksums.ChecksumId)")

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
