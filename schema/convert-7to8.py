import sqlite3
import sys
import os.path
import logging

version = 7

def upgrade(conn, logger):
    s = conn.execute('SELECT Value FROM Config WHERE Key = "SchemaVersion"')
    t = s.fetchone()
    if int(t[0]) != version:
        logger.error("Invalid database schema version: {}".format(t[0]))
        raise Exception("Invalid version {}.  Expected {}".format(t[0], version)

	conn.execute("ALTER TABLE Backups ADD COLUMN FilesFull INTEGER")
	conn.execute("ALTER TABLE Backups ADD COLUMN FilesDelta INTEGER")
	conn.execute("ALTER TABLE Backups ADD COLUMN BytesReceived INTEGER")

	conn.execute("ALTER TABLE CheckSums ADD COLUMN Encrypted INTEGER")

	conn.execute("UPDATE CheckSums SET Encrypted = 1 WHERE InitVector IS NOT NULL")
	conn.execute("UPDATE CheckSums SET Encrypted = 0 WHERE InitVector IS NULL")

	conn.execute('INSERT OR REPLACE INTO Config (Key, Value) VALUES ("SchemaVersion", ?)', str(version + 1))

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