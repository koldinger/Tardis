import sqlite3
import logging

def checkVersion(conn, version, log):
    s = conn.execute('SELECT Value FROM Config WHERE Key = "SchemaVersion"')
    t = s.fetchone()
    if int(t[0]) != version:
        log.error("Invalid database schema version: {}".format(t[0]))
        raise Exception("Invalid database schema version: {}".format(t[0]))

def updateVersion(conn, version, log):
    # Ugh, make sure the last element is a tuple, otherwise the string will get broken into multiple characters
    conn.execute('INSERT OR REPLACE INTO Config (Key, Value) VALUES ("SchemaVersion", ?)', (str(version + 1),) )
    log.info("Upgrade to schema version {} complete".format(version + 1))
