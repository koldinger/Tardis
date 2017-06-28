#! /usr/bin/python

from Tardis import Defaults, Util, TardisDB, TardisCrypto, CacheDir, librsync, Regenerator
import sqlite3
import argparse, logging
import os.path
import os
import base64
import hashlib
import sys

logger = None

def encryptFilenames(db, crypto):
    systemencoding = sys.getfilesystemencoding()
    conn = db.conn
    c = conn.cursor()
    c2 = conn.cursor()
    try:
        r = c.execute("SELECT Name, NameID FROM Names")
        while True:
            row = r.fetchone()
            if row is None:
                break
            (name, nameid) = row
            newname = crypto.encryptFilename(name.decode(systemencoding, 'replace'))
            c2.execute('UPDATE Names SET Name = ? WHERE NameID = ?', (newname, nameid))
        conn.commit()
    except Exception as e:
        logger.error("Caught exception encrypting filename %s: %s", name, str(e))
        conn.rollback()

def encryptFile(checksum, cacheDir, cipher, iv, pad, hmac, nameHmac):
    f = cacheDir.open(checksum, 'rb')
    o = cacheDir.open(checksum + '.enc', 'wb')
    o.write(iv)
    hmac.update(iv)
    for chunk, eof in Util._chunks(f, 64 * 1024):
        if eof:
            chunk = pad(chunk)
        ochunk = cipher.encrypt(chunk)
        o.write(ochunk)
        hmac.update(ochunk)
    o.write(hmac.digest())
    o.close()

def processFull(checksum, regenerator, cacheDir, nameMac, signature=True):
    i = regenerator.recoverChecksum(checksum)
    sig = None
    if signature:
        output = cacheDir.open(checksum + ".sig", "wb+")
        sig = librsync.SignatureJob(output)

    data = i.read(16 * 1024)
    while data:
        nameMac.update(data)
        if sig:
            sig.step(data)
        data = i.read(16 * 1024)

def encryptFilesAtLevel(db, crypto, cacheDir, chainlength=0):
    logger.info("Encrypting files which chainlength = %d", chainlength)
    conn = db.conn
    c = conn.cursor()
    regenerator = Regenerator.Regenerator(cacheDir, db, crypto)

    r = c.execute("SELECT Checksum, Size, Basis, Compressed FROM Checksums WHERE Encrypted = 0 AND IsFile = 1 AND ChainLength = :chainlength ORDER BY CheckSum", {"chainlength": chainlength})
    checksums = r.fetchall()
    c2 = conn.cursor()
    for row in checksums:
        try:
            checksum = row[0]
            logger.info("Encrypting %s", checksum)
            signature = not cacheDir.exists(checksum + ".sig")
                
            nameHmac = crypto.getHash()
            processFull(checksum, regenerator, cacheDir, nameHmac, signature)

            iv = crypto.getIV()
            cipher = crypto.getContentCipher(iv)
            hmac = crypto.getHash(func=hashlib.sha512)
            encryptFile(checksum, cacheDir, cipher, iv, crypto.pad, hmac, nameHmac)
            #biv = base64.b64encode(iv)
            newCks = nameHmac.hexdigest()

            ost = os.stat(cacheDir.path(checksum))
            st = os.stat(cacheDir.path(checksum + ".enc"))

            logger.debug("{} => {}: {} -> {}".format(checksum, newCks, ost.st_size, st.st_size))

            c2.execute('UPDATE CheckSums SET Encrypted = 1, DiskSize = :size, Checksum = :newcks WHERE Checksum = :cks', {"size": st.st_size, "newcks": newCks, "cks": checksum})
            c2.execute('UPDATE CheckSums SET Basis = :newcks WHERE Basis = :cks', {"newcks": newCks, "cks": checksum})

            # recordMetaData(cache, checksum, size, compressed, encrypted, disksize, basis=None, logger=None):
            Util.recordMetadata(cacheDir, newcks, row[1], row[3], True, st.st_size, basis=row[2], logger=logger)

            if not cacheDir.move(checksum, checksum + ".bak"):
                cacheDir.remove(checksum + ".enc")
                raise Exception("Unable to move old version to backup: {} -> {}".format(checksum, checksum + ".bak"))
            if not cacheDir.move(checksum + '.enc', newCks):
                raise Exception("Unable to rename encrypted file: {}".format(checksum))
            if not cacheDir.move(checksum + ".sig", newCks + ".sig"):
                raise Exception("Unable to rename signature file: {}".format(checksum + ".sig"))

            conn.commit()
            cacheDir.remove(checksum + '.meta')
            cacheDir.remove(checksum + '.bak')
        except Exception as e:
            conn.rollback()
            logger.error("Unable to convert checksum: %s :: %s", checksum, e)
            logger.exception(e)
            raise e

def encryptFiles(db, crypto, cacheDir):
    conn = db.conn
    r = conn.execute("SELECT MAX(ChainLength) FROM CheckSums")
    z = r.fetchone()[0]
    for level in range(z, -1, -1):
        encryptFilesAtLevel(db, crypto, cacheDir, level)

def generateSignatures(db, cacheDir):
    r = c.execute("SELECT Checksum FROM Checksums")
    regenerator = Regenerator.Regenerator(cacheDir, db, crypto)
    for row in r.fetchall():
        checksum = row[0]
        sigfile = checksum + '.sig'
        if not cacheDir.exists(sigfile):
            logger.info("Generating signature for {}".format(checksum))
            makeSig(checksum, regenerator, cacheDir)


def processArgs():
    parser = argparse.ArgumentParser(description='Encrypt the database')
    parser.add_argument('--database', '-D', dest='database', default=Defaults.getDefault('TARDIS_DB'),      help="Database to use.  Default: %(default)s")
    parser.add_argument('--client', '-C',   dest='client',   default=Defaults.getDefault('TARDIS_CLIENT'),  help="Client to list on.  Default: %(default)s")
    parser.add_argument('--dbname',         dest='dbname',   default=Defaults.getDefault('TARDIS_DBNAME'),  help="Name of the database file. Default: %(default)s")

    parser.add_argument('--filenames',      dest='filenames', action='store_true', default=False,       help='Encrypt filenames. Default=%(default)s')
    parser.add_argument('--files',          dest='files',     action='store_true', default=False,       help='Encrypt files. Default=%(default)s')
    #parser.add_argument('--signatures',     dest='sigs',      action='store_true', default=False,       help='Generate signatures. Default=%(default)s')

    passgroup= parser.add_argument_group("Password/Encryption specification options")
    pwgroup = passgroup.add_mutually_exclusive_group(required=True)
    pwgroup.add_argument('--password', '-P',dest='password', default=None, nargs='?', const=True,       help='Encrypt files with this password')
    pwgroup.add_argument('--password-file', dest='passwordfile', default=None,                          help='Read password from file')
    pwgroup.add_argument('--password-url',  dest='passwordurl', default=None,                           help='Retrieve password from the specified URL')
    pwgroup.add_argument('--password-prog', dest='passwordprog', default=None,                          help='Use the specified command to generate the password on stdout')

    return parser.parse_args()

def main():
    global logger
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('')
    args = processArgs()
    password = Util.getPassword(args.password, args.passwordfile, args.passwordurl, args.passwordprog)

    crypto = TardisCrypto.TardisCrypto(password, args.client)
    token = crypto.createToken()

    logger.info("Created token: %s", token)
    path = os.path.join(args.database, args.client, args.dbname)
    db = TardisDB.TardisDB(path, token=token, backup=False)
    (f, c) = db.getKeys()
    crypto.setKeys(f, c)

    cacheDir = CacheDir.CacheDir(os.path.join(args.database, args.client))

    #if args.sigs:
    #    generateSignatures(db, cacheDir)
    if args.filenames:
        encryptFilenames(db, crypto)
    if args.files:
        encryptFiles(db, crypto, cacheDir)

if __name__ == "__main__":
    main()
