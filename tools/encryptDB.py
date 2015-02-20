#! /usr/bin/python

from Tardis import Defaults, Util, TardisDB, TardisCrypto, CacheDir, librsync, Regenerate
import sqlite3
import argparse, logging
import os.path
import os
import base64

def encryptFilenames(db, crypto):
    conn = db.conn
    c = conn.cursor()
    c2 = conn.cursor()
    r = c.execute("SELECT Name, NameID FROM Names")
    while True:
        row = r.fetchone()
        if row is None:
            break
        (name, nameid) = row
        newname = crypto.encryptFilename(name)
        c2.execute('UPDATE Names SET Name = ? WHERE NameID = ?', (newname, nameid))

    conn.commit()

def encryptFile(checksum, cacheDir, cipher, pad):
    f = cacheDir.open(checksum, 'rb')
    o = cacheDir.open(checksum + '.enc', 'wb')
    while True:
        x = f.read(64 * 1024)
        if not x:
            break
        y = cipher.encrypt(pad(x))
        o.write(y)
    o.close()
    if not cacheDir.move(checksum, checksum + ".bak"):
        cacheDir.remove(checksum + ".enc")
        raise Exception("Unable to move old version to backup: %s", checksum)
    if not cacheDir.move(checksum + '.enc', checksum):
        raise Exception("Unable to rename encrypted file: %s", checksum)

def makeSig(checksum, regenerator, cacheDir):
    s = cacheDir.open(checksum + ".sig", "wb+")
    i = regenerator.recoverChecksum(checksum)
    librsync.signature(i, s)

def encryptFiles(db, crypto, cacheDir):
    logger = logging.getLogger('')
    conn = db.conn
    c = conn.cursor()
    regenerator = Regenerate.Regenerator(cacheDir, db, crypto)

    r = c.execute("SELECT Checksum FROM Checksums WHERE InitVector IS NULL ORDER BY CheckSum")
    checksums = r.fetchall()
    c2 = conn.cursor()
    for row in checksums:
        checksum = row[0]
        if not cacheDir.exists(checksum + ".sig"):
            logger.info("Making Signature for %s", checksum)
            makeSig(checksum, regenerator, cacheDir)
        logger.info("Encrypting %s", checksum)
        iv = crypto.getIV()
        cipher = crypto.getContentCipher(iv)
        encryptFile(checksum, cacheDir, cipher, crypto.pad)
        biv = base64.b64encode(iv)

        c2.execute('UPDATE CheckSums SET InitVector = ? WHERE Checksum = ?', (biv, checksum))
        conn.commit()
        cacheDir.remove(checksum + '.bak')

def processArgs():
    parser = argparse.ArgumentParser(description='Encrypt the database')
    parser.add_argument('--database', '-D', dest='database', default=Defaults.getDefault('TARDIS_DB'),      help="Database to use.  Default: %(default)s")
    parser.add_argument('--client', '-C',   dest='client',   default=Defaults.getDefault('TARDIS_CLIENT'),  help="Client to list on.  Default: %(default)s")
    parser.add_argument('--dbname',         dest='dbname',   default=Defaults.getDefault('TARDIS_DBNAME'),  help="Name of the database file. Default: %(default)s")

    parser.add_argument('--filenames',      dest='filenames', action='store_true', default=False,       help='Encrypt filenames. Default=%(default)s')
    parser.add_argument('--files',          dest='files',     action='store_true', default=False,       help='Encrypt files. Default=%(default)s')
    parser.add_argument('--signatures',     dest='sigs',      action='store_true', default=False,       help='Generate signatures. Default=%(default)s')

    passgroup= parser.add_argument_group("Password/Encryption specification options")
    pwgroup = passgroup.add_mutually_exclusive_group(required=True)
    pwgroup.add_argument('--password', '-p',dest='password', default=None, nargs='?', const=True,       help='Encrypt files with this password')
    pwgroup.add_argument('--password-file', dest='passwordfile', default=None,                          help='Read password from file')
    pwgroup.add_argument('--password-url',  dest='passwordurl', default=None,                           help='Retrieve password from the specified URL')
    pwgroup.add_argument('--password-prog', dest='passwordprog', default=None,                          help='Use the specified command to generate the password on stdout')

    return parser.parse_args()

def main():
    logging.basicConfig(level=logging.DEBUG)
    args = processArgs()
    password = Util.getPassword(args.password, args.passwordfile, args.passwordurl, args.passwordprog)

    crypto = TardisCrypto.TardisCrypto(password, args.client)
    token = crypto.createToken()

    path = os.path.join(args.database, args.client, args.dbname)
    db = TardisDB.TardisDB(path, token=token, backup=False)

    cacheDir = CacheDir.CacheDir(os.path.join(args.database, args.client))

    if args.filenames:
        encryptFilenames(db, crypto)
    if args.files:
        encryptFiles(db, crypto, cacheDir)

if __name__ == "__main__":
    main()
