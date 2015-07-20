#! /usr/bin/python

import sys
sys.path.insert(0, '.')

from Tardis import Defaults, Util, TardisDB, TardisCrypto
import os.path
import logging
import argparse
import hashlib


def processArgs():
    parser = argparse.ArgumentParser(description='Set a token/password')
    parser.add_argument('--database', '-D', dest='database', default=Defaults.getDefault('TARDIS_DB'),      help="Database to use.  Default: %(default)s")
    parser.add_argument('--client', '-C',   dest='client',   default=Defaults.getDefault('TARDIS_CLIENT'),  help="Client to list on.  Default: %(default)s")
    parser.add_argument('--dbname',         dest='dbname',   default=Defaults.getDefault('TARDIS_DBNAME'),  help="Name of the database file. Default: %(default)s")

    passgroup= parser.add_argument_group("Password/Encryption specification options")
    pwgroup = passgroup.add_mutually_exclusive_group()
    pwgroup.add_argument('--password', '-p',dest='password', default=None, nargs='?', const=True,       help='Encrypt files with this password')
    pwgroup.add_argument('--password-file', dest='passwordfile', default=None,                          help='Read password from file')
    pwgroup.add_argument('--password-url',  dest='passwordurl', default=None,                           help='Retrieve password from the specified URL')
    pwgroup.add_argument('--password-prog', dest='passwordprog', default=None,                          help='Use the specified command to generate the password on stdout')

    return parser.parse_args()

def main():
    logging.basicConfig(level=logging.INFO)
    crypto = None
    token = None
    args = processArgs()
    password = Util.getPassword(args.password, args.passwordfile, args.passwordurl, args.passwordprog)

    if password:
        crypto = TardisCrypto.TardisCrypto(password, args.client)
        token = crypto.createToken()

    path = os.path.join(args.database, args.client, args.dbname)
    db = TardisDB.TardisDB(path, token=token, backup=False)

    if crypto:
        (a, b) = db.getKeys()
        crypto.setKeys(a, b)

    conn = db.conn
    dirs = conn.execute("SELECT Name as name, Inode AS inode, Device AS device, FirstSet as firstset, LastSet AS lastset FROM Files JOIN Names ON Files.NameId = Names.NameId WHERE Dir = 1")
    while True:
        batch = dirs.fetchmany()
        if not batch:
            break
        for d in batch:
            name     = d['name']
            inode    = d['inode']
            device   = d['device']
            firstset = d['firstset']
            lastset  = d['lastset']

            files = db.readDirectory((inode, device), current=lastset)
            names = [x['name'] for x in files]
            if crypto:
                names = map(crypto.decryptFilename, names)
                name = crypto.decryptFilename(name)
            names = sorted(names)
            m = hashlib.md5()
            for f in names:
                m.update(f)
            checksum = m.hexdigest()
            print("%-20s (%d, %d) [%d %d] -- %s %d") % (name, inode, device, firstset, lastset, checksum, len(names))
            ckinfo = db.getChecksumInfo(checksum)
            if ckinfo:
                cksid = ckinfo['checksumid']
            else:
                cksid = db.insertChecksumFile(checksum, size=len(names), isFile=False)

            db.updateDirChecksum((inode, device), cksid, current=lastset)
        conn.commit()

if __name__ == "__main__":
    main()
