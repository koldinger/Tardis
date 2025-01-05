#! /usr/bin/env python3
# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2025, Eric Koldinger, All Rights Reserved.
# kolding@washington.edu
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import argparse, logging
import progressbar

from Tardis import Util, librsync, Regenerator, Config

logger = None

def encryptFilenames(db, crypto):
    conn = db.conn
    c = conn.cursor()
    c2 = conn.cursor()
    names = 0
    r = c.execute("SELECT COUNT(*) FROM Names")
    z = r.fetchone()[0]
    logger.info("Encrypting %d filenames", z)
    with progressbar.ProgressBar(max_value=z) as pbar:
        try:
            r = c.execute("SELECT Name, NameID FROM Names")
            while True:
                row = r.fetchone()
                if row is None:
                    break
                (name, nameid) = row
                newname = crypto.encryptFilename(name)
                c2.execute('UPDATE Names SET Name = ? WHERE NameID = ?', (newname, nameid))
                names = names + 1
                pbar.update(names)
            conn.commit()
        except Exception as e:
            logger.error("Caught exception encrypting filename %s: %s", name, str(e))
            logger.exception(e)
            conn.rollback()
    logger.info("Encrypted %d names", names)

def encryptFile(checksum, cacheDir, cipher, iv, output = None):
    f = cacheDir.open(checksum, 'rb')
    if output is None:
        output = checksum + '.enc'
    o = cacheDir.open(output, 'wb')
    o.write(iv)
    nb = len(iv)
    cipher.update(iv)
    # Encrypt the chunks
    for chunk, _ in Util._chunks(f, 64 * 1024):
        ochunk = cipher.encrypt(chunk)
        o.write(ochunk)
        nb = nb + len(ochunk)

    # add the digest chunk
    ochunk = cipher.digest()
    o.write(ochunk)
    nb = nb + len(ochunk)

    o.close()
    f.close()

    return nb

def generateFullFileInfo(checksum, regenerator, cacheDir, nameMac, signature=True, basis=None):
    i = regenerator.recoverChecksum(checksum, basisFile=basis)
    sig = None
    logger.debug("    Generating HMAC for %s.  Generating signature: %s", checksum, str(signature))
    if signature:
        output = cacheDir.open(checksum + ".sig", "wb+")
        sig = librsync.SignatureJob(output)

    data = i.read(64 * 1024)
    while data:
        nameMac.update(data)
        if sig:
            sig.step(data)
        data = i.read(64 * 1024)
    # Return a handle on the full file object.  Allows it to be reused in the next step
    i.close()
    return i

suffixes = ['','KB','MB','GB', 'TB', 'PB']

numFiles = 0

def processFile(cksInfo, regenerator, cacheDir, db, crypto, pbar, basis=None):
    global numFiles
    newCks = ''
    try:
        conn = db.conn
        c2 = conn.cursor()
        checksum = cksInfo['checksum']
        if cksInfo['encrypted']:
            logger.info("    Skipping  %s", checksum)
            return None

        pbar.update(numFiles)

        #logger.info("  Processing %s (%s, %s)", checksum, Util.fmtSize(cksInfo['size'], formats = suffixes), Util.fmtSize(cksInfo['diskSize'], formats = suffixes))
        signature = not cacheDir.exists(checksum + ".sig")

        nameHmac = crypto.getHash()
        retFile = generateFullFileInfo(checksum, regenerator, cacheDir, nameHmac, signature, basis)
        if basis:
            basis.close()
        newCks = nameHmac.hexdigest()

        #logger.info("    Hashed     %s => %s (%s, %s)", checksum, newCks, Util.fmtSize(cksInfo['size'], formats = suffixes), Util.fmtSize(cksInfo['diskSize'], formats = suffixes))

        iv = crypto.getIV()
        cipher = crypto.getContentCipher(iv)
        #hmac = crypto.getHash(func=hashlib.sha512)
        fSize = encryptFile(checksum, cacheDir, cipher, iv, output=newCks)
        #logger.info("    Encrypted  %s => %s (%s)", checksum, newCks, Util.fmtSize(fSize, formats = ['','KB','MB','GB', 'TB', 'PB']))

        #cacheDir.link(checksum + '.enc', newCks, soft=False)
        #cacheDir.link(checksum + ".sig", newCks + ".sig", soft=False)
        numFiles += 1
        cacheDir.move(checksum + ".sig", newCks + ".sig")
        logger.debug("    Moved sig file, updating database")

        c2.execute('UPDATE CheckSums SET Encrypted = 1, DiskSize = :size, Checksum = :newcks WHERE Checksum = :cks',
                    {"size": fSize, "newcks": newCks, "cks": checksum})
        c2.execute('UPDATE CheckSums SET Basis = :newcks WHERE Basis = :cks', {"newcks": newCks, "cks": checksum})

        logger.debug("    Ready to commit")
        conn.commit()
        logger.debug("    Commit complete, removing files")
        cacheDir.removeSuffixes(checksum, ['.meta', '.enc', '.sig', '.basis', ''])
        logger.debug("    Done with %s", checksum)
        return retFile
    except Exception as e:
        conn.rollback()
        logger.error("Unable to convert checksum: %s (%s) :: %s", checksum, newCks, e)
        logger.exception(e)
        return None

def encryptFilesAtLevel(db, crypto, cacheDir, chainlength, pbar):
    logger.info("Encrypting files with chainlength = %d", chainlength)
    conn = db.conn
    c = conn.cursor()
    regenerator = Regenerator.Regenerator(cacheDir, db, crypto)

    r = c.execute("SELECT Checksum, Size, Basis, Compressed FROM Checksums WHERE Encrypted = 0 AND IsFile = 1 AND ChainLength = :chainlength ORDER BY CheckSum", {"chainlength": chainlength})
    for row in r.fetchall():
        try:
            checksum = row[0]
            #logger.info("Encrypting Parent %s", checksum)
            chain = db.getChecksumInfoChain(checksum)
            bFile = None
            while chain:
                cksInfo = chain.pop()
                bFile = processFile(cksInfo, regenerator, cacheDir, db, crypto, pbar, bFile)
        except Exception as e:
            logger.error("Error processing checksum: %s", checksum)
            logger.exception(e)
            #raise e

def encryptFiles(db, crypto, cacheDir):
    conn = db.conn
    r = conn.execute("SELECT MAX(ChainLength) FROM CheckSums")
    mLevel = r.fetchone()[0]
    r = conn.execute("SELECT COUNT(*) FROM CheckSums WHERE Encrypted=0 AND IsFile = 1")
    files = r.fetchone()[0]
    logger.info("Encrypting %d files", files)
    pbar = progressbar.ProgressBar(max_value=int(files))

    for level in range(mLevel, -1, -1):
        encryptFilesAtLevel(db, crypto, cacheDir, level, pbar)

    pbar.finish()


def generateDirHashes(db, crypto):
    conn = db.conn
    r = conn.execute("SELECT COUNT(*) FROM Files WHERE Dir = 1")
    nDirs = r.fetchone()[0]
    logger.info("Hashing %d directories", nDirs)
    hashes = 0
    unique = 0
    with progressbar.ProgressBar(max_value=nDirs) as pbar:
        z = conn.cursor()
        r = conn.execute("SELECT Inode, Device, LastSet, Names.name, Checksums.ChecksumId, Checksum "
                         "FROM Files "
                         "JOIN Names ON Names.NameId = Files.NameID "
                         "JOIN Checksums ON Files.ChecksumId = Checksums.ChecksumId "
                         "WHERE Dir = 1 "
                         "ORDER BY Checksum")
        lastHash = None
        batch = r.fetchmany(10000)
        while batch:
            for row in batch:
                inode = row['Inode']
                device = row['Device']
                last = row['LastSet']
                oldHash = row['Checksum']
                cksId = row['ChecksumId']
                files = db.readDirectory((inode, device), last)
                hashes += 1
                if oldHash == lastHash:
                    continue
                lastHash = oldHash
                unique += 1

                #logger.debug("Rehashing directory %s (%d, %d)@%d: %s(%d)", crypto.decryptFilename(row['Name']),inode, device, last, oldHash, cksId)
                #logger.debug("    Directory contents: %s", str(files))
                (newHash, _) = Util.hashDir(crypto, files, True)
                #logger.info("Rehashed %s => %s.  %d files", oldHash, newHash, newSize)
                pbar.update(hashes)
                try:
                    if newHash != oldHash:
                        z.execute("UPDATE Checksums SET Checksum = :newHash WHERE ChecksumId = :id", {"newHash": newHash, "id": cksId})
                except Exception as e:
                    logger.error("Caught exception: %s->%s :: %s", oldHash, newHash,str(e))
            batch = r.fetchmany()
    logger.info("Hashed %d directories (%d unique)", hashes, unique)

def makeSig(checksum, regenerator, cacheDir):
    data = regenerator.recoverChecksum(checksum)
    fname = checksum + ".sig"
    output = cacheDir.open(fname, "wb")
    librsync.signature(data, output)
    output.close()


def generateSignatures(db, crypto, cacheDir):
    c = db.conn.cursor()

    r = c.execute("SELECT COUNT(*) FROM CheckSums WHERE IsFile = 1")
    n = r.fetchone()[0]
    logger.info("Generating signature files for %d files", n)

    regenerator = Regenerator.Regenerator(cacheDir, db, crypto)
    r = c.execute("SELECT Checksum FROM Checksums WHERE IsFile = 1")

    sigs = 0
    sigsGenned = 0

    with progressbar.ProgressBar(max_value=int(n)) as pbar:
        batch = r.fetchmany(4096)
        while batch:
            for row in batch:
                checksum = row[0]
                sigfile = checksum + '.sig'
                if not cacheDir.exists(sigfile):
                    #logger.info("Generating signature for {}".format(checksum))
                    makeSig(checksum, regenerator, cacheDir)
                    sigsGenned += 1
                sigs += 1
                pbar.update(sigs)
            batch = r.fetchmany(4096)

def generateMetadata(db, cacheDir):
    conn = db.conn
    r = conn.execute("SELECT COUNT(*) FROM CheckSums WHERE IsFile = 1")
    n = r.fetchone()[0]
    c = conn.cursor()
    r = c.execute("SELECT Checksum, Size, Compressed, Encrypted, DiskSize, Basis FROM Checksums WHERE IsFile = 1 ORDER BY CheckSum")
    metas = 0
    logger.info("Generating metadata/recovery info for %d files", n)
    with progressbar.ProgressBar(max_value=int(n)) as pbar:
        batch = r.fetchmany(4096)
        while batch:
            for row in batch:
                # recordMetaData(cache, checksum, size, compressed, encrypted, disksize, basis=None, logger=None):
                Util.recordMetaData(cacheDir, row[0], row[1], row[2], row[3], row[4], basis=row[5], logger=logger)
                metas += 1
                pbar.update(metas)
            batch = r.fetchmany(4096)

def processArgs():
    parser = argparse.ArgumentParser(description='Encrypt the database', add_help = False)

    (_, remaining) = Config.parseConfigOptions(parser)
    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser)

    parser.add_argument('--names',          dest='names',    action='store_true', default=False,       help='Encrypt filenames. Default=%(default)s')
    parser.add_argument('--dirs',           dest='dirs',     action='store_true', default=False,       help='Generate directory hashes.  Default=%(default)s')
    parser.add_argument('--sigs',           dest='sigs',     action='store_true', default=False,       help='Generate signature files.  Default=%(default)s')
    parser.add_argument('--files',          dest='files',    action='store_true', default=False,       help='Encrypt files. Default=%(default)s')
    parser.add_argument('--meta',           dest='meta',     action='store_true', default=False,       help='Generate metadata files.  Default=%(default)s')
    parser.add_argument('--all',            dest='all',      action='store_true', default=False,       help='Perform all encyrption steps. Default=%(default)s')

    parser.add_argument('--help', '-h',     action='help')

    Util.addGenCompletions(parser)

    args = parser.parse_args(remaining)

    if not (args.names or args.files or args.dirs or args.meta or args.all or args.sigs):
        parser.error("Must specify at least one --names, --files, --dirs, --meta, or --all")
    return args

def main():
    global logger
    progressbar.streams.wrap_stderr()
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('')
    args = processArgs()
    password = Util.getPassword(args.password, args.passwordfile, args.passwordprog, allowNone=False)

    #crypto = TardisCrypto.TardisCrypto(password, args.client)

    #path = os.path.join(args.database, args.client, args.dbname)
    #db = TardisDB.TardisDB(path, backup=False)

    #Util.authenticate(db, args.client, password)

    (db, cacheDir, crypto) = Util.setupDataConnection(args.database, args.client, password, args.keys, args.dbname, args.dbdir)


    #(f, c) = db.getKeys()
    #crypto.setKeys(f, c)

    #cacheDir = CacheDir.CacheDir(os.path.join(args.database, args.client))

    if args.names or args.all:
        encryptFilenames(db, crypto)
    if args.dirs or args.all:
        generateDirHashes(db, crypto)
    if args.sigs or args.all:
        generateSignatures(db, crypto, cacheDir)
    if args.files or args.all:
        encryptFiles(db, crypto, cacheDir)
    if args.meta or args.all:
        generateMetadata(db, cacheDir)

if __name__ == "__main__":
    main()
