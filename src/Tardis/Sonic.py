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

import argparse
import collections
import datetime
import functools
import logging
import os
import os.path
import pprint
import re
import stat
import sys
import time
import urllib.parse
from pathlib import Path

import parsedatetime
import srp
from rich.table import Table
from rich.text import Text
from rich import print

import Tardis

from . import (CacheDir, Config, Defaults, Regenerator, RemoteDB, TardisCrypto,
               TardisDB, Util)

#from icecream import ic
#ic.configureOutput(includeContext=True)

class NoSuchBackupError(Exception):
    def __init__(self, message, value):
        super().__init__(f"{message} {value}")
        self.value = value

current      = Text(Defaults.getDefault("TARDIS_RECENT_SET"), "green")

# Config keys which can be gotten or set.
configKeys = ["Formats", "Priorities", "KeepDays", "ForceFull", "SaveFull", "MaxDeltaChain", "MaxChangePercent", "VacuumInterval", "AutoPurge", "Disabled", "SaveConfig"]
# Extra keys that we print when everything is requested
sysKeys    = ["ClientID", "SchemaVersion", "FilenameKey", "ContentKey", "CryptoScheme"]

logger: logging.Logger
eLogger: Util.ExceptionLogger
args: argparse.Namespace

def parseDateTime(value):
    cal = parsedatetime.Calendar()
    dt, success = cal.parse(value)
    if not success:
        raise argparse.ArgumentTypeError(f"Couldn't find a valid date in '{value}'")
    return dt

def getDB(password, new=False, allowRemote=True, allowUpgrade=False, create=False):
    loc = urllib.parse.urlparse(args.repo, scheme="file")
    _, client = os.path.split(loc.path)
    # This is basically the same code as in Util.setupDataConnection().  Should consider moving to it.
    if loc.scheme in ["http", "https", "tardis"]:
        if not allowRemote:
            raise Exception("This command cannot be executed remotely.  You must execute it on the server directly.")
        # If no port specified, insert the port
        if loc.port is None:
            netloc = loc.netloc + ":" + Defaults.getDefault("TARDIS_REMOTE_PORT")
            dbLoc = urllib.parse.urlunparse((loc.scheme, netloc, loc.path, loc.params, loc.query, loc.fragment))
        else:
            dbLoc = args.repo
        tardisdb = RemoteDB.RemoteDB(dbLoc, client)
        cache = tardisdb
    elif loc.scheme == "file":
        dbfile = os.path.join(loc.path, "tardis.db")
        if new and os.path.exists(dbfile):
            raise Exception(f"Repository for client {client} already exists.")

        cache = CacheDir.CacheDir(Path(loc.path), 2, 2, create=new)
        tardisdb = TardisDB.TardisDB(dbfile, backup=False, initialize=create, allow_upgrade=allowUpgrade)
    else:
        raise Exception(f"Unrecognized scheme: {loc.scheme}")

    if tardisdb.needsAuthentication():
        if password is None:
            password = Util.getPassword(args.password, args.passwordfile, args.passwordprog, prompt=f"Password for {client}: ", allowNone=False, confirm=False)
        Util.authenticate(tardisdb, client, password)

        scheme = tardisdb.getCryptoScheme()
        crypt = TardisCrypto.getCrypto(scheme, password, client)
        logger.info("Using crypto scheme %s", TardisCrypto.getCryptoNames(int(scheme)))
    else:
        crypt = TardisCrypto.getCrypto(0, None, None)

    return (tardisdb, cache, crypt, client)

def createClient(password):
    try:
        getDB(None, True, allowRemote=False, create=True)
        if password:
            setPassword(password)
        return 0
    except TardisDB.AuthenticationException as e:
        logger.error("Authentication failed.  Bad password")
        eLogger.log(e)
        return 1
    except Exception as e:
        logger.error(str(e))
        eLogger.log(e)
        return 1

def setPassword(password):
    try:
        (db, _, _, client) = getDB(None)
        crypt = TardisCrypto.getCrypto(args.cryptoScheme, password, client)
        crypt.genKeys()
        (f, c) = crypt.getKeys()
        (salt, vkey) = srp.create_salted_verification_key(client, password)
        if args.keys:
            db.beginTransaction()
            db.setSrpValues(salt, vkey)
            db.setConfigValue("CryptoScheme", crypt.getCryptoScheme())
            Util.saveKeys(args.keys, db.getConfigValue("ClientID"), f, c)
            db.commit()
        else:
            db.setKeys(salt, vkey, f, c)
            db.setConfigValue("CryptoScheme", crypt.getCryptoScheme())
        return 0
    except TardisDB.NotAuthenticated as e:
        logger.error("Client %s already has a password", args.client)
        eLogger.log(e)
        return 1
    except TardisDB.AuthenticationFailed as e:
        logger.error("Authentication failed.  Bad password")
        eLogger.log(e)
        return 1
    except Exception as e:
        logger.error(str(e))
        eLogger.log(e)
        return 1

def changePassword(crypt, oldPw):
    try:
        #(db, _, crypt) = getDB(oldpw)
        #password = Util.getPassword(args.password, args.passwordfile, args.passwordprog, prompt=f"Password for {args.repo}")
        (db, _, crypt, client) = Util.setupDataConnection(args.repo, oldPw, args.keys)

        # Get the new password
        try:
            newpw = Util.getPassword(args.newpw, args.newpwf, args.newpwp, prompt=f"New Password for {args.repo}: ",
                                     allowNone=False, confirm=True)
        except Exception as e:
            logger.critical(str(e))
            eLogger.log(e)
            return -1

        scheme = db.getConfigValue("CryptoScheme", 1)
        crypt2 = TardisCrypto.getCrypto(scheme, newpw, client)

        # Load the keys, and insert them into the crypt object, to decyrpt them
        if args.keys:
            (f, c) = Util.loadKeys(args.keys, db.getConfigValue("ClientID"))
            # No need to check here, loadKeys() throws exception if nothing set.
        else:
            (f, c) = db.getKeys()
            if f is None or c is None:
                logger.critical("No keys loaded from repository.  Please specify --keys as appropriate")
                raise Exception("No keys loaded")
        crypt.setKeys(f, c)

        # Grab the keys from one crypt object.
        # Need to do this because getKeys/setKeys assumes they"re encrypted, and we need the raw
        # versions
        crypt2._filenameKey = crypt._filenameKey
        crypt2._contentKey  = crypt._contentKey
        # Now get the encrypted versions
        (f, c) = crypt2.getKeys()

        (salt, vkey) = srp.create_salted_verification_key(client, newpw)

        if args.keys:
            db.beginTransaction()
            db.setSrpValues(salt, vkey)
            Util.saveKeys(args.keys, db.getConfigValue("ClientID"), f, c)
            db.commit()
        else:
            db.setKeys(salt, vkey, f, c)
        return 0
    except Exception as e:
        logger.error(str(e))
        eLogger.log(e)
        return 1

def moveKeys(db, _):
    try:
        if args.keys is None:
            logger.error("Must specify key file for key manipulation")
            return 1
        clientId = db.getConfigValue("ClientID")
        salt, vkey = db.getSrpValues()
        #(db, _) = getDB(crypt)
        if args.extract:
            (f, c) = db.getKeys()
            if not (f and c):
                raise ValueError("Unable to retrieve keys from server.  Aborting.")
            Util.saveKeys(args.keys, clientId, f, c)
            if args.deleteKeys:
                db.setKeys(salt, vkey, None, None)
        elif args.insert:
            (f, c) = Util.loadKeys(args.keys, clientId)
            logger.info("Keys: F: %s C: %s", f, c)
            if not (f and c):
                raise ValueError("Unable to retrieve keys from key repository.  Aborting.")
            db.setKeys(salt, vkey, f, c)
            if args.deleteKeys:
                Util.saveKeys(args.keys, clientId, None, None)
    except TardisDB.AuthenticationException:
        logger.error("Authentication failed.  Bad password")
        return 1
    except Exception as e:
        logger.error(e)
        eLogger.log(e)
        return 1
    return 0

@functools.lru_cache
def getCommandLine(commandLineCksum, regenerator):
    if commandLineCksum:
        try:
            data = regenerator.recoverChecksum(commandLineCksum).read().strip()
            return data
        except Regenerator.RegenerateException as e:
            logger.error(e)
            eLogger.log(e)
    return None

def getBSets(db):
    # Get a list of the backup sets, and filter by priority
    sets = list(db.listBackupSets())

    # Filter the sets
    if args.minpriority:
        sets = list(filter(lambda x: x["priority"] >= args.minpriority, sets))

    if args.before:
        timestamp = time.mktime(args.before)
        sets = list(filter(lambda x: float(x["starttime"]) < timestamp, sets))
    if args.after:
        timestamp = time.mktime(args.after)
        sets = list(filter(lambda x: float(x["starttime"]) > timestamp, sets))

    if args.last:
        sets = sets[-args.last:]
    elif args.first:
        sets = sets[:args.first]

    return sets

def listBSets(db, crypt, cache):
    f = "{:30} {:4} {:6} {:>3}  {:5}  {:24}  {:8} {:>7} {:>6} {:>9} {:1} {:}"
    c = Text(", ")
    try:
        if args.longinfo:
            regenerator = Regenerator.Regenerator(cache, db, crypt)

        last = db.lastBackupSet()
        table = Table("Name", "Id", "Comp", "Pri", "Full", "Start", "Runtime", "Files", "Delta", "Size", "Locked", "", box=None)

        # Get a list of the backup sets, and filter by priority
        sets = list(db.listBackupSets())

        if args.minpriority:
            sets = list(filter(lambda x: x["priority"] >= args.minpriority, sets))

        if args.before:
            timestamp = time.mktime(args.before)
            sets = list(filter(lambda x: float(x["starttime"]) < timestamp, sets))
        if args.after:
            timestamp = time.mktime(args.after)
            sets = list(filter(lambda x: float(x["starttime"]) > timestamp, sets))

        if args.last:
            sets = sets[-args.last:]
        elif args.first:
            sets = sets[:args.first]

        for bset in sets:
            t = time.strftime("%d %b, %Y %I:%M:%S %p", time.localtime(float(bset["starttime"])))
            if bset["endtime"] is not None:
                duration = str(datetime.timedelta(seconds = (int(float(bset["endtime"]) - float(bset["starttime"])))))
            else:
                duration = ""
            completed = Text("Comp", "green") if bset["completed"] else Text("Incomp", "red")
            full      = "Full" if bset["full"] else "Delta"
            tags = [Text(_decryptName(tag, crypt)) for tag in db.getTags(bset["backupset"])]
            if bset["backupset"] == last["backupset"]:
                status = c.join(tags + [current])
            elif bset["errormsg"]:
                status = Text(bset["errormsg"], "red")
            else:
                status = c.join(tags)
            size = Util.fmtSize(bset["bytesreceived"], suffixes=["", "KB", "MB", "GB", "TB"])
            locked = "*" if bset["locked"] else " "

            #print(f.format(bset["name"], bset["backupset"], completed, bset["priority"], full, t, duration, bset["filesfull"] or 0, bset["filesdelta"] or 0, size, locked, status))
            table.add_row(bset["name"], str(bset["backupset"]), completed, str(bset["priority"]), full, t, duration, str(bset["filesfull"] or 0), str(bset["filesdelta"] or 0), size, str(locked), status)

            if args.longinfo:
                commandLine = getCommandLine(bset["commandline"], regenerator)
                cVersion = bset["clientversion"]
                sVersion = bset["serverversion"]
                if commandLine:
                    print(f"    Command Line: {commandLine.decode("utf-8")}")
                if cVersion or sVersion:
                    print(f"    SW Versions: Client: {cVersion} Server {sVersion}")
                if tags:
                    print(f"    Tags: {", ".join(tags)}")
                if tags or commandLine or cVersion or sVersion:
                    print()
        print(table)

    except TardisDB.AuthenticationException:
        logger.error("Authentication failed.  Bad password")
        return 1
    except Exception as e:
        logger.error(e)
        eLogger.log(e)
        return 1
    return 0

# cache of paths we"ve already calculated.
# the root (0, 0,) is always prepopulated
_paths = {(0, 0): "/"}

def _encryptName(name, crypt):
    return crypt.encryptName(name)

@functools.lru_cache(maxsize=2048)
def _decryptName(name, crypt):
    return crypt.decryptName(name)

@functools.lru_cache(maxsize=1024)
def _path(db, crypt, bset, inode):
    if inode in _paths:
        return _paths[inode]
    fInfo = db.getFileInfoByInode(inode, bset)
    if fInfo:
        parent = (fInfo["parent"], fInfo["parentdev"])
        prefix = _path(db, crypt, bset, parent)

        name = _decryptName(fInfo["name"], crypt)
        path = os.path.join(prefix, name)
        _paths[inode] = path
        return path
    return "/"

def humanify(size: int) -> str:
    if size is not None:
        if args.human:
            size = Util.fmtSize(size, suffixes=["","KB","MB","GB", "TB", "PB"])
    else:
        size = ""
    return str(size)

def listFiles(db, crypt):
    info = getBackupSet(db, args.backup, args.date, defaultCurrent=True)
    bset = info["backupset"]

    lastDir = "/"
    lastDirInode = (-1, -1)

    files = db.getNewFiles(bset, args.previous)

    details = args.cksums or args.chnlen or args.inode or args.type or args.size


    # Partiion the files into directories
    dirs = collections.defaultdict(list)
    for f in files:
        dirs[(f["parent"], f["parentdev"])].append(f)

    for d in sorted(dirs.keys(), key=lambda x: _path(db, crypt, bset, x)):
        path = _path(db, crypt, bset, d)
        files = dirs[d]

        # Build table
        tab = Table(box=None, show_header=False)
        for fInfo in sorted(files, key=lambda x: _decryptName(x["name"], crypt)):
            name = _decryptName(fInfo["name"], crypt)

            if not args.dirs and fInfo["dir"]:
                continue

            if args.status:
                status = Text("[New]", "green") if fInfo["chainlength"] == 0 else Text("[Delta] ", "yellow")
            else:
                status = ""

            if args.fullname:
                name = os.path.join(path, name)

            if args.long:
                mode  = stat.filemode(fInfo["mode"])
                group = crypt.decryptName(fInfo["groupname"])
                owner = crypt.decryptName(fInfo["username"])
                mtime = Util.formatTime(fInfo["mtime"])
                size = humanify(fInfo["size"])
                inode = fInfo["inode"]
                #print(f" {status} {mode:9} {owner:8} {group:8} {size:9} {mtime:12}", end=" ")
                row = [status, mode, owner, group, str(size), mtime]
                if args.cksums:
                    row.append(fInfo["checksum"] or "")
                if args.chnlen:
                    row.append(str(fInfo["chainlength"] or 0))
                if args.inode:
                    #print(f" {inode:16}", end=" ")
                    row.append(str(inode))
                if args.type:
                    #print(f" {"Delta" if fInfo.get("chainlength", 0) else "Full":5} " , end=" ")
                    row.append("Delta" if fInfo.get("chainlength", 0) else "Full")
                if args.size:
                    #size = humanify(fInfo.get("disksize", 0))
                    #print(f" {size:9} ", end=" ")
                    row.append(humanify(fInfo.get("disksize", 0)))
                row.append(Text(name, "green"))
            else:
                row = [status]
                if args.cksums:
                    #print(f" {fInfo["checksum"] or "":32s}", end=" ")
                    row.append(fInfo.get("checksum", ""))
                if args.chnlen:
                    # print(f" {fInfo["chainlength"] or 0:>4}", end=" ")
                    row.append(str(fInfo.get("chainlength", 0)))
                if args.inode:
                    #print(" %-16s " % (f"({fInfo["device"] or ""}, {fInfo["inode"] or ""})"), end=" ")
                    row.append(f"({fInfo.get("device", "")}, {fInfo.get("inode", "")})")
                if args.type:
                    # print(f" {"Delta" if fInfo["chainlength"] else "Full":5s}", end=" ")
                    row.append("Delta" if fInfo["chainlength"] else "Full")
                if args.size:
                    #size = humanify(fInfo["disksize"])
                    #print(f" {size:9} ", end=" ")
                    row.append(humanify(fInfo["size"]))
                row.append(name)
            tab.add_row(*row)
        # Print the table if it"s not empty
        if tab.rows:
            # Print the direcotry payth
            print(Text(path, "bright_blue"), ":")
            print(tab)


def _bsetInfo(db, crypt, info):
    print(f"Backupset       : {info["name"]} ({int(info["backupset"])})")
    print(f"Completed       : {"True" if info["completed"] else "False"}")
    t = time.strftime("%d %b, %Y %I:%M:%S %p", time.localtime(float(info["starttime"])))
    print(f"StartTime       : {t}")
    if info["endtime"] is not None:
        t = time.strftime("%d %b, %Y %I:%M:%S %p", time.localtime(float(info["endtime"])))
        duration = str(datetime.timedelta(seconds = (int(float(info["endtime"]) - float(info["starttime"])))))
        print(f"EndTime         : {t}")
        print(f"Duration        : {duration}")
    tags = [_decryptName(tag, crypt) for tag in db.getTags(info["backupset"])]
    print(f"Tags:           : {",".join(tags)}")
    print(f"SW Versions     : C:{info["clientversion"]} S:{info["serverversion"]}")
    print(f"Client IP       : {info["clientip"]}")
    details = db.getBackupSetDetails(info["backupset"])

    (files, dirs, size, newInfo, endInfo) = details
    print(f"Files           : {files}")
    print(f"Directories     : {dirs}")
    print(f"Total Size      : {Util.fmtSize(size)}")

    print(f"New Files       : {newInfo[0]}")
    print(f"New File Size   : {Util.fmtSize(newInfo[1])}")
    print(f"New File Space  : {Util.fmtSize(newInfo[2])}")

    print(f"Purgeable Files : {endInfo[0]}")
    print(f"Purgeable Size  : {Util.fmtSize(endInfo[1])}")
    print(f"Purgeable Space : {Util.fmtSize(endInfo[2])}")

def bsetInfo(db, crypt):
    printed = False
    if args.backup or args.date:
        info = getBackupSet(db, args.backup, args.date)
        _bsetInfo(db, crypt, info)
        printed = True
    else:
        first = True
        for info in db.listBackupSets():
            if not first:
                print("------------------------------------------------")
            _bsetInfo(db, crypt, info)
            first = False
            printed = True
    if printed:
        print("\n * Purgeable numbers are estimates only")

def confirm(message="Proceed (y/n): "):
    if not args.confirm:
        return True
    yesno = input(message).strip().upper()
    return yesno in ["YES", "Y"]

def doTagging(db, crypt):
    tag = _encryptName(args.tag, crypt)
    if args.remove or args.move:
        db.removeTag(tag)
    if not args.remove:
        bset = getBackupSet(db, args.backup, args.date, True)
        db.setTag(tag, bset["backupset"])
    return 0

def doLock(db, lock):
    bset = getBackupSet(db, args.backup, args.date, True)
    logger.info("Locking set %s", bset["name"])
    db.setLock(lock, bset["backupset"])
    return 0

def purge(db, cache):
    bset = getBackupSet(db, args.backup, args.date, True)
    if args.incomplete:
        pSets = db.listPurgeIncomplete(args.priority, bset["endtime"], bset["backupset"])
    else:
        pSets = db.listPurgeSets(args.priority, bset["endtime"], bset["backupset"])

    names = [str(x["name"]) for x in pSets]
    logger.debug("Names: %s", names)
    if len(names) == 0:
        print("No matching sets")
        return 1

    print("Sets to be deleted:")
    pprint.pprint(names, compact=True)

    if confirm():
        if args.incomplete:
            (filesDeleted, setsDeleted) = db.purgeIncomplete(args.priority, bset["endtime"], bset["backupset"])
        else:
            (filesDeleted, setsDeleted) = db.purgeSets(args.priority, bset["endtime"], bset["backupset"])
        print(f"Purged {setsDeleted} sets, containing {filesDeleted} files")
        removeOrphans(db, cache)

    return 0

def getBackupSets(db, backups):
    results = []
    allSets = None
    for i in backups:
        if m := re.match(r"(\d+)-(\d+)", i):
            lower = int(m.group(1))
            upper = int(m.group(2))
            if upper <= lower:
                raise ValueError(f"Invalid range: {lower}-{upper}")
            r = range(lower, upper+1)
            if not allSets:
                allSets = list(db.listBackupSets())
            for b in allSets:
                if b["backupset"] in r:
                    results.append(b)
        else:
            bset = getBackupSet(db, i, None)
            if bset is None:
                logger.error("No backup set found for %s", i)
            else:
                results.append(bset)
    return results

def deleteBsets(db, cache):
    if not args.backups:
        logger.error("No backup sets specified")
        sys.exit(0)
    bsets = getBackupSets(db, args.backups)

    if not bsets:
        raise ValueError("No backupsets specified")

    names = [b["name"] for b in bsets]
    print("Sets to be deleted:")
    pprint.pprint(names, compact=True)
    if confirm():
        filesDeleted = 0
        for bset in bsets:
            filesDeleted += db.deleteBackupSet(bset["backupset"])

        print(f"Deleted {filesDeleted} files")
        if args.purge:
            removeOrphans(db, cache)

    return 0

def removeOrphans(db, cache):
    if hasattr(cache, "removeOrphans"):
        r = cache.removeOrphans()
        logger.debug("Remove Orphans: %s %s", type(r), r)
        count = r["count"]
        size = r["size"]
        rounds = r["rounds"]
    else:
        count, size, rounds = Util.removeOrphans(db, cache)
    print(f"Removed {count} orphans, for {Util.fmtSize(size)}, in {rounds} rounds")

def checkSanity(db, cache, crypt):
    if not isinstance(db, TardisDB.TardisDB):
        print("DB must be on the local system for sanity checking")
        return None

    try:
        print("Checking backup sanity.   Scanning for files")
        cachefiles = list(cache.enumerateFiles())
        cacheNames = { x.stem for x in cachefiles }
        print(f"{len(cacheNames)} files found")
        print("Scanning for checksums")
        checksums = set(db.enumerateChecksums())
        print(f"{len(checksums)} checksums found")

        filesets = collections.defaultdict(list)

        for i in cachefiles:
            filesets[i.stem].append(i.suffix)

        # Compare the sets, using set arithmetic.   Anything in the first that"s not in the second is left.
        # Go both ways, to get ones in the DB, and ones in the cache.
        inCache = sorted(list(cacheNames - checksums))
        inDB    = sorted(list(checksums - cacheNames))

        print("Calculating groupings")
        groupings = collections.Counter()
        for i in filesets.values():
            k = tuple(sorted(i))
            groupings[k] += 1

        print(f"{len(inCache)} files in the store which don't have a matching DB entry")
        print(f"{len(inDB)} files in the DB which don't have a matching store entry")


        for (k, v) in groupings.items():
            match k:
                case ("",):
                    print(f"{v} files with only data (no metadata or signature, often ACL or Xattr)")
                case (".meta", ".sig") | (".meta") | (".sig"):
                    print(f"{v} files with no data")
                case ("", ".meta"):
                    print(f"{v} files without a signature")
                case ("", ".sig"):
                    print(f"{v} files without metadata")
                case ("", ".meta", ".sig"):
                    print(f"{v} fully populated files")
                case x:
                    print(f"{v} files with unknown files types : {x}")

        # If we found something, let"s talk about it.
        if inCache or inDB:
            if args.details:
                if inCache:
                    print("Unreferenced data files")
                    for i in inCache:
                        print(f"  {i}  {Util.fmtSize(cache.size(i))}")
                if inDB:
                    print("Checksums missing data files")
                    for i in inDB:
                        names = db.getNamesForChecksum(i)
                        names = sorted(map(crypt.decryptName, names))
                        print(i, names)

            # And get rid of it,
            if args.cleanup:
                if args.confirm():
                    for i in inCache:
                        for suffix in filesets[i]:
                            cache.remove(i + suffix)
                        db.beginTransaction()
                        for i in inDB:
                            db.removeChecksumReferences(i)
                            db.deleteChecksum(i)
                        db.commit()
    except Exception as e:
        logger.error(e)
        eLogger.log(e)

    return True

def _printConfigKey(db, key):
    value = db.getConfigValue(key)
    print(f"{key:18s}: {value}")

def getConfig(db):
    keys = args.configKeys
    if keys is None:
        keys = configKeys
        if args.sysKeys:
            keys = sysKeys + keys

    for i in keys:
        _printConfigKey(db, i)

def setConfig(db):
    print("Old Value: ", end=" ")
    _printConfigKey(db, args.key)
    db.setConfigValue(args.key, args.value)

def setPriority(db):
    info = getBackupSet(db, args.backup, args.date, defaultCurrent=True)
    db.setPriority(info["backupset"], args.priority)
    return 0

def renameSet(db):
    info = getBackupSet(db, args.backup, args.date, defaultCurrent=True)
    result = db.setBackupSetName(args.newname, info["priority"], info["backupset"])
    if not result:
        logger.error("Unable to rename %s to %s.  Name already exists", info["name"], args.newname)
    return result

def parseArgs() -> argparse.Namespace:
    global args

    parser = argparse.ArgumentParser(description="Tardis Sonic Screwdriver Utility Program", fromfile_prefix_chars="@", formatter_class=Util.HelpFormatter, add_help=False)

    (args, remaining) = Config.parseConfigOptions(parser)

    # Shared parser
    bsetParser = argparse.ArgumentParser(add_help=False)
    bsetgroup = bsetParser.add_mutually_exclusive_group()
    bsetgroup.add_argument("--backup", "-b", help="Backup set to use", dest="backup", default=None)
    bsetgroup.add_argument("--date", "-d",   type=parseDateTime, help="Use last backupset before date", dest="date", default=None)

    purgeParser = argparse.ArgumentParser(add_help=False)
    purgeParser.add_argument("--priority",       dest="priority",   default=0, type=int,                   help="Maximum priority backupset to purge")
    purgeParser.add_argument("--incomplete",     dest="incomplete", default=False, action="store_true",    help="Purge only incomplete backup sets")

    bsetgroup = purgeParser.add_mutually_exclusive_group()
    bsetgroup.add_argument("--date", "-d",     type=parseDateTime, dest="date",       default=None,   help="Purge sets before this date")
    bsetgroup.add_argument("--backup", "-b",   dest="backup",      default=None,                      help="Purge sets before this set")

    deleteParser = argparse.ArgumentParser(add_help=False)
    deleteParser.add_argument("--purge", "-p", dest="purge", default=True, action=argparse.BooleanOptionalAction,        help="Delete files in the backupset")
    deleteParser.add_argument("backups", nargs="*", default=None, help="Backup sets to delete")

    cnfParser = argparse.ArgumentParser(add_help=False)
    cnfParser.add_argument("--confirm",          dest="confirm", action=argparse.BooleanOptionalAction, default=True,   help="Confirm deletes and purges")

    keyParser = argparse.ArgumentParser(add_help=False)
    keyGroup = keyParser.add_mutually_exclusive_group(required=True)
    keyGroup.add_argument("--extract",          dest="extract", default=False, action="store_true",         help="Extract keys from repository")
    keyGroup.add_argument("--insert",           dest="insert", default=False, action="store_true",          help="Insert keys from repository")
    keyParser.add_argument("--delete",          dest="deleteKeys", default=False, action=argparse.BooleanOptionalAction, help="Delete keys from server or repository")

    filesParser = argparse.ArgumentParser(add_help=False)
    filesParser.add_argument("--long", "-l",    dest="long", default=False, action=argparse.BooleanOptionalAction,           help="Long format")
    filesParser.add_argument("--fullpath", "-f",    dest="fullname", default=False, action=argparse.BooleanOptionalAction,   help="Print full path name in names")
    filesParser.add_argument("--previous",      dest="previous", default=False, action=argparse.BooleanOptionalAction,       help="Include files that first appear in the set, but weren't added here")
    filesParser.add_argument("--dirs",          dest="dirs", default=False, action=argparse.BooleanOptionalAction,           help="Include directories in list")
    filesParser.add_argument("--status",        dest="status", default=False, action=argparse.BooleanOptionalAction,         help="Include status (new/delta) in list")
    filesParser.add_argument("--human", "-H",   dest="human", default=False, action=argparse.BooleanOptionalAction,          help="Print sizes in human readable form")
    filesParser.add_argument("--checksums", "-c", dest="cksums", default=False, action=argparse.BooleanOptionalAction,       help="Print checksums")
    filesParser.add_argument("--chainlen", "-L", dest="chnlen", default=False, action=argparse.BooleanOptionalAction,        help="Print chainlengths")
    filesParser.add_argument("--inode", "-i",   dest="inode", default=False, action=argparse.BooleanOptionalAction,          help="Print inodes")
    filesParser.add_argument("--type", "-t",    dest="type", default=False, action=argparse.BooleanOptionalAction,           help="Print backup type")
    filesParser.add_argument("--size", "-s",    dest="size", default=False, action=argparse.BooleanOptionalAction,           help="Print backup size")

    tagParser = argparse.ArgumentParser(add_help=False)
    tagParser.add_argument("--tag", "-t",      dest="tag",     default=None, required=True,             help="Set to tag")
    tagParser.add_argument("--remove", "-r",   dest="remove",  default=False, action="store_true",      help="Remove the tag")
    tagParser.add_argument("--move", "-m",     dest="move",    default=False, action="store_true",      help="Move the tag")

    common = argparse.ArgumentParser(add_help=False)
    Config.addPasswordOptions(common, addscheme=False)
    Config.addCommonOptions(common)

    newPassParser = argparse.ArgumentParser(add_help=False)
    newpassgrp = newPassParser.add_argument_group("New Password specification options")
    npwgroup = newpassgrp.add_mutually_exclusive_group()
    npwgroup.add_argument("--newpassword",      dest="newpw", default=None, nargs="?", const=True,  help="Change to this password")
    npwgroup.add_argument("--newpassword-file", dest="newpwf", default=None,                        help="Read new password from file")
    npwgroup.add_argument("--newpassword-prog", dest="newpwp", default=None,                        help="Use the specified command to generate the new password on stdout")

    configKeyParser = argparse.ArgumentParser(add_help=False)
    configKeyParser.add_argument("--key",       dest="configKeys", choices=configKeys, action="append",    help="Configuration key to retrieve.  None for all keys")
    configKeyParser.add_argument("--sys",       dest="sysKeys", default=False, action=argparse.BooleanOptionalAction,   help="List System Keys as well as configurable ones")

    configValueParser = argparse.ArgumentParser(add_help=False)
    configValueParser.add_argument("--key",     dest="key", choices=configKeys, required=True,      help="Configuration key to set")
    configValueParser.add_argument("--value",   dest="value", required=True,                        help="Configuration value to access")

    priorityParser = argparse.ArgumentParser(add_help=False)
    priorityParser.add_argument("--priority",   dest="priority", type=int, required=True,           help="New priority backup set")

    renameParser = argparse.ArgumentParser(add_help=False)
    renameParser.add_argument("--name",         dest="newname", required=True,                      help="New name")

    listParser = argparse.ArgumentParser(add_help=False)
    listParser.add_argument("--long", "-l",     dest="longinfo", default=False, action=argparse.BooleanOptionalAction,   help="Print long info")
    listParser.add_argument("--minpriority",    dest="minpriority", default=0, type=int,            help="Minimum priority to list")

    limitParser = listParser.add_mutually_exclusive_group()
    limitParser.add_argument("--first",         dest="first", default=None, type=int,       help="Show only the first N backupsets")
    limitParser.add_argument("--last",          dest="last", default=None, type=int,        help="Show only the last N backupsets")

    listParser.add_argument("--before",         dest="before", type=parseDateTime, default=None )
    listParser.add_argument("--after",          dest="after",  type=parseDateTime, default=None )

    lockParser = argparse.ArgumentParser(add_help=False)
    lockGroup = lockParser.add_mutually_exclusive_group()
    lockGroup.add_argument("--lock", "-L",     dest="lock", default=True, action="store_true",      help="Lock the set(s)")
    lockGroup.add_argument("--unlock", "-U",   dest="lock", default=True, action="store_false",     help="Unlock the set(s)")

    sanityParser = argparse.ArgumentParser(add_help=False)
    sanityParser.add_argument("--details", dest="details", default=False, action=argparse.BooleanOptionalAction, help="Print mismatched files")
    sanityParser.add_argument("--cleanup", dest="cleanup", default=False, action=argparse.BooleanOptionalAction, help="Delete mismatched files")

    cryptoParser = argparse.ArgumentParser(add_help=False, formatter_class=argparse.RawTextHelpFormatter)
    cryptoParser.add_argument("--crypt",               dest="cryptoScheme", type=int, choices=range(TardisCrypto.MAX_CRYPTO_SCHEME+1), default=TardisCrypto.DEF_CRYPTO_SCHEME,
                           help=f"Crypto scheme to use.  0-{TardisCrypto.MAX_CRYPTO_SCHEME}\n" + TardisCrypto.getCryptoNames())

    subs = parser.add_subparsers(help="Commands", dest="command")
    subs.add_parser("create",       parents=[common],                                       help="Create a client repository")
    subs.add_parser("setpass",      parents=[common, cryptoParser],                         help="Set a password")
    subs.add_parser("chpass",       parents=[common, newPassParser],                        help="Change a password")
    subs.add_parser("keys",         parents=[common, keyParser],                            help="Move keys to/from server and key file")
    subs.add_parser("list",         parents=[common, listParser],                           help="List backup sets")
    subs.add_parser("files",        parents=[common, filesParser, bsetParser],              help="List new files in a backup set")
    subs.add_parser("tag",          parents=[common, tagParser, bsetParser],                help="Add or delete tags on backup sets")
    subs.add_parser("lock",         parents=[common, lockParser, bsetParser],               help="Lock backup sets")
    subs.add_parser("info",         parents=[common, bsetParser],                           help="Print info on backup sets")
    subs.add_parser("purge",        parents=[common, purgeParser, cnfParser],               help="Purge old backup sets")
    subs.add_parser("delete",       parents=[common, deleteParser, cnfParser],              help="Delete a backup set")
    subs.add_parser("orphans",      parents=[common],                                       help="Delete orphan files")
    subs.add_parser("getconfig",    parents=[common, configKeyParser],                      help="Get Config Value")
    subs.add_parser("setconfig",    parents=[common, configValueParser],                    help="Set Config Value")
    subs.add_parser("priority",     parents=[common, priorityParser, bsetParser],           help="Set backupset priority")
    subs.add_parser("rename",       parents=[common, renameParser, bsetParser],             help="Rename a backup set")
    subs.add_parser("sanity",       parents=[common, sanityParser, cnfParser],              help="Perform a sanity check")
    subs.add_parser("upgrade",      parents=[common],                                       help="Update the repository schema")

    parser.add_argument("--exceptions", "-E",   dest="exceptions", default=False, action=argparse.BooleanOptionalAction,   help="Log exception messages")
    parser.add_argument("--verbose", "-v",      dest="verbose", default=0, action="count", help="Be verbose.  Add before usb command")
    parser.add_argument("--version",            action="version", version="%(prog)s " + Tardis.__versionstring__,    help="Show the version")
    parser.add_argument("--help", "-h",         action="help")

    Util.addGenCompletions(parser)

    args = parser.parse_args(remaining)
    if args.command is None:
        parser.print_help()
        sys.exit(0)

    # And load the required strength for new passwords.  NOT specifiable on the command line.
    return args

def getBackupSet(db, backup, date, defaultCurrent=False):
    bInfo = None
    if date:
        timestamp = time.mktime(date)
        logger.debug("Using time: %s", time.asctime(date))
        bInfo = db.getBackupSetInfoForTime(timestamp)
        if bInfo and bInfo["backupset"] != 1:
            bset = bInfo["backupset"]
            logger.debug("Using backupset: %s %d", bInfo["name"], bInfo["backupset"])
        else:
            raise NoSuchBackupError("No backup for date", date)
    elif backup:
        try:
            bset = int(backup)
            logger.debug("Using integer value: %d", bset)
            bInfo = db.getBackupSetInfoById(bset)
        except ValueError:
            logger.debug("Using string value: %s", backup)
            if backup == current:
                bInfo = db.lastBackupSet()
            else:
                bInfo = db.getBackupSetInfo(backup)
                if not bInfo:
                    bInfo = db.getBackupSetInfoByTag(backup)
        if not bInfo:
            raise NoSuchBackupError("No backupset for", backup)
    elif defaultCurrent:
        bInfo = db.lastBackupSet()
        if not bInfo:
            raise NoSuchBackupError("No Current backupset", "")

    return bInfo

def main():
    global logger, eLogger
    parseArgs()
    logger = Util.setupLogging(args.verbose)
    eLogger = Util.ExceptionLogger(logger, args.exceptions, True)

    # Commands which cannot be executed on remote repository
    allowRemote = args.command not in ["create", "upgrade"]

    db      = None
    crypt   = None
    cache   = None
    try:
        confirmPw = args.command in ["setpass", "create"]
        allowNone = args.command not in ["setpass", "chpass"]
        try:
            password = Util.getPassword(args.password, args.passwordfile, args.passwordprog, prompt="Password: ", allowNone=allowNone, confirm=confirmPw)
        except Exception as e:
            logger.critical(str(e))
            eLogger.log(e)
            return -1

        match args.command:
            case "create":
                return createClient(password)
            case "setpass":
                return setPassword(password)
            case "chpass":
                return changePassword(crypt)

        # Fall through to here if it didn't match any of the above.

        upgrade = args.command == "upgrade"

        try:
            (db, cache, crypt, _) = Util.setupDataConnection(args.repo, password, args.keys, allow_remote=allowRemote, allow_upgrade=upgrade)

            if crypt.encrypting() and args.command != "keys":
                if args.keys:
                    (f, c) = Util.loadKeys(args.keys, db.getConfigValue("ClientID"))
                else:
                    (f, c) = db.getKeys()
                crypt.setKeys(f, c)
        except TardisDB.AuthenticationException as e:
            logger.error("Authentication failed.  Bad password")
            eLogger.log(e)
            return 1
        except Exception as e:
            logger.critical("Unable to connect to repository: %s", e)
            eLogger.log(e)
            return 1

        # Dispatch the command
        match args.command:
            case "keys":
                ret =  moveKeys(db, crypt)
            case "list":
                ret =  listBSets(db, crypt, cache)
            case "files":
                ret =  listFiles(db, crypt)
            case "info":
                ret =  bsetInfo(db, crypt)
            case "tag":
                ret =  doTagging(db, crypt)
            case "lock":
                ret =  doLock(db, args.lock)
            case "purge":
                ret =  purge(db, cache)
            case "delete":
                ret =  deleteBsets(db, cache)
            case "priority":
                ret =  setPriority(db)
            case "rename":
                ret =  renameSet(db)
            case "getconfig":
                ret =  getConfig(db)
            case "setconfig":
                ret =  setConfig(db)
            case "orphans":
                ret =  removeOrphans(db, cache)
            case "sanity":
                ret =  checkSanity(db, cache, crypt)
            case "upgrade":
                ret =  0
            case _:
                ret = 1
        return ret
    except KeyboardInterrupt:
        pass
    except TardisDB.AuthenticationException:
        logger.error("Authentication failed.  Bad password")
        sys.exit(1)
    except NoSuchBackupError as e:
        logger.error(str(e))
        sys.exit(2)
    except Exception as e:
        logger.error("Caught exception: %s", str(e))
        eLogger.log(e)
    finally:
        if db:
            db.close()

if __name__ == "__main__":
    main()
