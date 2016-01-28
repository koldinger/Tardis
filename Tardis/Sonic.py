# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2015, Eric Koldinger, All Rights Reserved.
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

import logging
import argparse
import ConfigParser
import os, os.path
import sys
import time
import datetime
import pprint

import parsedatetime

import Tardis
import Util
import Defaults
import TardisDB
import TardisCrypto
import CacheDir


databaseName = Defaults.getDefault('TARDIS_DBNAME')
schemaName   = Defaults.getDefault('TARDIS_SCHEMA')
configName   = Defaults.getDefault('TARDIS_DAEMON_CONFIG')
baseDir      = Defaults.getDefault('TARDIS_DB')
client       = Defaults.getDefault('TARDIS_CLIENT')
current      = Defaults.getDefault('TARDIS_RECENT_SET')

configDefaults = {
    'BaseDir'           : baseDir,
    'DBName'            : databaseName,
    'Schema'            : schemaName,
}

logger = None

def getDB(crypt, new=False, keyfile=None):
    basedir = os.path.join(args.database, args.client)
    dbfile = os.path.join(basedir, args.dbname)
    if new and os.path.exists(dbfile):
        raise Exception("Database for client %s already exists." % (args.client))

    cache = CacheDir.CacheDir(basedir, 2, 2, create=new)
    token = crypt.createToken() if crypt else None
    schema = args.schema if new else None
    tardisdb = TardisDB.TardisDB(dbfile, backup=False, initialize=schema, token=token)

    return (tardisdb, cache)

def createClient(crypt):
    try:
        (db, cache) = getDB(crypt, True)
        db.close()
        return 0
    except Exception as e:
        logger.error(e)
        return 1

def setToken(crypt):
    try:
        # Must be no token specified yet
        (db, cache) = getDB(None)
        crypt.genKeys()
        (f, c) = crypt.getKeys()
        token = crypt.createToken()
        if args.keys:
            db.setToken(token)
            Util.saveKeys(args.keys, db.getConfigValue('ClientID'), f, c)
        else:
            db.setKeys(token, f, c)
        db.close()
        return 0
    except Exception as e:
        logger.error(e)
        return 1

def changePassword(crypt, crypt2):
    try:
        (db, cache) = getDB(crypt)
        # Load the keys, and insert them into the crypt object, to decyrpt them
        if args.keys:
            (f, c) = Util.loadKeys(args.keys, db.getConfigValue('ClientID'))
        else:
            (f, c) = db.getKeys()
        crypt.setKeys(f, c)

        # Grab the keys from one crypt object.
        # Need to do this because getKeys/setKeys assumes they're encrypted, and we need the raw
        # versions
        crypt2._filenameKey = crypt._filenameKey
        crypt2._contentKey  = crypt._contentKey
        # Now get the encrypted versions
        (f, c) = crypt2.getKeys()
        if args.keys:
            db.setToken(crypt2.createToken())
            Util.saveKeys(args.keys, db.getConfigValue('ClientID'), f, c)
        else:
            db.setKeys(crypt2.createToken(), f, c)
        db.close()
        return 0
    except Exception as e:
        logger.error(e)
        return 1

def moveKeys(db, crypt):
    try:
        if args.keys is None:
            logger.error("Must specify key file for key manipulation")
            return 1
        clientId = db.getConfigValue('ClientID')
        token    = crypt.createToken()
        (db, cache) = getDB(crypt)
        if args.extract:
            (f, c) = db.getKeys()
            Util.saveKeys(args.keys, clientId, f, c)
            if args.deleteKeys:
                db.setKeys(token, None, None)
        elif args.insert:
            (f, c) = Util.loadKeys(args.keys, clientId)
            db.setKeys(token, f, c)
            if args.deleteKeys:
                Util.saveKeys(args.keys, clientId, None, None)
        return 0
    except Exception as e:
        logger.error(e)
        return 1

def listBSets(db, crypt):
    try:
        last = db.lastBackupSet()
        for i in db.listBackupSets():
            t = time.strftime("%d %b, %Y %I:%M:%S %p", time.localtime(float(i['starttime'])))
            if i['endtime'] is not None:
                duration = str(datetime.timedelta(seconds = (int(float(i['endtime']) - float(i['starttime'])))))
            else:
                duration = ''
            completed = 'Comp' if i['completed'] else 'Incomp'
            isCurrent = current if i['backupset'] == last['backupset'] else ''
            print "%-40s %-4d %-6s %3d  %s  %s %s" % (i['name'], i['backupset'], completed, i['priority'], t, duration, isCurrent)
    except Exception as e:
        logger.error(e)
        return 1

def _bsetInfo(db, crypt, info):
    print "Backupset       : %s (%d)" % ((info['name']), info['backupset'])
    print "Completed       : %s" % ('True' if info['completed'] else 'False')
    t = time.strftime("%d %b, %Y %I:%M:%S %p", time.localtime(float(info['starttime'])))
    print "StartTime       : %s" % (t)
    if info['endtime'] is not None:
        t = time.strftime("%d %b, %Y %I:%M:%S %p", time.localtime(float(info['endtime'])))
        duration = str(datetime.timedelta(seconds = (int(float(info['endtime']) - float(info['starttime'])))))
        print "EndTime         : %s" % (t)
        print "Duration        : %s" % (duration)
    print "SW Versions     : C:%s S:%s" % (info['clientversion'], info['serverversion'])
    print "Client IP       : %s" % (info['clientip'])
    details = db.getBackupSetDetails(info['backupset'])
    (files, dirs, size, newInfo, endInfo) = details
    print "Files           : %d" % (files)
    print "Directories     : %d" % (dirs)
    print "Total Size      : %s" % (Util.fmtSize(size))

    print "New Files       : %d" % (newInfo[0])
    print "New File Size   : %s" % (Util.fmtSize(newInfo[1]))
    print "New File Space  : %s" % (Util.fmtSize(newInfo[2]))

    print "Purgeable Files : %d" % (endInfo[0])
    print "Purgeable Size  : %s" % (Util.fmtSize(endInfo[1]))
    print "Purgeable Space : %s" % (Util.fmtSize(endInfo[2]))

def bsetInfo(db, crypt):
    printed = False
    if args.backup or args.date:
        info = getBackupSet(db)
        if info:
            _bsetInfo(db, crypt, info)
            printed = True
    else:
        first = True
        for info in db.listBackupSets():
            if not first:
                print "------------------------------------------------"
            _bsetInfo(db, crypt, info)
            first = False
            printed = True
    if printed:
        print "\n * Purgeable numbers are estimates only"

def confirm():
    if not args.confirm:
        return True
    else:
        print "Proceed (y/n): ",
        yesno = sys.stdin.readline().strip().upper()
        return (yesno == 'YES' or yesno == 'Y')

def purge(db, cache, crypt):
    bset = getBackupSet(db, True)
    if bset == None:
        logger.error("No backup set found")
        sys.exit(1)
    # List the sets we're going to delete`
    if args.incomplete:
        pSets = db.listPurgeIncomplete(args.priority, bset['endtime'], bset['backupset'])
    else:
        pSets = db.listPurgeSets(args.priority, bset['endtime'], bset['backupset'])
    names = [x['name'] for x in pSets]
    if len(names) == 0:
        print "No matching sets"
        return

    print "Sets to be deleted:"
    pprint.pprint(names)

    if confirm():
        if args.incomplete:
            (filesDeleted, setsDeleted) = db.purgeIncomplete(args.priority, bset['endtime'], bset['backupset'])
        else:
            (filesDeleted, setsDeleted) = db.purgeSets(args.priority, bset['endtime'], bset['backupset'])
        print "Purged %d sets, containing %d files" % (setsDeleted, filesDeleted)
        removeOrphans(db, cache)

def deleteBset(db, cache):
    bset = getBackupSet(db)
    if bset == None:
        logger.error("No backup set found")
        sys.exit(1)
    print "Set to be deleted: %s" % (bset['name'])
    if confirm():
        filesDeleted = db.deleteBackupSet(bset['backupset'])
        print "Deleted %d files" % (filesDeleted)
        removeOrphans(db, cache)

def _removeOrphans(db, cache):
    # Now remove any leftover orphans
    size = 0
    count = 0
    # Get a list of orphan'd files
    orphans = db.listOrphanChecksums()
    logger.debug("Attempting to remove orphans")
    for c in orphans:
        # And remove them each....
        try:
            s = os.stat(cache.path(c))
            if s:
                count += 1
                size += s.st_size
            cache.remove(c)
            sig = c + ".sig"
            sigpath = cache.path(sig)
            if os.path.exists(sigpath):
                s = os.stat(cache.path(sig))
                if s:
                    count += 1
                    size += s.st_size
                cache.remove(sig)
        except OSError:
            logger.warning("No checksum file for checksum %s", c)
        except Exception as e:
            if server.exceptions:
                logger.exception(e)
        db.deleteChecksum(c)
    return (count, size)

def removeOrphans(db, cache):
    count = 0
    size = 0
    rounds = 0
    while True:
        (lCount, lSize) = _removeOrphans(db, cache)
        if lCount == 0:
            break
        rounds += 1
        count  += lCount
        size   += lSize
    print "Removed %d orphans, for %s, in %d rounds" % (count, Util.fmtSize(size), rounds)

def parseArgs():
    global args

    parser = argparse.ArgumentParser(description='Tardis Sonic Screwdriver Utility Program', formatter_class=Util.HelpFormatter, add_help=False)
    parser.add_argument('--config',         dest='config', default=configName, help="Location of the configuration file (Default: %(default)s)")
    (args, remaining) = parser.parse_known_args()

    t = 'Tardis'
    config = ConfigParser.ConfigParser(configDefaults)
    config.add_section(t)                   # Make it safe for reading other values from.
    config.read(args.config)

    # Shared parser
    bsetParser = argparse.ArgumentParser(add_help=False)
    bsetgroup = bsetParser.add_mutually_exclusive_group()
    bsetgroup.add_argument("--backup", "-b", help="Backup set to use", dest='backup', default=None)
    bsetgroup.add_argument("--date", "-D",   help="Regenerate as of date", dest='date', default=None)
    #bsetgroup.add_argument("--last", "-l",   dest='last', default=False, action='store_true', help="Regenerate the most recent version of the file"),

    purgeParser= argparse.ArgumentParser(add_help=False)
    purgeParser.add_argument('--priority',       dest='priority',   default=0, type=int,                   help='Maximum priority backupset to purge')
    purgeParser.add_argument('--incomplete',     dest='incomplete', default=False, action='store_true',    help='Purge only incomplete backup sets')

    cnfParser = argparse.ArgumentParser(add_help=False)
    cnfParser.add_argument('--confirm',          dest='confirm', action=Util.StoreBoolean, default=True,   help='Confirm deletes and purges')

    keyParser = argparse.ArgumentParser(add_help=False)
    keyGroup = keyParser.add_mutually_exclusive_group(required=True)
    keyGroup.add_argument('--extract',          dest='extract', default=False, action='store_true',         help='Extract keys from database')
    keyGroup.add_argument('--insert',           dest='insert', default=False, action='store_true',          help='Insert keys from database')
    keyParser.add_argument('--delete',          dest='deleteKeys', default=False, action=Util.StoreBoolean,     help='Delete keys from server or database')

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--dbname',             dest='dbname',          default=config.get(t, 'DBName'), help='Use the database name (Default: %(default)s)')
    common.add_argument('--client',             dest='client',          default=client,                  help='Client to use (Default: %(default)s)')
    common.add_argument('--database',           dest='database',        default=baseDir,                 help='Path to the database (Default: %(default)s)')

    passgroup = common.add_argument_group("Password/Encryption specification options")
    pwgroup = passgroup.add_mutually_exclusive_group()
    pwgroup.add_argument('--password', '-P',dest='password', default=None, nargs='?', const=True,   help='Encrypt files with this password')
    pwgroup.add_argument('--password-file', dest='passwordfile', default=None,                      help='Read password from file')
    pwgroup.add_argument('--password-url',  dest='passwordurl', default=None,                       help='Retrieve password from the specified URL')
    pwgroup.add_argument('--password-prog', dest='passwordprog', default=None,                      help='Use the specified command to generate the password on stdout')
    passgroup.add_argument('--crypt',       dest='crypt',action=Util.StoreBoolean, default=True,    help='Encrypt data.  Only valid if password is set')
    passgroup.add_argument('--keys',        dest='keys', default=None,                              help='Load keys from key database')

    newPassParser = argparse.ArgumentParser(add_help=False)
    newpassgrp = newPassParser.add_argument_group("New Password specification options")
    npwgroup = newpassgrp.add_mutually_exclusive_group()
    npwgroup.add_argument('--newpassword',      dest='newpw', default=None, nargs='?', const=True,  help='Change to this password')
    npwgroup.add_argument('--newpassword-file', dest='newpwf', default=None,                        help='Read new password from file')
    npwgroup.add_argument('--newpassword-url',  dest='newpwu', default=None,                        help='Retrieve new password from the specified URL')
    npwgroup.add_argument('--newpassword-prog', dest='newpwp', default=None,                        help='Use the specified command to generate the new password on stdout')


    subs = parser.add_subparsers(help="Commands", dest='command')
    cp = subs.add_parser('create',       parents=[common], help='Create a client database')
    sp = subs.add_parser('setpass',      parents=[common], help='Set a password')
    cp = subs.add_parser('chpass',       parents=[common, newPassParser],                       help='Change a password')
    kp = subs.add_parser('keys',         parents=[common, keyParser],                           help='Move keys to/from server and key file')
    lp = subs.add_parser('list',         parents=[common],                                      help='List backup sets')
    ip = subs.add_parser('info',         parents=[common, bsetParser],                          help='Print info on backup sets')
    pp = subs.add_parser('purge',        parents=[common, bsetParser, purgeParser, cnfParser],  help='Purge old backup sets')
    dp = subs.add_parser('delete',       parents=[common, bsetParser, cnfParser],               help='Delete an old backupset')
    op = subs.add_parser('orphans',      parents=[common],                                      help='Delete orphan files')

    cp.add_argument('--schema',                 dest='schema',          default=config.get(t, 'Schema'), help='Path to the schema to use (Default: %(default)s)')

    #parser.add_argument('--verbose', '-v',      dest='verbose', action='count',                     help='Be verbose')
    parser.add_argument('--version',            action='version', version='%(prog)s ' + Tardis.__version__ + ' ' + Tardis.__buildversion__,    help='Show the version')
    parser.add_argument('--help', '-h',         action='help')

    args = parser.parse_args(remaining)
    return args

def getBackupSet(db, defaultCurrent=False):
    bsetInfo = None
    if args.date:
        cal = parsedatetime.Calendar()
        (then, success) = cal.parse(args.date)
        if success:
            timestamp = time.mktime(then)
            logger.info("Using time: %s", time.asctime(then))
            bsetInfo = db.getBackupSetInfoForTime(timestamp)
            if bsetInfo and bsetInfo['backupset'] != 1:
                bset = bsetInfo['backupset']
                logger.debug("Using backupset: %s %d", bsetInfo['name'], bsetInfo['backupset'])
            else:
                logger.critical("No backupset at date: %s (%s)", args.date, time.asctime(then))
                bsetInfo = None
        else:
            logger.critical("Could not parse date string: %s", args.date)
    elif args.backup:
        try:
            bset = int(args.backup)
            bsetInfo = db.getBackupSetInfoById(bset)
        except:
            if args.backup == current:
                bsetInfo = db.lastBackupSet()
            else:
                bsetInfo = db.getBackupSetInfo(args.backup)
            if not bsetInfo:
                logger.critical("No backupset at for name: %s", args.backup)
    elif defaultCurrent:
        bsetInfo = db.lastBackupSet()
    return bsetInfo

def setupLogging():
    global logger
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('')

def main():
    parseArgs()
    setupLogging()

    try:
        crypt = None
        password = Util.getPassword(args.password, args.passwordfile, args.passwordurl, args.passwordprog, prompt="Password for %s: " % (args.client))
        if args.command == 'setpass' and args.password:
            pw2 = Util.getPassword(args.password, args.passwordfile, args.passwordurl, args.passwordprog, prompt='Confirm Password: ')
            if pw2 != password:
                logger.error("Passwords don't match")
                return -1
            pw2 = None

        if password:
            crypt = TardisCrypto.TardisCrypto(password, args.client)
            password = None
            args.password = None

        if args.command == 'create':
            return createClient(crypt)

        if args.command == 'setpass':
            if not crypt:
                logger.error("No password specified")
                return -1
            return setToken(crypt)

        if args.command == 'chpass':
            newpw = Util.getPassword(args.newpw, args.newpwf, args.newpwu, args.newpwp, prompt="New Password for %s: " % (args.client))
            if args.newpw:
                newpw2 = Util.getPassword(args.newpw, args.newpwf, args.newpwu, args.newpwp, prompt="New Password for %s: " % (args.client))
                if newpw2 != newpw:
                    logger.error("Passwords don't match")
                    return -1
                newpw2 = None
            crypt2 = TardisCrypto.TardisCrypto(newpw, args.client)
            newpw = None
            args.newpw = None
            return changePassword(crypt, crypt2)

        (db, cache) = getDB(crypt)

        if args.command == 'keys':
            return moveKeys(db, crypt)

        if args.command == 'list':
            return listBSets(db, crypt)

        if args.command == 'info':
            return bsetInfo(db, crypt)

        if args.command == 'purge':
            return purge(db, cache, crypt)

        if args.command == 'delete':
            return deleteBset(db, cache)

        if args.command == 'orphans':
            return removeOrphans(db, cache)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.error("Caught exception: %s", str(e))

if __name__ == "__main__":
    main()
