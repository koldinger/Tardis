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
import configparser
import os, os.path
import sys
import time
import datetime

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

configDefaults = {
    'BaseDir'           : baseDir,
    'DBName'            : databaseName,
    'Schema'            : schemaName,
}


def getDB(crypt, new=False):
    basedir = os.path.join(args.database, args.client)
    dbfile = os.path.join(basedir, args.dbname)
    if new and os.path.exists(dbfile):
        raise Exception("Database for client %s already exists." % (args.client))

    cache = CacheDir.CacheDir(basedir, 2, 2, create=new)
    token = crypt.createToken() if crypt else None
    schema = args.schema if new else None
    tardisdb = TardisDB.TardisDB(dbfile, backup=False, initialize=schema, token=token)

    return tardisdb

def createClient(crypt):
    try:
        db = getDB(crypt, True)
        db.close()
        return 0
    except Exception as e:
        logger.error(e)
        return 1


def setToken(crypt):
    try:
        # Must be no token specified yet
        db = getDB(None)
        db.setToken(crypt.createToken())
        db.close()
        return 0
    except Exception as e:
        logger.error(e)
        return 1

def listBSets(db, crypt):
    try:
        for i in db.listBackupSets():
            t = time.strftime("%d %b, %Y %I:%M:%S %p", time.localtime(float(i['starttime'])))
            if i['endtime'] is not None:
                duration = str(datetime.timedelta(seconds = (int(float(i['endtime']) - float(i['starttime'])))))
            else:
                duration = ''
            print "%-40s %-4d %d %3d  %s  %s" % (i['name'], i['backupset'], i['completed'], i['priority'], t, duration)
    except Exception as e:
        logger.error(e)
        return 1

def _bsetInfo(db, crypt, info):
    print "Backupset       : %s" % (info['name'])
    print "Completed       : %d" % (info['completed'])
    t = time.strftime("%d %b, %Y %I:%M:%S %p", time.localtime(float(info['starttime'])))
    print "StartTime       : %s" % (t)
    if info['endtime'] is not None:
        t = time.strftime("%d %b, %Y %I:%M:%S %p", time.localtime(float(info['endtime'])))
        duration = str(datetime.timedelta(seconds = (int(float(info['endtime']) - float(info['starttime'])))))
        print "EndTime         : %s" % (t)
        print "Duration        : %s" % (duration)
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

def purgeIncomplete(db, crypt):
    pass

def purge(db, crypt):
    pass

def parseArgs():
    global args
    parser = argparse.ArgumentParser(description='Tardis Sonic Screwdriver Utility Program', formatter_class=Util.HelpFormatter, add_help=False)
    parser.add_argument('--config',         dest='config', default=configName, help="Location of the configuration file (Default: %(default)s)")
    (args, remaining) = parser.parse_known_args()

    t = 'Tardis'
    config = configparser.ConfigParser(configDefaults)
    config.add_section(t)                   # Make it safe for reading other values from.
    config.read(args.config)

    parser.add_argument('--dbname',             dest='dbname',          default=config.get(t, 'DBName'), help='Use the database name (Default: %(default)s)')
    parser.add_argument('--client',             dest='client',          default=client,                  help='Client to use (Default: %(default)s)')
    parser.add_argument('--database',           dest='database',        default=baseDir,                 help='Path to the database (Default: %(default)s)')
    parser.add_argument('--schema',             dest='schema',          default=config.get(t, 'Schema'), help='Path to the schema to use (Default: %(default)s)')

    bsetgroup = parser.add_mutually_exclusive_group()
    bsetgroup.add_argument("--backup", "-b", help="Backup set to use", dest='backup', default=None)
    bsetgroup.add_argument("--date", "-D",   help="Regenerate as of date", dest='date', default=None)
    #bsetgroup.add_argument("--last", "-l",   dest='last', default=False, action='store_true', help="Regenerate the most recent version of the file"),

    passgroup = parser.add_argument_group("Password/Encryption specification options")
    pwgroup = passgroup.add_mutually_exclusive_group()
    pwgroup.add_argument('--password',      dest='password', default=None, nargs='?', const=True,   help='Encrypt files with this password')
    pwgroup.add_argument('--password-file', dest='passwordfile', default=None,                      help='Read password from file')
    pwgroup.add_argument('--password-url',  dest='passwordurl', default=None,                       help='Retrieve password from the specified URL')
    pwgroup.add_argument('--password-prog', dest='passwordprog', default=None,                      help='Use the specified command to generate the password on stdout')
    passgroup.add_argument('--crypt',          dest='crypt',action=Util.StoreBoolean, default=True,        help='Encrypt data.  Only valid if password is set')

    commandgroup = parser.add_argument_group("Actions to take (one required)")
    cmdgrp = commandgroup.add_mutually_exclusive_group(required=True)
    cmdgrp.add_argument('--create',         dest='create', default=False, action='store_true',      help='Create a client database')
    cmdgrp.add_argument('--set-password',   dest='setpw', default=False, action='store_true',       help='Set the password for the database')
    cmdgrp.add_argument('--list',           dest='list', default=False, action='store_true',        help='List backupsets for the client')
    cmdgrp.add_argument('--info',           dest='info', default=False, action='store_true',        help='List details for each backupset')

    cmdgrp.add_argument('--purge',          dest='purge', default=False, action='store_true',       help='Purge backup sets')
    cmdgrp.add_argument('--purge-incomplete',   dest='prginc', default=False, action='store_true',  help='Purge incomplete backup sets')

    parser.add_argument('--verbose', '-v',      dest='verbose', action='count',                help='Be verbose')
    parser.add_argument('--version',            action='version', version='%(prog)s ' + Tardis.__version__ , help='Show the version')
    parser.add_argument('--help', '-h',         action='help')

    args = parser.parse_args(remaining)

def getBackupSet(db):
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
            bsetInfo = db.getBackupSetInfo(args.backup)
            if not bsetInfo:
                logger.critical("No backupset at for name: %s", args.backup)
    return bsetInfo

def setupLogging():
    global logger
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('')

def main():
    parseArgs()
    setupLogging()

    crypt = None
    password = Util.getPassword(args.password, args.passwordfile, args.passwordurl, args.passwordprog)
    if password:
        crypt = TardisCrypto.TardisCrypto(password)
        password = None

    if args.create:
        return createClient(crypt)

    if args.setpw:
        if not crypt:
            logger.error("No password specified")
            return -1
        return setToken(crypt)

    db = getDB(crypt)

    if args.list:
        return listBSets(db, crypt)

    if args.info:
        return bsetInfo(db, crypt)

    if args.prginc:
        return purgeIncomplete(db, crypt)

    if args.purge:
        return purge(db, crypt)

if __name__ == "__main__":
    main()
