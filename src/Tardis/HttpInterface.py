# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2024, Eric Koldinger, All Rights Reserved.
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



import os
import os.path
import logging
import logging.handlers
import json
import argparse
import configparser
import zlib
import base64

import daemonize

from flask import Flask, Response, session, request, abort, make_response
from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop

import Tardis
from . import TardisDB
from . import Util
from . import CacheDir
from . import Defaults

basedir     = Defaults.getDefault('TARDIS_DB')
dbname      = Defaults.getDefault('TARDIS_DBNAME')
port        = Defaults.getDefault('TARDIS_REMOTE_PORT')
configName  = Defaults.getDefault('TARDIS_REMOTE_CONFIG')
pidFile     = Defaults.getDefault('TARDIS_REMOTE_PIDFILE')

configDefaults = {
    'Port'              : port,
    'Database'          : basedir,
    'DBName'            : dbname,
    'LogFile'           : '',
    'LogExceptions'     : str(False),
    'Verbose'           : '0',
    'Daemon'            : str(False),
    'User'              : '',
    'Group'             : '',
    'SSL'               : str(False),
    'CertFile'          : '',
    'KeyFile'           : '',
    'PidFile'           : pidFile,
    'Compress'          : str(True),
    'AllowCache'        : str(True),
    'AllowSchemaUpgrades': str(False)
}

app = Flask(__name__)
app.secret_key = os.urandom(24)

dbs = {}
caches= {}

allowCompress = False
allowCache = False

args = None
config = None

logger = None

def getDB():
    if 'host' not in session:
        abort(401, "Host not in session")
    host = session['host']
    try:
        db = dbs[host]
    except KeyError:
        abort(401, f"{host} not in db list")
    return db

def makeDict(row):
    if row:
        d = {}
        for i in list(row.keys()):
            d[i] = row[i]
        return d
    return None

def compressMsg(string, threshold=1024):
    if len(string) > threshold:
        comp = zlib.compress(bytes(string, 'utf8'))
        if len(comp) < len(string):
            app.logger.debug("Compressed %d to %d", len(string), len(comp))
            return (comp, True)
    return (string, False)

def createResponse(string, compress=True, cacheable=True, dumps=True):
    if dumps:
        string = json.dumps(string)

    if compress and allowCompress and len(string) > 1024:
        app.logger.debug("Attempting to compress: %d", len(string))
        (data, compressed) = compressMsg(string)
        response = make_response(data)
        if compressed:
            response.headers['Content-Encoding'] = 'deflate'
    else:
        response = make_response(string)

    if cacheable and allowCache:
        response.headers['Cache-Control'] = 'max-age=300'
    app.logger.debug("Response: %s", str(response.headers))
    return response

@app.errorhandler(TardisDB.NotAuthenticated)
def handleNotAuthenticated(error):
    app.logger.info("Not Authenticated Exception: %s", str(error))
    response = make_response(str(error))
    response.status_code = 401
    return response

@app.errorhandler(TardisDB.AuthenticationFailed)
def handleAuthenticationFailed(error):
    app.logger.info("Authentication failed.  Wrong password")
    response = make_response(str(error))
    response.status_code = 401
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            #app.logger.debug(str(request))
            host    = request.form['host']
            dbPath  = os.path.join(args.database, host, dbname)
            cache   = CacheDir.CacheDir(os.path.join(args.database, host), create=False)
            upgrade = config.getboolean('Remote', 'AllowSchemaUpgrades')
            tardis  = TardisDB.TardisDB(dbPath, allow_upgrade=upgrade)

            #session['tardis']   = tardis
            session['host']     = host
            #app.logger.debug(str(session))
            dbs[host] = tardis
            caches[host] = cache
            if tardis.needsAuthentication():
                status = 'AUTH'
            else:
                status = 'OK'
            return createResponse({"status": status }, compress=False, cacheable=False)
        except Exception as e:
            app.logger.exception(e)
            abort(401)
    else:
        return '''
        <form action="" method="post">
            <p><input type=text name=host>
            <p><input type=text name=token>
            <p><input type=submit value=Login>
        </form>
        '''

@app.route('/needsAuthentication')
def needsAuthentication():
    db = getDB()
    resp = db.needsAuthentication()
    return createResponse(resp, compress=False, cacheable=True)

@app.route('/authenticate1', methods=['POST'])
def authenticate1():
    db = getDB()
    data = request.form
    app.logger.debug("Authenticate 1: Got data: %s", str(data))
    srpUname = base64.b64decode(data['srpUname'])
    srpValueA = base64.b64decode(data['srpValueA'])
    srpValueS, srpValueB = db.authenticate1(srpUname, srpValueA)
    resp = { "srpValueS": str(base64.b64encode(srpValueS), 'utf8'), "srpValueB": str(base64.b64encode(srpValueB), 'utf8') }
    return createResponse(resp, compress=False, cacheable=False)

@app.route('/authenticate2', methods=['POST'])
def authenticate2():
    db = getDB()
    data = request.form
    app.logger.debug("Authenticate 2: Got data: " + str(data))
    srpValueM = base64.b64decode(data['srpValueM'])
    srpValueH = db.authenticate2(srpValueM)
    resp = { "srpValueH": str(base64.b64encode(srpValueH), 'utf8') }
    return createResponse(resp, compress=False, cacheable=False)

@app.route('/close')
def close():
    # remove the username from the session if it's there
    #app.logger.info("close Invoked")
    host = session.pop('host', None)
    if host in dbs:
        dbs[host].close()
        del dbs[host]
    if host in caches:
        del caches[host]
    ret = { 'status': 'OK' }
    return createResponse(ret)

# getBackupSetInfo
@app.route('/getBackupSetInfo/<name>')
def getBackupSetInfo(name):
    #app.logger.info("getBackupSetInfo Invoked: %s", name)
    db = getDB()
    return createResponse(makeDict(db.getBackupSetInfo(name)))

@app.route('/getBackupSetInfoById/<int:backupset>')
def getBackupSetInfoById(backupset):
    #app.logger.info("getBackupSetInfoById Invoked: %s", backupset)
    db = getDB()
    return createResponse(makeDict(db.getBackupSetInfoById(backupset)))

@app.route('/getBackupSetInfoByTag/<tag>')
def getBackupSetInfoByTag(tag):
    db = getDB()
    return createResponse(makeDict(db.getBackupSetInfoByTag(tag)))

@app.route('/getBackupSetDetails/<backupset>')
def getBackupSetDetails(backupset):
    db = getDB()
    return createResponse(db.getBackupSetDetails(backupset))

# lastBackupSet
@app.route('/lastBackupSet/<int:completed>')
def lastBackupSet(completed):
    db = getDB()
    return createResponse(makeDict(db.lastBackupSet(bool(completed))))

# listBackupSets
@app.route('/listBackupSets')
def listBackupSets():
    #app.logger.info("listBackupSets Invoked")
    db = getDB()
    sets = []
    for backup in db.listBackupSets():
        #app.logger.debug(str(backup))
        sets.append(makeDict(backup))

    #app.logger.debug(str(sets))
    return createResponse(sets)

@app.route('/getFileInfoByPath/<int:backupset>')
def getFileInfoByPathRoot(backupset):
    return getFileInfoByPath(backupset, "/")

# getFileInfoByPath
@app.route('/getFileInfoByPath/<int:backupset>/<path:pathname>')
def getFileInfoByPath(backupset, pathname):
    #app.logger.info("getFileInfoByPath Invoked: %d %s", backupset, pathname)
    db = getDB()
    return createResponse(makeDict(db.getFileInfoByPath(str(pathname), backupset)))

@app.route('/getFileInfoForPath/<int:backupset>/<path:pathname>')
def getFileInfoForPath(backupset, pathname):
    db = getDB()
    pathinfo = []
    for i in db.getFileInfoForPath(pathname, backupset):
        pathinfo.append(makeDict(i))
    return createResponse(pathinfo)


@app.route('/getFileInfoByPathForRange/<int:first>/<int:last>/<path:pathname>')
def getFileInfoByPathForRange(first, last, pathname):
    db = getDB()
    fInfos = []
    #return createResponse(json.dumps(makeDict(db.getFileInfoByPathForRange(str(pathname), first, last))))
    for (bset, info) in db.getFileInfoByPathForRange(str(pathname), first, last):
        fInfos.append((bset, makeDict(info)))
    return createResponse(fInfos)

# getFileInfoByName
@app.route('/getFileInfoByName/<int:backupset>/<int:device>/<int:inode>/<name>')
def getFileInfoByName(backupset, device, inode, name):
    #app.logger.info("getFileInfoByName Invoked: %d (%d,%d) %s", backupset, inode, device, name)
    db = getDB()
    return createResponse(makeDict(db.getFileInfoByName(name, (inode, device), backupset)))


# getFileInfoByInode
@app.route('/getFileInfoByInode/<int:backupset>/<int:device>/<int:inode>')
def getFileInfoByInode(backupset, device, inode):
    #app.logger.info("getFileInfoByName Invoked: %d (%d,%d) %s", backupset, inode, device)
    db = getDB()
    return createResponse(makeDict(db.getFileInfoByInode((inode, device), backupset)))

@app.route('/getFileInfoByChecksum/<int:backupset>/<checksum>')
def getFileInfoByChecksum(backupset, checksum):
    #app.logger.info("getFileInfoByChceksum Invoked: %d %s", backupset, checksum)
    db = getDB()
    return createResponse([makeDict(x) for x in db.getFileInfoByChecksum(checksum, backupset)])

# getNewFiles
@app.route('/getNewFiles/<int:backupset>/<other>')
def getNewFiles(backupset, other):
    db = getDB()
    files = []
    other = True if other == 'True' else False
    for x in db.getNewFiles(backupset, other):
        files.append(makeDict(x))
    return createResponse(files)

# readDirectory
@app.route('/readDirectory/<int:backupset>/<int:device>/<int:inode>')
def readDirectory(backupset, device, inode):
    #app.logger.info("readDirectory Invoked: %d (%d,%d)", backupset, inode, device)
    db = getDB()
    directory = []
    for x in db.readDirectory((inode, device), backupset):
        directory.append(makeDict(x))
    return createResponse(directory)

@app.route('/readDirectoryForRange/<int:device>/<int:inode>/<int:first>/<int:last>')
def readDirectoryForRange(device, inode, first, last):
    #app.logger.info("readDirectoryForRange Invoked: %d (%d,%d) %d %d", inode, device, first, last)
    db = getDB()
    directory = []
    for x in db.readDirectoryForRange((inode, device), first, last):
        directory.append(makeDict(x))
    return createResponse(directory)

# getChecksumByPath
@app.route('/getChecksumByPath/<int:backupset>/<path:pathname>')
def getChecksumByPath(backupset, pathname):
    #app.logger.info("getChecksumByPath Invoked: %d %s", backupset, pathname)
    db = getDB()
    cksum = db.getChecksumByPath(pathname, backupset)
    #app.logger.info("Checksum: %s", cksum)
    return createResponse(cksum)

# getChecksumInfo
@app.route('/getChecksumInfo/<checksum>')
def getChecksumInfo(checksum):
    #app.logger.info("getChecksumInfo Invoked: %s", checksum)
    db = getDB()
    return createResponse(makeDict(db.getChecksumInfo(checksum)))

@app.route('/getChecksumInfoChain/<checksum>')
def getChecksumInfoChain(checksum):
    #app.logger.info("getChecksumInfo Invoked: %s", checksum)
    db = getDB()
    return createResponse(list(map(makeDict, db.getChecksumInfoChain(checksum))))

@app.route('/getChecksumInfoChainByPath/<int:backupset>/<path:pathname>')
def getChecksumInfoChainByPath(pathname, backupset):
    db = getDB()
    return createResponse(list(map(makeDict, db.getChecksumInfoChainByPath(pathname, backupset))))

@app.route('/getBackupSetInfoForTime/<float:time>')
def getBackupSetInfoForTime(time):
    #app.logger.info("getBackupSetInfoForTime Invoked: %f", time)
    db = getDB()
    return createResponse(makeDict(db.getBackupSetInfoForTime(time)))

# getFirstBackupSet
@app.route('/getFirstBackupSet/<int:backupset>/<path:pathname>')
def getFirstBackupSet(backupset, pathname):
    #app.logger.info("getFirstBackupSet Invoked: %d %s", backupset, pathname)
    db = getDB()
    if not pathname.startswith('/'):
        pathname = '/' + pathname
    return createResponse(db.getFirstBackupSet(pathname, backupset))

# getChainLength
@app.route('/getChainLength/<checksum>')
def getChainLength(checksum):
    #app.logger.info("getChainLength Invoked: d %s", checksum)
    db = getDB()
    return createResponse(db.getChainLength(checksum))

_blocksize = 1024 * 1024
def _stream(f):
    try:
        f.seek(0)
        r = f.read(_blocksize)
        while r:
            yield r
            r = f.read(_blocksize)
    except Exception as e:
        app.logger.exception(e)
    finally:
        f.close()

@app.route('/getFileData/<checksum>')
def getFileData(checksum):
    #app.logger.info("getFileData Invoked: %s", checksum)
    db = getDB()
    host = session['host']
    cache = caches[host]
    try:
        ckinfo = db.getChecksumInfo(checksum)
        ckfile = cache.open(checksum, "rb")
        #ckfile = os.path.abspath(cache.path(checksum))
        #return send_file(ckfile)
        resp = Response(_stream(ckfile))
        resp.headers['Content-Length'] = ckinfo['disksize']
        resp.headers['Content-Type'] = 'application/octet-stream'
        return resp
    except Exception:
        abort(404)

@app.route('/getConfigValue/<name>')
def getConfigValue(name):
    db = getDB()
    #app.logger.info("getConfigValue Invoked: %s", name)
    return createResponse(db.getConfigValue(name))

@app.route('/setConfigValue/<name>/<value>')
def setConfigValue(name, value):
    db = getDB()
    app.logger.info("setConfigValue Invoked: %s %s", name, value)
    return createResponse(db.setConfigValue(name, value))

@app.route('/setPriority/<int:backupset>/<int:priority>')
def setPriority(backupset, priority):
    db = getDB()
    app.logger.info("setPriority Invoked: %s %s", backupset, priority)
    return createResponse(db.setPriority(backupset, priority))

@app.route('/setBackupSetName/<int:backupset>/<name>/<int:priority>')
def setBackupSetName(backupset, name, priority):
    db = getDB()
    app.logger.info("setBackupSetName Invoked: %s %s %s", backupset, name, priority)
    return createResponse(db.setBackupSetName(name, priority, backupset))

@app.route('/setKeys', methods=['POST'])
def setKeys():
    #app.logger.info("Form: %s", str(request.form))
    try:
        db = getDB()
        salt  = request.form.get('Salt')
        vkey  = request.form.get('SrpVKey')
        fKey  = request.form.get('FilenameKey')
        cKey  = request.form.get('ContentKey')
        if not db.setKeys(base64.b64decode(salt), base64.b64decode(vkey), fKey, cKey):
            raise Exception("Unable to set keys")
        return "OK"
    except Exception as e:
        app.logger.exception(e)
        abort(403)

@app.route('/setSrpValues', methods=['POST'])
def setSrpValues():
    try:
        db = getDB()
        salt = request.form['salt']
        vkey = request.form['vkey']
        if not db.setSrpValues(salt, vkey):
            raise Exception("Unable to set token")
    except Exception:
        abort(403)

@app.route('/listPurgeSets/<int:backupset>/<int:priority>/<float:timestamp>')
def listPurgeSets(backupset, priority, timestamp):
    db = getDB()
    sets = []
    for x in db.listPurgeSets(priority, timestamp, backupset):
        sets.append(makeDict(x))
    return createResponse(sets)

@app.route('/listPurgeIncomplete/<int:backupset>/<int:priority>/<float:timestamp>')
def listPurgeIncomplete(backupset, priority, timestamp):
    db = getDB()
    sets = []
    for x in db.listPurgeIncomplete(priority, timestamp, backupset):
        sets.append(makeDict(x))
    return createResponse(sets)

@app.route('/purgeSets/<int:backupset>/<int:priority>/<float:timestamp>')
def purgeSets(backupset, priority, timestamp):
    db = getDB()
    return createResponse(db.purgeSets(priority, timestamp, backupset))

@app.route('/purgeIncomplete/<int:backupset>/<int:priority>/<float:timestamp>')
def purgeIncomplete(backupset, priority, timestamp):
    db = getDB()
    return createResponse(db.purgeIncomplete(priority, timestamp, backupset))

@app.route('/deleteBackupSet/<int:backupset>')
def deleteBackupSet(backupset):
    db = getDB()
    return createResponse(db.deleteBackupSet(backupset))

@app.route('/listOrphanChecksums/<int:isfile>')
def listOrphanChecksums(isfile):
    db = getDB()
    orphans = list(db.listOrphanChecksums(isfile))
    return createResponse(orphans)

@app.route('/deleteOrphanChecksums/<int:isfile>')
def deleteOrphanChecksums(isfile):
    db = getDB()
    return createResponse(db.deleteOrphanChecksums(isfile))

@app.route('/setTag/<int:backupset>/<tag>')
def setTags(backupset, tag):
    db = getDB()
    return createResponse(db.setTag(tag, backupset))

@app.route('/removeTag/<tag>')
def removeTag(tag):
    db = getDB()
    return createResponse(db.removeTag(tag))

@app.route('/getTags/<int:backupset>')
def getTags(backupset):
    db = getDB()
    return createResponse(db.getTags(backupset))

@app.route('/setLock/<int:backupset>/<int:lock>')
def setLock(lock, backupset):
    db = getDB()
    return createResponse(db.setLock(lock, backupset))

@app.route('/beginTransaction')
def beginTransaction():
    db = getDB()
    return createResponse(db.beginTransaction())

@app.route('/commit')
def commit():
    db = getDB()
    return createResponse(db.commit())


@app.route('/removeOrphans')
def removeOrphans():
    db = getDB()
    host = session['host']
    cache = caches[host]
    count, size, rounds = Util.removeOrphans(db, cache)
    j = {
        'count': count,
        'size': size,
        'rounds': rounds,
    }
    return createResponse(j)

def processArgs():
    parser = argparse.ArgumentParser(description='Tardis HTTP Data Server', formatter_class=Util.HelpFormatter, add_help=False)

    parser.add_argument('--config',         dest='config', default=configName, help="Location of the configuration file (Default: %(default)s)")
    (args, remaining) = parser.parse_known_args()

    t = 'Remote'
    config = configparser.ConfigParser(configDefaults, default_section='Tardis')
    config.add_section(t)                   # Make it safe for reading other values from.
    config.read(args.config)

    parser.add_argument('--port',               dest='port',            default=config.getint(t, 'Port'), type=int, help='Listen on port (Default: %(default)s)')
    parser.add_argument('--dbname',             dest='dbname',          default=config.get(t, 'DBName'), help='Use the database name (Default: %(default)s)')
    parser.add_argument('--database',           dest='database',        default=config.get(t, 'Database'), help='Database Directory (Default: %(default)s)')
    parser.add_argument('--logfile', '-l',      dest='logfile',         default=config.get(t, 'LogFile'), help='Log to file (Default: %(default)s)')

    parser.add_argument('--verbose', '-v',      dest='verbose',         action='count', default=config.getint(t, 'Verbose'), help='Increase the verbosity (may be repeated)')
    parser.add_argument('--exceptions',         dest='exceptions',      action=Util.StoreBoolean, default=config.getboolean(t, 'LogExceptions'), help='Log full exception details')

    parser.add_argument('--daemon',             dest='daemon',          action=Util.StoreBoolean, default=config.getboolean(t, 'Daemon'), help='Run as a daemon')
    parser.add_argument('--user',               dest='user',            default=config.get(t, 'User'), help='Run daemon as user.  Valid only if --daemon is set')
    parser.add_argument('--group',              dest='group',           default=config.get(t, 'Group'), help='Run daemon as group.  Valid only if --daemon is set')
    parser.add_argument('--pidfile',            dest='pidfile',         default=config.get(t, 'PidFile'), help='Use this pidfile to indicate running daemon')

    parser.add_argument('--ssl',                dest='ssl',             action=Util.StoreBoolean, default=config.getboolean(t, 'SSL'), help='Use SSL connections')
    parser.add_argument('--certfile',           dest='certfile',        default=config.get(t, 'CertFile'), help='Path to certificate file for SSL connections')
    parser.add_argument('--keyfile',            dest='keyfile',         default=config.get(t, 'KeyFile'), help='Path to key file for SSL connections')

    parser.add_argument('--compress',           dest='compress',        action=Util.StoreBoolean, default=config.getboolean(t, 'Compress'), help='Compress data going out')
    parser.add_argument('--cache',              dest='cache',           action=Util.StoreBoolean, default=config.getboolean(t, 'AllowCache'), help='Allow caching')

    parser.add_argument('--version',            action='version', version='%(prog)s ' + Tardis.__versionstring__,   help='Show the version')
    parser.add_argument('--help', '-h',         action='help')

    Util.addGenCompletions(parser)

    args = parser.parse_args(remaining)
    return(args, config)


def setupLogging():
    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    log = logging.getLogger('')

    verbosity = args.verbose
    loglevel = levels[verbosity] if verbosity < len(levels) else logging.DEBUG
    log.setLevel(loglevel)

    format = logging.Formatter("%(asctime)s %(levelname)s : %(message)s")

    if args.logfile:
        handler = logging.handlers.WatchedFileHandler(args.logfile)
    elif args.daemon:
        handler = logging.handlers.SysLogHandler()
    else:
        handler = logging.StreamHandler()

    logging.raiseExceptions = False

    handler.setFormatter(format)
    log.addHandler(handler)
    return log

def setup():
    global args, config, logger, allowCompress, allowCache
    logging.basicConfig(level=logging.INFO)
    (args, config) = processArgs()
    logger = setupLogging()
    if args.compress:
        allowCompress = True
    if args.cache:
        allowCache = True

def main_flask():
    setup()
    app.run(debug=True, port=int(port))

def run_server():
    sslOptions = None
    if args.ssl:
        sslOptions = {
            "certfile": args.certfile,
            "keyfile" : args.keyfile
        }

    logger.info("Tornado server starting: %s", Tardis.__versionstring__)

    http_server = HTTPServer(WSGIContainer(app), ssl_options = sslOptions)
    http_server.listen(args.port)
    IOLoop.instance().start()

def tornado():
    setup()
    if args.daemon:
        user  = args.user
        group = args.group
        pidfile = args.pidfile
        fds = [h.stream.fileno() for h in logger.handlers if isinstance(h, logging.StreamHandler)]
        logger.info("About to daemonize")

        try:
            daemon = daemonize.Daemonize(app="tardisremote", pid=pidfile, action=run_server, user=user, group=group, keep_fds=fds)
            daemon.start()
        except Exception as e:
            logger.critical(f"Caught Exception on Daemonize call: {e}")
            if args.exceptions:
                logger.exception(e)
    else:
        try:
            run_server()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logger.critical(f"Unable to run server: {e}")
            if args.exceptions:
                logger.exception(e)

if __name__ == "__main__":
    main_flask()
