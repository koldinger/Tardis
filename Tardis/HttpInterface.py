# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2016, Eric Koldinger, All Rights Reserved.
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

from flask import Flask, Response, session, request, url_for, escape, abort, redirect, send_file, make_response
from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop

import os, os.path
import logging, logging.handlers
import json
import argparse
import ConfigParser
import zlib
import base64
import daemonize

import Tardis
import TardisDB
import Util
import CacheDir
import Defaults


basedir     = Defaults.getDefault('TARDIS_DB')
dbname      = Defaults.getDefault('TARDIS_DBNAME')
port        = Defaults.getDefault('TARDIS_REMOTE_PORT')
configName  = Defaults.getDefault('TARDIS_REMOTE_CONFIG')
pidFile     = Defaults.getDefault('TARDIS_REMOTE_PIDFILE')

configDefaults = {
    'Port'              : port,
    'Database'          : basedir,
    'DBName'            : dbname,
    'LogFile'           : None,
    'LogExceptions'     : str(False),
    'Verbose'           : '0',
    'Daemon'            : str(False),
    'User'              : None,
    'Group'             : None,
    'SSL'               : str(False),
    'CertFile'          : None,
    'KeyFile'           : None,
    'PidFile'           : pidFile,
    'Compress'          : str(True),
    'AllowCache'        : str(True)
}

app = Flask(__name__)
app.secret_key = os.urandom(24)

dbs = {}
caches= {}

allowCompress = False
allowCache = False

args = None
config = None

def getDB():
    if not 'host' in session:
        abort(401)
    host = session['host']
    db = dbs[host]
    return db

def makeDict(row):
    if row:
        d = {}
        for i in row.keys():
            d[i] = row[i]
        return d
    return None

def compressMsg(string, threshold=1024):
    if len(string) > threshold:
        comp = zlib.compress(string)
        if len(comp) < len(string):
            app.logger.debug("Compressed %d to %d", len(string), len(comp))
            return (comp, True)
    return (string, False)

def createResponse(string, compress=True, cacheable=True):
    if compress and allowCompress:
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

@app.route('/')
def hello():
    return "Hello World\n"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            #app.logger.debug(str(request))
            host    = request.form['host']
            token   = request.form['token'] if 'token' in request.form else None
            dbPath  = os.path.join(args.database, host, dbname)
            cache   = CacheDir.CacheDir(os.path.join(args.database, host), create=False)
            tardis  = TardisDB.TardisDB(dbPath, token=token)
            #session['tardis']   = tardis
            session['host']     = host
            #app.logger.debug(str(session))
            dbs[host] = tardis
            caches[host]= cache
            return "OK"
        except Exception as e:
            app.logger.exception(e)
            abort(401)
    return '''
        <form action="" method="post">
            <p><input type=text name=host>
            <p><input type=text name=token>
            <p><input type=submit value=Login>
        </form>
    '''

@app.route('/logout')
def logout():
    # remove the username from the session if it's there

    session.pop('host', None)
    return redirect(url_for('index'))

# getBackupSetInfo
@app.route('/getBackupSetInfo/<backupset>')
def getBackupSetInfo(backupset):
    #app.logger.info("getBackupSetInfo Invoked: %s", backupset)
    db = getDB()
    return createResponse(json.dumps(makeDict(db.getBackupSetInfo(backupset))))

@app.route('/getBackupSetDetails/<backupset>')
def getBackupSetDetails(backupset):
    db = getDB()
    return createResponse(json.dumps(db.getBackupSetDetails(backupset)))

# lastBackupSet
@app.route('/lastBackupSet/<int:completed>')
def lastBackupSet(completed):
    db = getDB()
    return createResponse(json.dumps(makeDict(db.lastBackupSet(bool(completed)))))

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
    return createResponse(json.dumps(sets))

@app.route('/getFileInfoByPath/<int:backupset>')
def getFileInfoByPathRoot(backupset):
    return getFileInfoByPath(backupset, "/")

# getFileInfoByPath
@app.route('/getFileInfoByPath/<int:backupset>/<path:pathname>')
def getFileInfoByPath(backupset, pathname):
    #app.logger.info("getFiloInfoByPath Invoked: %d %s", backupset, pathname)
    db = getDB()
    return createResponse(json.dumps(makeDict(db.getFileInfoByPath(str(pathname), backupset))))

@app.route('/getFileInfoForPath/<int:backupset>/<path:pathname>')
def getFileInfoForPath(backupset, pathname):
    db = getDB()
    pathinfo = []
    for i in db.getFileInfoForPath(pathname, backupset):
        pathinfo.append(makeDict(i))
    return createResponse(json.dumps(pathinfo))

# getFileInfoByName
@app.route('/getFileInfoByName/<int:backupset>/<int:device>/<int:inode>/<name>')
def getFileInfoByName(backupset, device, inode, name):
    #app.logger.info("getFiloInfoByName Invoked: %d (%d,%d) %s", backupset, inode, device, name)
    db = getDB()
    return createResponse(json.dumps(makeDict(db.getFileInfoByName(name, (inode, device), backupset))))

# readDirectory
@app.route('/readDirectory/<int:backupset>/<int:device>/<int:inode>')
def readDirectory(backupset, device, inode):
    #app.logger.info("readDirectory Invoked: %d (%d,%d)", backupset, inode, device)
    db = getDB()
    directory = []
    for x in db.readDirectory((inode, device), backupset):
        directory.append(makeDict(x))
    return createResponse(json.dumps(directory))

@app.route('/readDirectoryForRange/<int:device>/<int:inode>/<int:first>/<int:last>')
def readDirectoryForRange(device, inode, first, last):
    #app.logger.info("readDirectoryForRange Invoked: %d (%d,%d) %d %d", inode, device, first, last)
    db = getDB()
    directory = []
    for x in db.readDirectoryForRange((inode, device), first, last):
        directory.append(makeDict(x))
    return createResponse(json.dumps(directory))

# getChecksumByPath
@app.route('/getChecksumByPath/<int:backupset>/<path:pathname>')
def getChecksumByPath(backupset, pathname):
    #app.logger.info("getChecksumByPath Invoked: %d %s", backupset, pathname)
    db = getDB()
    cksum = db.getChecksumByPath(pathname, backupset)
    #app.logger.info("Checksum: %s", cksum)
    return createResponse(json.dumps(cksum))

# getChecksumInfo
@app.route('/getChecksumInfo/<checksum>')
def getChecksumInfo(checksum):
    #app.logger.info("getChecksumInfo Invoked: %s", checksum)
    db = getDB()
    return createResponse(json.dumps(makeDict(db.getChecksumInfo(checksum))))

@app.route('/getBackupSetInfoForTime/<float:time>')
def getBackupSetInfoForTime(time):
    #app.logger.info("getBackupSetInfoForTime Invoked: %f", time)
    db = getDB()
    return createResponse(json.dumps(makeDict(db.getBackupSetInfoForTime(time))))

# getFirstBackupSet
@app.route('/getFirstBackupSet/<int:backupset>/<path:pathname>')
def getFirstBackupSet(backupset, pathname):
    #app.logger.info("getFirstBackupSet Invoked: %d %s", backupset, pathname)
    db = getDB()
    if not pathname.startswith('/'):
        pathname = '/' + pathname
    return createResponse(json.dumps(db.getFirstBackupSet(pathname, backupset)))

# getChainLength
@app.route('/getChainLength/<checksum>')
def getChainLength(checksum):
    #app.logger.info("getChainLength Invoked: d %s", checksum)
    db = getDB()
    return createResponse(json.dumps(db.getChainLength(checksum)))

_blocksize = 127 * 1024
def _stream(f):
    try:
        r = f.read(_blocksize)
        while (r):
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
        return resp
    except:
        abort(404)

@app.route('/getConfigValue/<name>')
def getConfigValue(name):
    db = getDB()
    #app.logger.info("getConfigValue Invoked: %s", name)
    return createResponse(json.dumps(db.getConfigValue(name)))

@app.route('/setKeys', methods=['POST'])
def setKeys():
    #app.logger.info("Form: %s", str(request.form))
    try:
        db = getDB()
        token = request.form['token']
        fKey  = request.form.get('FilenameKey')
        cKey  = request.form.get('ContentKey')
        if (db.setKeys(token, fKey, cKey) == False):
            raise Exception("Unable to set keys")
        return "OK"
    except Exception as e:
        app.logger.exception(e)
        abort(403)

@app.route('/setToken', methods=['POST'])
def setToken():
    try:
        db = getDB()
        token = request.form['token']
        if (db.setToken(token, fKey, cKey) == False):
            raise Exception("Unable to set keys")
    except Exception as e:
        abort(403)

@app.route('/listPurgeSets/<int:backupset>/<int:priority>/<float:timestamp>')
def listPurgeSets(backupset, priority, timestamp):
    db = getDB()
    sets = []
    for x in db.listPurgeSets(priority, timestamp, backupset):
        sets.append(makeDict(x))
    return createResponse(json.dumps(sets))

@app.route('/listPurgeIncomplete/<int:backupset>/<int:priority>/<float:timestamp>')
def listPurgeIncomplete(backupset, priority, timestamp):
    db = getDB()
    sets = []
    for x in db.listPurgeIncomplete(priority, timestamp, backupset):
        sets.append(makeDict(x))
    return createResponse(json.dumps(sets))

@app.route('/purgeSets/<int:backupset>/<int:priority>/<float:timestamp>')
def purgeSets(backupset, priority, timestamp):
    db = getDB()
    return createResponse(json.dumps(db.purgeSets(priority, timestamp, backupset)))
    
@app.route('/purgeIncomplete/<int:backupset>/<int:priority>/<float:timestamp>')
def purgeIncomplete(backupset, priority, timestamp):
    db = getDB()
    return createResponse(json.dumps(db.purgeIncomplete(priority, timestamp, backupset)))

@app.route('/listOrphanChecksums')
def listOrphanChecksums():
    db = getDB()
    orphans = []
    for i in db.listOrphanChecksums():
        orphans.append(i)
    return createResponse(json.dumps(orphans))

def processArgs():
    parser = argparse.ArgumentParser(description='Tardis HTTP Data Server', formatter_class=Util.HelpFormatter, add_help=False)

    parser.add_argument('--config',         dest='config', default=configName, help="Location of the configuration file (Default: %(default)s)")
    (args, remaining) = parser.parse_known_args()

    t = 'Tardis'
    config = ConfigParser.ConfigParser(configDefaults)
    config.add_section(t)                   # Make it safe for reading other values from.
    config.read(args.config)

    parser.add_argument('--port',               dest='port',            default=config.getint(t, 'Port'), type=int, help='Listen on port (Default: %(default)s)')
    parser.add_argument('--dbname',             dest='dbname',          default=config.get(t, 'DBName'), help='Use the database name (Default: %(default)s)')
    parser.add_argument('--database',           dest='database',        default=config.get(t, 'Database'), help='blah blah blah')
    parser.add_argument('--logfile', '-l',      dest='logfile',         default=config.get(t, 'LogFile'), help='Log to file')

    parser.add_argument('--verbose', '-v',      dest='verbose',         action='count', default=config.getint(t, 'Verbose'), help='Increase the verbosity (may be repeated)')
    parser.add_argument('--log-exceptions',     dest='exceptions',      action=Util.StoreBoolean, default=config.getboolean(t, 'LogExceptions'), help='Log full exception details')

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

    args = parser.parse_args(remaining)
    return(args, config)


def setupLogging():
    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    logger = logging.getLogger('')

    verbosity = args.verbose
    loglevel = levels[verbosity] if verbosity < len(levels) else logging.DEBUG
    logger.setLevel(loglevel)

    format = logging.Formatter("%(asctime)s %(levelname)s : %(message)s")

    if args.logfile:
        handler = logging.handlers.WatchedFileHandler(args.logfile)
    elif args.daemon:
        handler = logging.handlers.SysLogHandler()
    else:
        handler = logging.StreamHandler()

    handler.setFormatter(format)
    logger.addHandler(handler)
    return logger

def setup():
    global args, config, logger, allowCompress, allowCache
    logging.basicConfig(loglevel=logging.INFO)
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
            logger.critical("Caught Exception on Daemonize call: {}".format(e))
            if args.exceptions:
                logger.exception(e)
    else:
        try:
            run_server()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logger.critical("Unable to run server: {}".format(e))
            if args.exceptions:
                logger.exception(e)

if __name__ == "__main__":
    main_flask()
