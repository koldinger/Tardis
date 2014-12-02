# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2014, Eric Koldinger, All Rights Reserved.
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

from flask import Flask, session, request, url_for, escape, abort, redirect, send_file
from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop

import os, os.path
import logging
import json

import Tardis
import TardisDB
import Util
import CacheDir

basedir = Util.getDefault('TARDIS_DB')
dbname  = Util.getDefault('TARDIS_DBNAME')

app = Flask(__name__)
print __name__
app.secret_key = os.urandom(24)

dbs = {}
caches= {}

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
            dbPath  = os.path.join(basedir, host, dbname)
            cache   = CacheDir.CacheDir(os.path.join(basedir, host), create=False)
            tardis  = TardisDB.TardisDB(dbPath, backup=False, token=token)
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
    return json.dumps(makeDict(db.getBackupSetInfo(backupset)))

# lastBackupSet
@app.route('/lastBackupSet/<int:completed>')
def lastBackupSet(completed):
    db = getDB()
    return json.dumps(makeDict(db.lastBackupSet(bool(completed))))

# listBackupSets
@app.route('/listBackupSets')
def listBackupSets():
    #app.logger.info("listBackupSets Invoked")
    db = getDB()
    sets = []
    for backup in db.listBackupSets():
        app.logger.debug(str(backup))
        sets.append(makeDict(backup))

    app.logger.debug(str(sets))
    return json.dumps(sets)

@app.route('/getFileInfoByPath/<int:backupset>')
def getFileInfoByPathRoot(backupset):
    return getFileInfoByPath(backupset, "/")

# getFileInfoByPath
@app.route('/getFileInfoByPath/<int:backupset>/<path:pathname>')
def getFileInfoByPath(backupset, pathname):
    #app.logger.info("getFiloInfoByPath Invoked: %d %s", backupset, pathname)
    db = getDB()
    return json.dumps(makeDict(db.getFileInfoByPath(pathname, backupset)))


# getFileInfoByName
@app.route('/getFileInfoByName/<int:backupset>/<int:device>/<int:inode>/<name>')
def getFileInfoByName(backupset, device, inode, name):
    #app.logger.info("getFiloInfoByName Invoked: %d (%d,%d) %s", backupset, inode, device, name)
    db = getDB()
    return json.dumps(makeDict(db.getFileInfoByName(name, (inode, device), backupset)))

# readDirectory
@app.route('/readDirectory/<int:backupset>/<int:device>/<int:inode>')
def readDirectory(backupset, device, inode):
    #app.logger.info("readDirectory Invoked: %d (%d,%d)", backupset, inode, device)
    db = getDB()
    directory = []
    for x in db.readDirectory((inode, device), backupset):
        directory.append(makeDict(x))
    return json.dumps(directory)


# getChecksumByPath
@app.route('/getChecksumByPath/<int:backupset>/<path:pathname>')
def getChecksumByPath(backupset, pathname):
    #app.logger.info("getChecksumByPath Invoked: %d %s", backupset, pathname)
    db = getDB()
    cksum = db.getChecksumByPath(pathname, backupset)
    app.logger.info("Checksum: %s", cksum)
    return json.dumps(cksum)

# getChecksumInfo
@app.route('/getChecksumInfo/<checksum>')
def getChecksumInfo(checksum):
    #app.logger.info("getChecksumInfo Invoked: %s", checksum)
    db = getDB()
    return json.dumps(makeDict(db.getChecksumInfo(checksum)))

@app.route('/getBackupSetInfoForTime/<float:time>')
def getBackupSetInfoForTime(time):
    #app.logger.info("getBackupSetInfoForTime Invoked: %f", time)
    db = getDB()
    return json.dumps(makeDict(db.getBackupSetInfoForTime(time)))


# getFirstBackkupSet
@app.route('/getFirstBackupSet/<int:backupset>/<path:pathname>')
def getFirstBackupSet(backupset, pathname):
    #app.logger.info("getFirstBackupSet Invoked: %d %s", backupset, pathname)
    db = getDB()
    if not pathname.startswith('/'):
        pathname = '/' + pathname
    return json.dumps(db.getFirstBackupSet(pathname, backupset))

# getChainLength
@app.route('/getChainLength/<checksum>')
def getChainLength(checksum):
    #app.logger.info("getChainLength Invoked: d %s", checksum)
    db = getDB()
    return json.dumps(db.getChainLength(checksum))

@app.route('/getFileData/<checksum>')
def getFileData(checksum):
    #app.logger.info("getFileData Invoked: %s", checksum)
    if not 'host' in session:
        abort(401)
    host = session['host']
    cache = caches[host]
    return send_file(cache.open(checksum, "rb"))

def main():
    logging.basicConfig(level=logging.DEBUG)
    app.run(debug=True, port=5000)

def tornado():
    logging.basicConfig(level=logging.DEBUG)
    http_server = HTTPServer(WSGIContainer(HttpInterface.app))
    http_server.listen(5000)
    IOLoop.instance().start()

if __name__ == "__main__":
    main()
