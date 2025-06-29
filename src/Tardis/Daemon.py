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
import configparser
# For profiling
import cProfile
import grp
import io
import json
import logging
import logging.config
import pstats
import pwd
import signal
import socketserver
import ssl
import sys
import threading
import traceback
import uuid
from datetime import datetime

import colorlog
import daemonize

import Tardis

from . import Backend, Connection, ConnIdLogAdapter, Defaults, Messages, Util

DONE    = 0
CONTENT = 1
CKSUM   = 2
DELTA   = 3
REFRESH = 4                     # Perform a full content update
LINKED  = 5                     # Check if it's already linked

config: configparser.ConfigParser
args: argparse.Namespace

configSection = 'Daemon'

configName      = Defaults.getDefault('TARDIS_DAEMON_CONFIG')
baseDir         = Defaults.getDefault('TARDIS_DB') or Defaults.getDefault('TARDIS_BASEDIR')
portNumber      = Defaults.getDefault('TARDIS_PORT')
pidFileName     = Defaults.getDefault('TARDIS_PIDFILE')
timeout         = Defaults.getDefault('TARDIS_TIMEOUT')
logExceptions   = Defaults.getDefault('TARDIS_LOGEXCEPTIONS')
skipFile        = Defaults.getDefault('TARDIS_SKIP')

configDefaults = {
    'Port'              : portNumber,
    'BaseDir'           : baseDir,
    'LogCfg'            : '',
    'Profile'           : str(False),
    'LogFile'           : '',
    'LinkBasis'         : str(False),
    'LogExceptions'     : str(False),
    'AllowNewHosts'     : str(False),
    'RequirePassword'   : str(False),
    'Single'            : str(False),
    'Local'             : '',
    'Verbose'           : '0',
    'Daemon'            : str(False),
    'Umask'             : '027',
    'User'              : '',
    'Group'             : '',
    'SSL'               : str(False),
    'Timeout'           : timeout,
    'CertFile'          : '',
    'KeyFile'           : '',
    'PidFile'           : pidFileName,
    'ReuseAddr'         : str(False),
    'Formats'           : 'Monthly-%Y-%m, Weekly-%Y-%U, Daily-%Y-%m-%d',
    'Priorities'        : '40, 30, 20',
    'KeepDays'          : '0, 180, 30',
    'ForceFull'         : '0, 0, 0',
    'MaxDeltaChain'     : '5',
    'MaxChangePercent'  : '50',
    'SaveFull'          : str(False),
    'SkipFileName'      : skipFile,
    'DBBackups'         : '0',
    'CksContent'        : '65536',
    'AutoPurge'         : str(False),
    'SaveConfig'        : str(True),
    'AllowClientOverrides'  :  str(True),
    'AllowSchemaUpgrades'   :  str(False),
}

server = None
logger: logging.Logger

class InitFailedException(Exception):
    pass

class ProtocolError(Exception):
    pass

class TardisServerHandler(socketserver.BaseRequestHandler):
    full    = False
    statNewFiles = 0
    statUpdFiles = 0
    statBytesReceived = 0
    statPurgedFiles = 0
    statPurgedSets = 0
    statCommands = {}
    address = ''
    basedir = None
    autoPurge = False
    saveConfig = False
    forceFull = False
    lastCompleted = None

    def setup(self):
        if self.client_address:
            self.address = self.client_address[0]
        else:
            self.address = 'localhost'
        log            = logging.getLogger('Tardis')
        self.sessionid = str(uuid.uuid1())
        self.logger = ConnIdLogAdapter.ConnIdLogAdapter(log, {'connid': self.sessionid[0:13]})
        self.logger.info("Session created from: %s", self.address)
        self.eLogger = Util.ExceptionLogger(self.logger, self.server.exceptions, False)

    def finish(self):
        self.logger.info("Ending session %s from %s", self.sessionid, self.address)

    def handle(self):
        started = False
        completed = False
        starttime = datetime.now()
        endtime = starttime         # just to keep pylint happy

        if self.server.profiler:
            self.logger.info("Starting Profiler")
            self.server.profiler.enable()

        try:
            sock = self.request
            sock.settimeout(args.timeout)

            if self.server.ssl:
                sock.sendall(bytes(Connection.sslHeaderString, 'utf-8'))
                sock = self.server.sslCtx.wrap_socket(sock, server_side=True)
            else:
                sock.sendall(bytes(Connection.headerString, 'utf-8'))

            # Receive the initial messages.  Defines the communication parameters.
            # Should be : { "encoding": "MSGP", "compress": "snappy" }

            message = sock.recv(1024)
            self.logger.debug(message)
            message = str(message, 'utf-8').strip()

            fields = json.loads(message)
            resp = {'status': 'OK'}
            sock.sendall(bytes(json.dumps(resp), 'utf-8'))

            # Create the messenger object.  From this point on, ALL communications should
            # go through messenger, not director to the socket
            messenger = Messages.MsgPackMessages(sock, compress=fields['compress'])

            # Create a backend, and run it.
            backend = Backend.Backend(messenger, self.server, sessionid=self.sessionid, prettyExceptions=False)

            started, completed, endtime, orphansRemoved, orphanSize = backend.runBackup()

            if self.server.profiler:
                self.logger.info("Stopping Profiler")
                self.server.profiler.disable()
                s = io.StringIO()
                sortby = 'cumulative'
                ps = pstats.Stats(self.server.profiler, stream=s).sort_stats(sortby)
                ps.print_stats()
                print(s.getvalue())

        except InitFailedException as e:
            self.logger.error("Connection initialization failed: %s", e)
            self.eLogger.log(e)
        except Exception as e:
            self.logger.error("Caught exception %s: %s", type(e), e)
            self.eLogger.log(e)
        finally:
            if started:
                self.logger.info("Connection completed successfully: %s  Runtime: %s", str(completed), str(endtime - starttime))
                self.logger.info("New or replaced files:    %d", backend.statNewFiles)
                self.logger.info("Updated files:            %d", backend.statUpdFiles)
                self.logger.info("Total file data received: %s (%d)", Util.fmtSize(backend.statBytesReceived), backend.statBytesReceived)
                self.logger.info("Command breakdown:        %s", backend.statCommands)
                self.logger.info("Purged Sets and File:     %d %d", backend.statPurgedSets, backend.statPurgedFiles)
                self.logger.info("Removed Orphans           %d (%s)", orphansRemoved, Util.fmtSize(orphanSize))

            self.logger.info("Session from %s {%s} Ending: %s: %s", backend.client, self.sessionid, str(completed), str(datetime.now() - starttime))

class TardisServer:
    # HACK.  Operate on an object, but not in the class.
    # Want to do this in multiple classes.
    def __init__(self):
        self.basedir        = args.basedir

        self.savefull       = config.getboolean(configSection, 'SaveFull')
        self.maxChain       = config.getint(configSection, 'MaxDeltaChain')
        self.deltaPercent   = float(config.getint(configSection, 'MaxChangePercent')) / 100.0        # Convert to a ratio
        self.cksContent     = config.getint(configSection, 'CksContent')

        self.allowNew       = args.newhosts

        self.linkBasis      = config.getboolean(configSection, 'LinkBasis')

        self.requirePW      = config.getboolean(configSection, 'RequirePassword')

        self.allowOverrides = config.getboolean(configSection, 'AllowClientOverrides')

        self.allowUpgrades  = config.getboolean(configSection, 'AllowSchemaUpgrades')

        self.formats        = list(map(str.strip, config.get(configSection, 'Formats').split(',')))
        self.priorities     = list(map(int, config.get(configSection, 'Priorities').split(',')))
        self.keep           = list(map(int, config.get(configSection, 'KeepDays').split(',')))
        self.forceFull      = list(map(int, config.get(configSection, 'ForceFull').split(',')))

        self.timeout        = args.timeout

        numFormats = len(self.formats)
        if len(self.priorities) != numFormats or len(self.keep) != numFormats or len(self.forceFull) != numFormats:
            logger.warning("Different sizes for the lists of formats: Formats: %d Priorities: %d KeepDays: %d ForceFull: %d",
                           len(self.formats), len(self.priorities), len(self.keep), len(self.forceFull))

        self.dbbackups      = config.getint(configSection, 'DBBackups')

        self.exceptions     = args.exceptions

        self.umask          = Util.parseInt(config.get(configSection, 'Umask'))

        self.autoPurge      = config.getboolean(configSection, 'AutoPurge')
        self.saveConfig     = config.getboolean(configSection, 'SaveConfig')

        self.skip           = config.get(configSection, 'SkipFileName')

        self.user = None
        self.group = None

        # If the User or Group is set, attempt to determine the users
        # Note, these will throw exeptions if the User or Group is unknown.  Will get
        # passed up.
        if args.daemon:
            if args.user:
                self.user = pwd.getpwnam(args.user).pw_uid
            if args.group:
                self.group = grp.getgrnam(args.group).gr_gid

        # Get SSL set up, if it's been requested.
        self.ssl            = args.ssl
        self.certfile       = args.certfile
        self.keyfile        = args.keyfile

        if self.ssl:
            try:
                self.sslCtx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                self.sslCtx.load_cert_chain(self.certfile, self.keyfile)
            except Exception as e:
                logger.critical("Unable to create SSL Context: %s", str(e))
                raise Exception(str(e)) from e
        else:
            self.sslCtx = None

        # Create a session ID
        self.serverSessionID = str(uuid.uuid1())

        if args.profile:
            self.profiler = cProfile.Profile()
        else:
            self.profiler = None

class TardisSocketServer(socketserver.ThreadingMixIn, socketserver.TCPServer, TardisServer):
    def __init__(self):

        socketserver.TCPServer.__init__(self, ("", args.port), TardisServerHandler)
        TardisServer.__init__(self)
        logger.info("TCP Server %s Running", Tardis.__versionstring__)

class TardisSingleThreadedSocketServer(socketserver.TCPServer, TardisServer):
    def __init__(self):
        socketserver.TCPServer.__init__(self, ("", args.port), TardisServerHandler)
        TardisServer.__init__(self)
        logger.info("Single Threaded TCP Server %s Running", Tardis.__versionstring__)

class TardisDomainSocketServer(socketserver.UnixStreamServer, TardisServer):
    def __init__(self):
        socketserver.UnixStreamServer.__init__(self,  args.local, TardisServerHandler)
        TardisServer.__init__(self)
        logger.info("Unix Domain Socket %s Server Running", Tardis.__versionstring__)


def setupLogging():
    levels = [logging.WARNING, logging.INFO, logging.DEBUG]

    logging.raiseExceptions = False

    if args.logcfg:
        logging.config.fileConfig(args.logcfg)
        logger = logging.getLogger('')
    else:
        logger = logging.getLogger('')
        if args.logfile or args.daemon:
            logFormat = logging.Formatter("%(asctime)s %(levelname)s : %(message)s")
        else:
            # Create some default colors
            colors = {
                'DEBUG':    'cyan',
                'INFO':     'green',
                'WARNING':  'yellow',
                'ERROR':    'red',
                'CRITICAL': 'red,bg_white',
            }
            logFormat = colorlog.TTYColoredFormatter("%(asctime)s %(log_color)s%(levelname)s%(reset)s : %(message)s", log_colors=colors, stream=sys.stdout)

        verbosity = args.verbose

        if args.local:
            # Always send output to stderr for local connections
            handler = logging.StreamHandler()
        elif args.logfile:
            handler = logging.handlers.WatchedFileHandler(args.logfile)
        elif args.daemon:
            handler = logging.handlers.SysLogHandler()
        else:
            handler = logging.StreamHandler()

        handler.setFormatter(logFormat)
        logger.addHandler(handler)

        loglevel = levels[verbosity] if verbosity < len(levels) else levels[-1]
        logger.setLevel(loglevel)

    return logger

def runServer():
    global server

    try:
        if args.reuseaddr:
            # Allow reuse of the address before timeout if requested.
            socketserver.TCPServer.allow_reuse_address = True

        if args.local:
            logger.info("Starting Server. Socket: %s", args.local)
            server = TardisDomainSocketServer()
        elif args.threaded:
            logger.info("Starting Server on Port: %d", config.getint(configSection, 'Port'))
            server = TardisSocketServer()
        else:
            logger.info("Starting Single Threaded Server on Port: %d", config.getint(configSection, 'Port'))
            server = TardisSingleThreadedSocketServer()

        logger.info("Server Session: %s", server.serverSessionID)

        if args.single:
            logger.info("Single backup session only")
            server.handle_request()
        else:
            try:
                server.serve_forever()
            except Exception:
                logger.info("Socket server completed")
        logger.info("Ending")
    except Exception as e:
        logger.critical(f"Unable to run server: {e}")
        if args.exceptions:
            logger.exception(e)

def stopServer():
    logger.info("Stopping server")
    server.shutdown()

def signalTermHandler(_sig, _frame):
    logger.info("Caught term signal.  Stopping")
    t = threading.Thread(target=shutdownHandler)
    t.start()
    logger.info("Server stopped")

def shutdownHandler():
    stopServer()

def processArgs():
    parser = argparse.ArgumentParser(description='Tardis Backup Server', formatter_class=Util.HelpFormatter, add_help=False)

    parser.add_argument('--config',         dest='config', default=configName, help="Location of the configuration file (Default: %(default)s)")
    (args, remaining) = parser.parse_known_args()

    t = configSection
    config = configparser.ConfigParser(configDefaults, default_section='Tardis', interpolation=configparser.ExtendedInterpolation())
    config.add_section(t)                   # Make it safe for reading other values from.
    if args.config:
        config.read(args.config)

    parser.add_argument('--port',               dest='port',            default=config.getint(t, 'Port'), type=int, help='Listen on port (Default: %(default)s)')
    parser.add_argument('--basedir',            dest='basedir',         default=config.get(t, 'BaseDir'), help='Location where all backup clients are stored (Default: %(default)s)')
    parser.add_argument('--logfile', '-l',      dest='logfile',         default=config.get(t, 'LogFile'), help='Log to file (Default: %(default)s)')
    parser.add_argument('--logcfg',             dest='logcfg',          default=config.get(t, 'LogCfg'), help='Logging configuration file')
    parser.add_argument('--verbose', '-v',      dest='verbose',         action='count', default=config.getint(t, 'Verbose'), help='Increase the verbosity (may be repeated)')
    parser.add_argument('--exceptions', '-E',   dest='exceptions',      action=argparse.BooleanOptionalAction, default=config.getboolean(t, 'LogExceptions'), help='Log full exception details')
    parser.add_argument('--allow-new-hosts',    dest='newhosts',        action=argparse.BooleanOptionalAction, default=config.getboolean(t, 'AllowNewHosts'),
                        help='Allow new clients to attach and create new backup sets')
    parser.add_argument('--profile',            dest='profile',         default=config.getboolean(t, 'Profile'), help='Generate a profile')

    parser.add_argument('--single',             dest='single',          action=argparse.BooleanOptionalAction, default=config.getboolean(t, 'Single'),
                        help='Run a single transaction and quit')
    parser.add_argument('--local',              dest='local',           default=config.get(t, 'Local'),
                        help='Run as a Unix Domain Socket Server on the specified filename')
    parser.add_argument('--threads',            dest='threaded',        action=argparse.BooleanOptionalAction, default=True, help='Run a threaded server.  Default: %(default)s')

    parser.add_argument('--timeout',            dest='timeout',         default=config.getint(t, 'Timeout'), type=float, help='Timeout, in seconds.  0 for no timeout (Default: %(default)s)')

    parser.add_argument('--reuseaddr',          dest='reuseaddr',       action=argparse.BooleanOptionalAction, default=config.getboolean(t, 'ReuseAddr'),
                        help='Reuse the socket address immediately')

    parser.add_argument('--daemon',             dest='daemon',          action=argparse.BooleanOptionalAction, default=config.getboolean(t, 'Daemon'),
                        help='Run as a daemon')
    parser.add_argument('--user',               dest='user',            default=config.get(t, 'User'), help='Run daemon as user.  Valid only if --daemon is set')
    parser.add_argument('--group',              dest='group',           default=config.get(t, 'Group'), help='Run daemon as group.  Valid only if --daemon is set')
    parser.add_argument('--pidfile',            dest='pidfile',         default=config.get(t, 'PidFile'), help='Use this pidfile to indicate running daemon')

    parser.add_argument('--ssl',                dest='ssl',             action=argparse.BooleanOptionalAction, default=config.getboolean(t, 'SSL'), help='Use SSL connections')
    parser.add_argument('--certfile',           dest='certfile',        default=config.get(t, 'CertFile'), help='Path to certificate file for SSL connections')
    parser.add_argument('--keyfile',            dest='keyfile',         default=config.get(t, 'KeyFile'), help='Path to key file for SSL connections')

    parser.add_argument('--version',            action='version', version='%(prog)s ' + Tardis.__versionstring__,    help='Show the version')
    parser.add_argument('--help', '-h',         action='help')

    Util.addGenCompletions(parser)

    args = parser.parse_args(remaining)
    return (args, config)

def main():
    global logger, args, config
    (args, config) = processArgs()

    # Set up a handler
    signal.signal(signal.SIGTERM, signalTermHandler)
    try:
        logger = setupLogging()
    except Exception as e:
        print(f"Unable to initialize logging: {str(e)}", file=sys.stderr)
        if args.exceptions:
            traceback.print_exc()
        sys.exit(1)

    if args.daemon and not args.local:
        user  = args.user
        group = args.group
        pidfile = args.pidfile
        fds = [h.stream.fileno() for h in logger.handlers if isinstance(h, logging.StreamHandler)]
        logger.info("About to daemonize")

        try:
            daemon = daemonize.Daemonize(app="tardisd", pid=pidfile, action=runServer, user=user, group=group, keep_fds=fds)
            daemon.start()
        except Exception as e:
            logger.critical(f"Caught Exception on Daemonize call: {e}")
            if args.exceptions:
                logger.exception(e)
    else:
        try:
            runServer()
        except KeyboardInterrupt:
            logger.warning("Killed by Keyboard")
        except Exception as e:
            logger.critical(f"Unable to run server: {e}")
            if args.exceptions:
                logger.exception(e)

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
