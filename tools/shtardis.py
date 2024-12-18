#! /usr/bin/env python3
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

from Tardis import Util, TardisDB, Config
import argparse, logging
import os.path
import os
import sys
import pwd
import subprocess

logger = None

def getShell():
    if 'SHELL' in os.environ:
        return os.environ['SHELL']
    try:
        pwdEntry = pwd.getpwuid(os.getuid())
        return pwdEntry[6]
    except KeyError:
        pass
    return '/bin/bash'

def validateShell(shell):
    shells = list(map(str.strip, open('/etc/shells', 'r').readlines()))
    if not shell in shells:
        logger.error('%s is not a valid shell', shell)
    return (shell in shells)

def processArgs():
    parser = argparse.ArgumentParser(description='Encrypt the database', add_help = False)

    (_, remaining) = Config.parseConfigOptions(parser)
    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser)

    parser.add_argument('--shell',          dest='shell',      default=getShell(),       help='Shell to use.  Default: %(default)s')

    parser.add_argument('--verbose', '-v',  action='count', default=0, dest='verbose',                  help='Increase the verbosity')

    parser.add_argument('--help', '-h',     action='help');

    Util.addGenCompletions(parser)

    args = parser.parse_args(remaining)

    return args

def main():
    global logger
    crypto = None

    args = processArgs()

    Util.setupLogging(args.verbose, levels=[logging.WARNING, logging.DEBUG])
    logger = logging.getLogger('')

    if not validateShell(args.shell):
        sys.exit(1)

    password = Util.getPassword(args.password, args.passwordfile, args.passwordprog)

    try:
        (tardis, cache, crypt, password) = Util.setupDataConnection(args.database, args.client, password, args.keys, args.dbname, args.dbdir, retpassword=True)
    except TardisDB.AuthenticationFailed as e:
        logger.error("Authentication failed")
        sys.exit(1)

    try:
        logger.debug("Setting environment variables")
        if password:
            pwFileName = ".tardis-" + str(os.getpid())
            pwFilePath = os.path.join(os.path.expanduser("~"), pwFileName)
            logger.debug("Storing password in %s", pwFilePath)
            with os.fdopen(os.open(pwFilePath, os.O_WRONLY | os.O_CREAT, 0o400), 'w') as handle:
              handle.write(password)
            os.environ['TARDIS_PWFILE'] = pwFilePath
        os.environ['TARDIS_CLIENT'] = args.client
        os.environ['TARDIS_DB'] = args.database
        if args.keys:
            os.environ['TARDIS_KEYFILE'] = os.path.abspath(args.keys)

        prompt = os.environ.get('PS1')
        if prompt:
            os.environ['PS1'] = f'TARDIS: {args.client}: {PS1}'

        logger.warning("Spawning interactive shell with security preauthenticated.")

        # Run the shell, and wait
        status = subprocess.run(args.shell)

        # Check the return code.
        if status.returncode != 0:
            logger.warning("Child exited with status %d", status.returncode)

        logger.warning("Returned to unauthenticated environment")
    finally:
        if password:
            try:
                os.unlink(pwFilePath)
            except Exception as e:
                logger.critical("Unable to delete password file: %s :: %s", pwFilePath, str(e))

    sys.exit(status.returncode)

if __name__ == "__main__":
    main()
