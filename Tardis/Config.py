# vi: set et sw=4 sts=4 fileencoding=utf-8:
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

import ConfigParser
import Defaults
import argparse
import Util
import sys

configDefaults = {
    'Database':             Defaults.getDefault('TARDIS_DB'),
    'Client':               Defaults.getDefault('TARDIS_CLIENT'),
    'DBDir':		    Defaults.getDefault('TARDIS_DBDIR'),
    'DBName':		    Defaults.getDefault('TARDIS_DBNAME'),
    'Password':             None,
    'PasswordFile':         None,
    'PasswordProg':         None,
    'Crypt':                str(True),
    'KeyFile':              None,
    'LogFiles':             None,
    'Verbosity':            str(0),
    'Schema':				Defaults.getDefault('TARDIS_SCHEMA')
}

config = ConfigParser.ConfigParser(configDefaults)
job = None

def parseConfigOptions(parser):
    global job
    configGroup = parser.add_argument_group("Configuration File Options")
    configGroup.add_argument('--config',         dest='config', default=None,                                    help='Location of the configuration file.   Default: %(default)s')
    configGroup.add_argument('--job',            dest='job', default='Tardis',                                   help='Job Name within the configuration file.  Default: %(default)s')

    (args, remaining) = parser.parse_known_args()

    job = args.job
    if args.config:
        config.read(args.config)
        if not config.has_section(job):
            sys.stderr.write("WARNING: No Job named %s listed.  Using defaults.  Jobs available: %s\n" %(job, str(config.sections()).strip('[]')))
            config.add_section(job)                    # Make it safe for reading other values from.
    else:
        config.add_section(job)                        # Make it safe for reading other values from.

    return args, remaining

def addCommonOptions(parser):
    dbGroup = parser.add_argument_group("Database specification options")
    dbGroup.add_argument('--database', '-D', dest='database',    default=config.get(job, 'Database'),               help="Database to use.  Default: %(default)s")
    dbGroup.add_argument('--client', '-C',   dest='client',      default=config.get(job, 'Client'),                 help="Client to list on.  Default: %(default)s")
    dbGroup.add_argument('--dbname', '-N',   dest='dbname',      default=config.get(job, 'DBName'),                 help="Name of the database file (Default: %(default)s)")
    dbGroup.add_argument('--dbdir',  '-Y',   dest='dbdir',       default=config.get(job, 'DBDir'),                  help="Database directory.  If no value, uses the value of --database.  Default: %(default)s")

def addPasswordOptions(parser):
    passgroup = parser.add_argument_group("Password/Encryption specification options")
    pwgroup = passgroup.add_mutually_exclusive_group()
    pwgroup.add_argument('--password', '-P',dest='password', default=config.get(job, 'Password'), nargs='?', const=True, help='Encrypt files with this password')
    pwgroup.add_argument('--password-file', '-F',   dest='passwordfile', default=config.get(job, 'PasswordFile'),  help='Read password from file.  Can be a URL (HTTP/HTTPS or FTP)')
    pwgroup.add_argument('--password-prog', dest='passwordprog', default=config.get(job, 'PasswordProg'),          help='Use the specified command to generate the password on stdout')

    passgroup.add_argument('--crypt',       dest='crypt',action=Util.StoreBoolean, default=config.getboolean(job, 'Crypt'),
                                                                                                            help='Encrypt data.  Only valid if password is set')
    passgroup.add_argument('--keys',        dest='keys', default=config.get(job, 'KeyFile'),                       help='Load keys from file.')
