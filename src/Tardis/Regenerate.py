# vim: set et sw=4 sts=4 fileencoding=utf-8:
#
# Tardis: A Backup System
# Copyright 2013-2023, Eric Koldinger, All Rights Reserved.
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
import stat
import sys
import argparse
import time
import base64
import json
import hmac

import parsedatetime
import xattr
import posix1e

import Tardis
from Tardis import TardisDB
from Tardis import Regenerator
from Tardis import Util
from Tardis import Config
from Tardis import Defaults

logger  = None
crypt = None

OW_NEVER  = 0
OW_ALWAYS = 1
OW_NEWER  = 2
OW_OLDER  = 3
OW_PROMPT = 4

overwriteNames = { 'never': OW_NEVER, 'always': OW_ALWAYS, 'newer': OW_NEWER, 'older': OW_OLDER, 'ask': OW_PROMPT }
if sys.stdout.isatty():
    owMode = OW_PROMPT
    owModeDefault = 'ask'
else:
    owMode = OW_NEVER
    owModeDefault = 'never'

errors = 0

tardis = None
args = None

def yesOrNo(x):
    if x:
        x = x.strip().lower()
        return x[0] == 'y'
    else:
        return False

def checkOverwrite(name, info):
    if os.path.exists(name):
        if owMode == OW_NEVER:
            return False
        elif owMode == OW_ALWAYS:
            return True
        elif owMode == OW_PROMPT:
            return yesOrNo(input(f"Overwrite {name} [y/N]: "))
        else:
            s = os.lstat(name)
            if s.st_mtime < info['mtime']:
                # Current version is older
                return True if owMode == OW_NEWER else False
            else:
                # Current version is newer
                return True if owMode == OW_OLDER else False
    else:
        return True

def doAuthenticate(outname, checksum, digest):
    """
    Check that the recorded checksum of the file, and the digest of the generated file match.
    Perform the expected action if they don't.  Return the name of the file that's being generated.
    """
    logger.debug("File: %s Expected Hash: %s Hash: %s", outname, checksum, digest)
    # should use hmac.compare_digest() here, but it's not working for some reason.  Probably different types
    if not hmac.compare_digest(checksum, digest):
        if outname:
            if args.authfailaction == 'keep':
                action = ''
                target = outname
            elif args.authfailaction == 'rename':
                target = outname + '-CORRUPT-' + str(digest)
                action = 'Renaming to ' + target + '.'
                try:
                    os.rename(outname, target)
                except os.error:
                    action = "Unable to rename to " + target + ".  File saved as " + outname + "."
            elif args.authfailaction == 'delete':
                action = 'Deleting.'
                os.unlink(outname)
                target = None
        else:
            target = None
            action = ''
        if outname is None:
            outname = ''
        logger.error("File %s did not authenticate.  Expected: %s.  Got: %s.  %s",
                        outname, checksum, digest, action)
        return target
    else:
        return outname

def notSame(a, b, string):
    if a == b:
        return ''
    else:
        return string

def setAttributes(regenerator, info, outname):
    if outname:
        if args.setperm:
            try:
                logger.debug("Setting permissions on %s to %o", outname, info['mode'])
                os.chmod(outname, info['mode'])
            except Exception:
                logger.warning("Unable to set permissions for %s", outname)
            try:
                # Change the group, then the owner.
                # Change the group first, as only root can change owner, and that might fail.
                os.chown(outname, -1, info['gid'])
                os.chown(outname, info['uid'], -1)
            except Exception:
                logger.warning("Unable to set owner and group of %s", outname)
        if args.settime:
            try:
                logger.debug("Setting times on %s to %d %d", outname, info['atime'], info['mtime'])
                os.utime(outname, (info['atime'], info['mtime']))
            except Exception:
                logger.warning("Unable to set times on %s", outname)

        if args.setattrs and 'attr' in info and info['attr']:
            try:
                f = regenerator.recoverChecksum(info['attr'], True)
                xattrs = json.loads(f.read())
                x = xattr.xattr(outname)
                for attr in xattrs.keys():
                    value = base64.b64decode(xattrs[attr])
                    try:
                        x.set(attr, value)
                    except IOError:
                        logger.warning("Unable to set extended attribute %s on %s", attr, outname)
            except Exception:
                logger.warning("Unable to process extended attributes for %s", outname)
        if args.setacl and 'acl' in info and info['acl']:
            try:
                f = regenerator.recoverChecksum(info['acl'], True)
                acl = json.loads(f.read())
                a = posix1e.ACL(text=acl)
                a.applyto(outname)
            except Exception:
                logger.warning("Unable to process extended attributes for %s", outname)

def doRecovery(regenerator, info, authenticate, path, outname):
    myname = outname if outname else "stdout"
    logger.info("Recovering file %s %s", Util.shortPath(path), notSame(path, myname, " => " + Util.shortPath(myname)))

    checksum = info['checksum']
    i = regenerator.recoverChecksum(checksum, authenticate)

    if i:
        if authenticate:
            hasher = crypt.getHash()

        if info['link']:
            # read and make a link
            i.seek(0)
            x = i.read(16 * 1024)
            if outname:
                os.symlink(x, outname)
            else:
                logger.warning("No name specified for link: %s", x)
            if hasher:
                hasher.update(x)
        else:
            if outname:
                # Generate an output name
                logger.debug("Writing output to %s", outname)
                output = open(outname,  "wb")
            else:
                output = sys.stdout.buffer
            try:
                x = i.read(16 * 1024)
                while x:
                    output.write(x)
                    if hasher:
                        hasher.update(x)
                    x = i.read(16 * 1024)
            except Exception as e:
                logger.error("Unable to read file: {}: {}".format(i, repr(e)))
                raise
            finally:
                i.close()
                if output is not sys.stdout.buffer:
                    output.close()

            if authenticate:
                outname = doAuthenticate(outname, checksum, hasher.hexdigest())

            setAttributes(regenerator, info, outname)

def recoverObject(regenerator, info, bset, outputdir, path, linkDB, name=None, authenticate=True):
    """
    Main recovery routine.  Recover an object, based on the info object, and put it in outputdir.
    """
    retCode = 0
    outname = None
    skip = False

    try:
        if info:
            realname = crypt.decryptFilename(info['name'])

            if name:
                # This should only happen only one file specified.
                outname = name
            elif outputdir:
                outname = os.path.abspath(os.path.join(outputdir, realname))

            if outname and not checkOverwrite(outname, info):
                skip = True
                try:
                    logger.warning("Skipping existing file: %s %s", Util.shortPath(path), notSame(path, outname, '(' + Util.shortPath(outname) + ')'))
                except Exception:
                    pass

            # First, determine if we're in a linking situation
            if linkDB is not None and info['nlinks'] > 1 and not info['dir']:
                key = (info['inode'], info['device'])
                if key in linkDB:
                    logger.info("Linking %s to %s", outname, linkDB[key])
                    os.link(linkDB[key], outname)
                    skip = True
                else:
                    linkDB[key] = outname

            # If it's a directory, create the directory, and recursively process it
            if info['dir']:
                if not outname:
                    #logger.error("Cannot regenerate directory %s without outputdir specified", path)
                    raise Exception("Cannot regenerate directory %s without outputdir specified" % (path))

                try:
                    logger.info("Processing directory %s", Util.shortPath(path))
                except Exception:
                    pass

                contents = list(tardis.readDirectory((info['inode'], info['device']), bset))

                # Make sure an output directory is specified (really only useful at the top level)
                if not os.path.exists(outname):
                    os.mkdir(outname)

                setAttributes(regenerator, info, outname)

                dirInode = (info['inode'], info['device'])
                files = []
                dirs = []
                # Get info on each child object
                for i in contents:
                    name = crypt.decryptFilename(i['name'])
                    logger.debug("Processing file %s", name)
                    # Get the Info
                    childInfo = tardis.getFileInfoByName(i['name'], dirInode, bset)
                    logger.debug("Info on %s: %s", name, childInfo)
                    if childInfo:
                        if childInfo['dir']:
                            dirs.append((name, childInfo))
                        else:
                            files.append((name, childInfo))
                    else:
                        logger.warning("No info on %s", name)
                        retCode += 1


                # Process the files
                for (name, childInfo) in files:
                    # Recurse into the child, if it exists.
                    try:
                        recoverObject(regenerator, childInfo, bset, outname, os.path.join(path, name), linkDB, authenticate=authenticate)
                    except Exception as e:
                        logger.error("Could not recover file %s in %s", name, path)
                        if args.exceptions:
                            logger.exception(e)

                # And descend into the directories
                if args.recurse:
                    for (name, childInfo) in dirs:
                        try:
                            recoverObject(regenerator, childInfo, bset, outname, os.path.join(path, name), linkDB, authenticate=authenticate)
                        except Exception as e:
                            logger.error("Could not recover directory %s in %s", name, path)
                            if args.exceptions:
                                logger.exception(e)
            elif not skip:
                doRecovery(regenerator, info, authenticate, path, outname)

    except Exception as e:
        logger.error("Recovery of %s failed. %s", outname, e)
        if args.exceptions:
            logger.exception(e)
        retCode += 1

    return retCode

def setupPermissionChecks():
    uid = os.getuid()
    groups = os.getgroups()

    if uid == 0:
        return None     # If super-user, return None.  Causes no checking to happen.

    # Otherwise, create a closure function which can be used to do checking for each file.
    def checkPermission(pUid, pGid, mode):
        if stat.S_ISDIR(mode):
            if (uid == pUid) and (stat.S_IRUSR & mode) and (stat.S_IXUSR & mode):
                return True
            elif (pGid in groups) and (stat.S_IRGRP & mode) and (stat.S_IXGRP & mode):
                return True
            elif (stat.S_IROTH & mode) and (stat.S_IXOTH & mode):
                return True
        else:
            if (uid == pUid) and (stat.S_IRUSR & mode):
                return True
            elif (pGid in groups) and (stat.S_IRGRP & mode):
                return True
            elif stat.S_IROTH & mode:
                return True
        return False

    # And return the function.
    return checkPermission

def findLastPath(path, reduce):
    logger.debug("findLastPath: %s", path)
    # Search all the sets in backwards order
    bsets = list(tardis.listBackupSets())
    for bset in reversed(bsets):
        logger.debug("Checking for path %s in %s (%d)", path, bset['name'], bset['backupset'])
        tmp = Util.reducePath(tardis, bset['backupset'], os.path.abspath(path), reduce, crypt)
        tmp2 = crypt.encryptPath(tmp)
        info = tardis.getFileInfoByPath(tmp2, bset['backupset'])
        if info:
            logger.debug("Found %s in backupset %s: %s", path, bset['name'], tmp)
            return bset['backupset'], tmp, bset['name']
    return (None, None, None)

def recoverName(cksum):
    names = tardis.getNamesForChecksum(cksum)
    #print names
    if names:
        names = map(crypt.decryptFilename, names)
        name = names[0]
        if len(names) > 1:
            logger.warning("Multiple (%d) names for checksum %s %s.  Choosing '%s'.", len(names), cksum, map(str, list(names)), name)
        return name
    else:
        logger.error("No name discovered for checksum %s", cksum)
        return cksum

def mkOutputDir(name):
    if os.path.isdir(name):
        return name
    elif os.path.exists(name):
        logger.error("%s is not a directory", name)
    else:
        os.mkdir(name)
        return name

def parseArgs():
    parser = argparse.ArgumentParser(description='Recover Backed Up Files', fromfile_prefix_chars='@', formatter_class=Util.HelpFormatter, add_help=False)

    (_, remaining) = Config.parseConfigOptions(parser)
    Config.addCommonOptions(parser)
    Config.addPasswordOptions(parser)

    parser.add_argument("--output", "-o",   dest="output", help="Output file", default=None)
    parser.add_argument("--checksum", "-c", help="Use checksum instead of filename", dest='cksum', action='store_true', default=False)

    bsetgroup = parser.add_mutually_exclusive_group()
    bsetgroup.add_argument("--backup", "-b", help="Backup set to use.  Default: %(default)s", dest='backup', default=Defaults.getDefault('TARDIS_RECENT_SET'))
    bsetgroup.add_argument("--date", "-d",   help="Regenerate as of date", dest='date', default=None)
    bsetgroup.add_argument("--last", "-l",   dest='last', default=False, action='store_true', help="Regenerate the most recent version of the file")

    parser.add_argument('--recurse',        dest='recurse', default=True, action=Util.StoreBoolean, help='Recurse directory trees.  Default: %(default)s')
    parser.add_argument('--recovername',    dest='recovername', default=False, action=Util.StoreBoolean,    help='Recover the name when recovering a checksum.  Default: %(default)s')

    parser.add_argument('--authenticate',    dest='auth', default=True, action=Util.StoreBoolean,    help='Authenticate files while regenerating them.  Default: %(default)s')
    parser.add_argument('--authfail-action', dest='authfailaction', default='rename', choices=['keep', 'rename', 'delete'], help='Action to take for files that do not authenticate.  Default: %(default)s')

    parser.add_argument('--reduce-path', '-R',  dest='reduce',  default=0, const=sys.maxsize, type=int, nargs='?',   metavar='N',
                        help='Reduce path by N directories.  No value for "smart" reduction')
    parser.add_argument('--set-times', dest='settime', default=True, action=Util.StoreBoolean,      help='Set file times to match original file. Default: %(default)s')
    parser.add_argument('--set-perms', dest='setperm', default=True, action=Util.StoreBoolean,      help='Set file owner and permisions to match original file. Default: %(default)s')
    parser.add_argument('--set-attrs', dest='setattrs', default=True, action=Util.StoreBoolean,     help='Set file extended attributes to match original file.  May only set attributes in user space. Default: %(default)s')
    parser.add_argument('--set-acl',   dest='setacl', default=True, action=Util.StoreBoolean,       help='Set file access control lists to match the original file. Default: %(default)s')
    parser.add_argument('--overwrite', '-O', dest='overwrite', default=owModeDefault, const='always', nargs='?',
                        choices=['always', 'newer', 'older', 'never', 'ask'],
                        help='Mode for handling existing files. Default: %(default)s')

    parser.add_argument('--hardlinks',  dest='hardlinks',   default=True,   action=Util.StoreBoolean,   help='Create hardlinks of multiple copies of same inode created. Default: %(default)s')

    parser.add_argument('--exceptions',         default=False, action=Util.StoreBoolean, dest='exceptions', help="Log full exception data")
    parser.add_argument('--verbose', '-v',      action='count', default=0, dest='verbose', help='Increase the verbosity')
    parser.add_argument('--version',            action='version', version='%(prog)s ' + Tardis.__versionstring__,    help='Show the version')
    parser.add_argument('--help', '-h',         action='help')

    parser.add_argument('files', nargs='+', default=None, help="List of files to regenerate")

    Util.addGenCompletions(parser)

    return parser.parse_args(remaining)

def main():
    global logger, crypt, tardis, args, owMode
    args = parseArgs()
    logger = Util.setupLogging(args.verbose, stream=sys.stderr)

    try:
        password = Util.getPassword(args.password, args.passwordfile, args.passwordprog, prompt="Password for %s: " % (args.client))
        args.password = None
        (tardis, cache, crypt) = Util.setupDataConnection(args.database, args.client, password, args.keys, args.dbname, args.dbdir)

        r = Regenerator.Regenerator(cache, tardis, crypt=crypt)
    except TardisDB.AuthenticationException:
        logger.error("Authentication failed.  Bad password")
        #if args.exceptions:
            #logger.exception(e)
        sys.exit(1)
    except Exception as e:
        logger.error("Regeneration failed: %s", e)
        if args.exceptions:
            logger.exception(e)
        sys.exit(1)

    try:
        bset = False

        if args.date:
            cal = parsedatetime.Calendar()
            (then, success) = cal.parse(args.date)
            if success:
                timestamp = time.mktime(then)
                logger.info("Using time: %s", time.asctime(then))
                bsetInfo = tardis.getBackupSetInfoForTime(timestamp)
                if bsetInfo and bsetInfo['backupset'] != 1:
                    bset = bsetInfo['backupset']
                    logger.debug("Using backupset: %s %d", bsetInfo['name'], bsetInfo['backupset'])
                else:
                    logger.critical("No backupset at date: %s (%s)", args.date, time.asctime(then))
                    sys.exit(1)
            else:
                logger.critical("Could not parse date string: %s", args.date)
                sys.exit(1)
        elif args.backup:
            #bsetInfo = tardis.getBackupSetInfo(args.backup)
            bsetInfo = Util.getBackupSet(tardis, args.backup)
            if bsetInfo:
                bset = bsetInfo['backupset']
            else:
                logger.critical("No backupset at for name: %s", args.backup)
                sys.exit(1)

        outputdir = None
        output    = sys.stdout.buffer
        outname   = None
        linkDB    = None

        owMode    = overwriteNames[args.overwrite]

        if args.output:
            if len(args.files) > 1:
                outputdir = mkOutputDir(args.output)
            elif os.path.isdir(args.output):
                outputdir = args.output
            else:
                outname = args.output
        logger.debug("Outputdir: %s  Outname: %s", outputdir, outname)

        if args.hardlinks:
            linkDB = {}

        #if args.cksum and (args.settime or args.setperm):
            #logger.warning("Unable to set time or permissions on files specified by checksum.")

        permChecker = setupPermissionChecks()

        retcode = 0
        hasher = None

        # do the work here
        if args.cksum:
            for i in args.files:
                try:
                    if args.auth:
                        hasher = crypt.getHash()
                    ckname = i
                    if args.recovername:
                        ckname = recoverName(i)
                    f = r.recoverChecksum(i, args.auth)
                    if f:
                        logger.info("Recovering checksum %s", ckname)
                    # Generate an output name
                        if outname:
                            # Note, this should ONLY be true if only one file
                            output = open(outname,  "wb")
                        elif outputdir:
                            outname = os.path.join(outputdir, ckname)
                            if os.path.exists(outname) and owMode == OW_NEVER:
                                logger.warning("File %s exists.  Skipping", outname)
                                continue
                            logger.debug("Writing output to %s", outname)
                            output = open(outname,  "wb")
                        elif outname:
                            # Note, this should ONLY be true if only one file
                            if os.path.exists(outname) and owMode == OW_NEVER:
                                logger.warning("File %s exists.  Skipping", outname)
                                continue
                            output = open(outname,  "wb")
                        try:
                            x = f.read(64 * 1024)
                            while x:
                                output.write(x)
                                if hasher:
                                    hasher.update(x)
                                x = f.read(64 * 1024)
                        except Exception as e:
                            logger.error("Unable to read file: {}: {}".format(i, repr(e)))
                            raise
                        finally:
                            f.close()
                            if output is not sys.stdout.buffer:
                                output.close()
                        if args.auth:
                            logger.debug("Checking authentication")
                            outname = doAuthenticate(outname, i, hasher.hexdigest())

                except TardisDB.AuthenticationException:
                    logger.error("Authentication failed.  Bad password")
                    #if args.exceptions:
                        #logger.exception(e)
                    sys.exit(1)
                except Exception as e:
                    logger.error("Could not recover: %s: %s", i, e)
                    if args.exceptions:
                        logger.exception(e)
                    retcode += 1

        else: # Not checksum, but acutal pathnames
            for i in args.files:
                try:
                    i = os.path.abspath(i)
                    logger.info("Processing %s", Util.shortPath(i))
                    path = None
                    f = None
                    if args.last:
                        (bset, path, name) = findLastPath(i, args.reduce)
                        if bset is None:
                            logger.error("Unable to find a latest version of %s", i)
                            raise Exception("Unable to find a latest version of " + i)
                        logger.info("Found %s in backup set %s", i, name)
                    elif args.reduce:
                        path = Util.reducePath(tardis, bset, i, args.reduce, crypt)
                        logger.debug("Reduced path %s to %s", path, i)
                        if not path:
                            logger.error("Unable to find a compute path for %s", i)
                            raise Exception("Unable to compute path for " + i)
                    else:
                        path = i

                    actualPath = crypt.encryptPath(path)

                    logger.debug("Actual path is %s -- %s", actualPath, bset)
                    info = tardis.getFileInfoByPath(actualPath, bset)
                    if info:
                        retcode += recoverObject(r, info, bset, outputdir, path, linkDB, name=outname, authenticate=args.auth)
                    else:
                        logger.error("Could not recover info for %s (File not found)", i)
                        retcode += 1
                except TardisDB.AuthenticationException:
                    logger.error("Authentication failed.  Bad password")
                    #if args.exceptions:
                        #logger.exception(e)
                    sys.exit(1)
                except Exception as e:
                    logger.error("Could not recover: %s: %s", i, e)
                    if args.exceptions:
                        logger.exception(e)
    except KeyboardInterrupt:
        logger.error("Recovery interupted")
    except TardisDB.AuthenticationException as e:
        logger.error("Authentication failed.  Bad password")
        if args.exceptions:
            logger.exception(e)
    except Exception as e:
        logger.error("Regeneration failed: %s", e)
        if args.exceptions:
            logger.exception(e)

    if errors:
        logger.warning("%d files could not be recovered.")

    return retcode

if __name__ == "__main__":
    sys.exit(main())
