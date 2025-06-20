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
import base64
import enum
import hmac
import json
import logging
import os
import os.path
import sys
import time

import parsedatetime
import posix1e
import xattr

import Tardis

from . import Config, Defaults, Regenerator, TardisCrypto, TardisDB, Util

logger: logging.Logger
eLogger: Util.ExceptionLogger
crypt: TardisCrypto.CryptoScheme
args: argparse.Namespace

class OwMode(enum.StrEnum):
    OW_NEVER  = 'never'
    OW_ALWAYS = 'always'
    OW_NEWER  = 'newer'
    OW_OLDER  = 'older'
    OW_PROMPT = 'ask'

if sys.stdout.isatty():
    owMode = OwMode.OW_PROMPT
else:
    owMode = OwMode.OW_NEVER
owModeDefault = str(owMode)

errors = 0

tardis = None
args:argparse.Namespace

def yesOrNo(x):
    if x:
        x = x.strip().lower()
        return x[0] == 'y'
    return False

def checkOverwrite(name, info):
    if os.path.exists(name):
        match (owMode):
            case OwMode.OW_NEVER:
                return False
            case OwMode.OW_ALWAYS:
                return True
            case OwMode.OW_PROMPT:
                return yesOrNo(input(f"Overwrite {name} [y/N]: "))
            case OwMode.OW_NEWER | OwMode.OW_OLDER:
                s = os.lstat(name)
                if s.st_mtime < info['mtime']:
                    # Current version is older
                    return owMode == OwMode.OW_NEWER
                # Current version is newer
                return owMode == OwMode.OW_OLDER
    return True

def doVerifyContents(outname, checksum, digest):
    """
    Check that the recorded checksum of the file, and the digest of the generated file match.
    Perform the expected action if they don't.  Return the name of the file that's being generated.
    """
    logger.debug("File: %s Expected Hash: %s Hash: %s", outname, checksum, digest)
    # should use hmac.compare_digest() here, but it's not working for some reason.  Probably different types
    if not hmac.compare_digest(checksum, digest):
        if outname:
            if args.verifyaction == 'keep':
                action = ''
                target = outname
            elif args.verifyaction == 'rename':
                target = outname + '-CORRUPT-' + str(digest)
                action = 'Renaming to ' + target + '.'
                try:
                    os.rename(outname, target)
                except os.error:
                    action = "Unable to rename to " + target + ".  File saved as " + outname + "."
            elif args.verifyaction == 'delete':
                action = 'Deleting.'
                os.unlink(outname)
                target = None
            else:
                logger.critical(f"Unknown verify failure action: {args.verifyaction}")
                action = ''
                target = outname
        else:
            target = None
            action = ''
        if outname is None:
            outname = ''
        logger.error("File %s did no.  Expected: %s.  Got: %s.  %s",
                     outname, checksum, digest, action)
        return target
    return outname

def notSame(a, b, string):
    if a == b:
        return ''
    return string

def setAttributes(regenerator, info, outname):
    if outname:
        if args.setperm:
            try:
                logger.debug("Setting permissions on %s to %o", outname, info['mode'])
                os.chmod(outname, info['mode'])
            except OSError:
                logger.warning("Unable to set permissions for %s", outname)
            try:
                # Change the group, then the owner.
                # Change the group first, as only root can change owner, and that might fail.
                os.chown(outname, -1, Util.getGroupId(crypt.decryptName(info['groupname'])))
                os.chown(outname, Util.getUserId(crypt.decryptName(info['username'])), -1)
            except OSError:
                logger.warning("Unable to set owner and group of %s", outname)
        if args.settime:
            try:
                logger.debug("Setting times on %s to %d %d", outname, info['atime'], info['mtime'])
                os.utime(outname, (info['atime'], info['mtime']))
            except OSError:
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
            except IOError:
                logger.warning("Unable to process extended attributes for %s", outname)
        if args.setacl and 'acl' in info and info['acl']:
            try:
                f = regenerator.recoverChecksum(info['acl'], True)
                acl = json.loads(f.read())
                a = posix1e.ACL(text=acl)
                a.applyto(outname)
            except Exception:
                logger.warning("Unable to process extended attributes for %s", outname)

CHUNKSIZE = 256 * 1024

def doRecovery(regenerator, info, authenticate, path, outname):
    myname = outname if outname else "stdout"
    logger.info("Recovering file %s %s", Util.shortPath(path), notSame(path, myname, " => " + Util.shortPath(myname)))

    checksum = info['checksum']
    instream = regenerator.recoverChecksum(checksum, authenticate=authenticate)

    if instream:
        hasher = crypt.getHash()

        if info['link']:
            # read and make a link
            instream.seek(0)
            x = instream.read(16 * 1024)
            hasher.update(x)
            if outname:
                os.symlink(x, outname)
            else:
                logger.warning("No name specified for link: %s", x)
        else:
            if outname:
                # Generate an output name
                logger.debug("Writing output to %s", outname)
                output = open(outname,  "wb")
            else:
                output = sys.stdout.buffer
            try:
                while x := instream.read(CHUNKSIZE):
                    output.write(x)
                    hasher.update(x)
            except Exception as e:
                logger.error(f"Unable to read file: {checksum}: {repr(e)}")
                raise
            finally:
                instream.close()
                if output is not sys.stdout.buffer:
                    output.close()

            outname = doVerifyContents(outname, checksum, hasher.hexdigest())

            setAttributes(regenerator, info, outname)

def recoverObject(regenerator, info, bset, outputdir, path, linkDB, name=None, authenticate=True):
    """
    Main recovery routine.  Recover an object, based on the info object, and put it in outputdir.
    """
    retCode = 0
    outname = None
    skip = False

    try:
        realname = crypt.decryptName(info['name'])

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
                raise Exception(f"Cannot regenerate directory {path} without outputdir specified")

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
                name = crypt.decryptName(i['name'])
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
                    eLogger.log(e)

            # And descend into the directories
            if args.recurse:
                for (name, childInfo) in dirs:
                    try:
                        recoverObject(regenerator, childInfo, bset, outname, os.path.join(path, name), linkDB, authenticate=authenticate)
                    except Exception as e:
                        logger.error("Could not recover directory %s in %s", name, path)
                        eLogger.log(e)
        elif not skip:
            doRecovery(regenerator, info, authenticate, path, outname)

    except Exception as e:
        logger.error("Recovery of %s failed. %s", outname, e)
        eLogger.log(e)
        retCode += 1

    return retCode

def setupPermissionChecks():
    uid = os.getuid()
    groups = os.getgroups()

    if uid == 0:
        return None     # If super-user, return None.  Causes no checking to happen.

    return Util.checkPermission

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
    if names:
        names = list(map(crypt.decryptName, names))
        name = names[0]
        if len(names) > 1:
            logger.warning("Multiple (%d) names for checksum %s %s.  Choosing '%s'.", len(names), cksum, map(str, list(names)), name)
        return name

    logger.error("No name discovered for checksum %s", cksum)
    return cksum

def mkOutputDir(name):
    if os.path.isdir(name):
        return name
    if os.path.exists(name):
        logger.error("%s is not a directory", name)
        raise Exception(f"{name} is not a directory")
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
    bsetgroup.add_argument("--backup", "-b", dest='backup', default=Defaults.getDefault('TARDIS_RECENT_SET'), help="Backup set to use.  Default: %(default)s")
    bsetgroup.add_argument("--date", "-d",   dest='date', default=None, help="Regenerate as of date", )
    bsetgroup.add_argument("--last", "-l",   dest='last', default=False, action='store_true', help="Regenerate the most recent version of the file")

    parser.add_argument('--recurse', '-r',    dest='recurse', default=True, action=argparse.BooleanOptionalAction, help='Recurse directory trees.  Default: %(default)s')
    parser.add_argument('--recovername',      dest='recovername', default=False, action=argparse.BooleanOptionalAction,    help='Recover the name when recovering a checksum.  Default: %(default)s')

    parser.add_argument('--authenticate',    dest='auth', default=True, action=argparse.BooleanOptionalAction,    help='Cryptographically authenticate files while regenerating them.  Only for encrypted backups. Default: %(default)s')
    parser.add_argument('--verify-action',   dest='verifyaction', default='rename', choices=['keep', 'rename', 'delete'], help='Action to take for files that do not verify their checksum.  Default: %(default)s')

    parser.add_argument('--reduce-path',     dest='reduce',  default=0, const=sys.maxsize, type=int, nargs='?',   metavar='N',
                        help='Reduce path by N directories.  No value for "smart" reduction')
    parser.add_argument('--set-times',       dest='settime', default=True, action=argparse.BooleanOptionalAction,      help='Set file times to match original file. Default: %(default)s')
    parser.add_argument('--set-perms',       dest='setperm', default=True, action=argparse.BooleanOptionalAction,      help='Set file owner and permisions to match original file. Default: %(default)s')
    parser.add_argument('--set-attrs',       dest='setattrs', default=True, action=argparse.BooleanOptionalAction,     help='Set file extended attributes to match original file.  May only set attributes in user space. Default: %(default)s')
    parser.add_argument('--set-acl',         dest='setacl', default=True, action=argparse.BooleanOptionalAction,       help='Set file access control lists to match the original file. Default: %(default)s')
    parser.add_argument('--overwrite', '-O', dest='overwrite', default=owModeDefault, const='always', nargs='?',
                        choices=list(map(str, OwMode)),
                        help='Mode for handling existing files. Default: %(default)s')

    parser.add_argument('--hardlinks',       dest='hardlinks',   default=True,   action=argparse.BooleanOptionalAction,   help='Create hardlinks of multiple copies of same inode created. Default: %(default)s')

    parser.add_argument('--exceptions', '-E',   dest='exceptions', default=False, action=argparse.BooleanOptionalAction, help="Log full exception data")
    parser.add_argument('--verbose', '-v',   dest='verbose', action='count', default=0, help='Increase the verbosity')
    parser.add_argument('--version',         action='version', version='%(prog)s ' + Tardis.__versionstring__,    help='Show the version')
    parser.add_argument('--help', '-h',      action='help')

    parser.add_argument('files', nargs='+', default=None, help="List of files to regenerate")

    Util.addGenCompletions(parser)

    return parser.parse_args(remaining)

def processFiles(files: list[str], r: Regenerator.Regenerator, bset: bool|int, outputdir: str, outname: str):
    retcode = 0
    linkDB    = None
    if args.hardlinks:
        linkDB = {}

    for i in files:
        try:
            i = os.path.abspath(i)
            logger.info("Processing %s", Util.shortPath(i))
            path = None
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
            sys.exit(1)
        except Exception as e:
            logger.error("Could not recover: %s: %s", i, e)
            eLogger.log(e)
    return retcode

def processChecksums(checksums: list[str], r: Regenerator.Regenerator, outputdir: str, outname: str):
    retcode = 0
    for i in checksums:
        try:
            hasher = crypt.getHash()
            output = None
            ckname = i
            if args.recovername:
                ckname = recoverName(i)
            logger.info("Recovering checksum %s -> %s", i, ckname)
            # Recover the checksum, but don't attempt to authenticate it.   We'll do that ourselves later
            f = r.recoverChecksum(i, args.auth)

            if f:
            # Generate an output name
                if not outname:
                    if outputdir:
                        outname = os.path.join(outputdir, ckname)
                    else:
                        outname = ckname
                        # Note, this should ONLY be true if only one file
                    if os.path.exists(outname) and owMode == OwMode.OW_NEVER:
                        logger.warning("File %s exists.  Skipping", outname)
                        continue
                    logger.debug("Writing output to %s", outname)
                try:
                    output = open(outname,  "wb")
                    while x := f.read(CHUNKSIZE):
                        hasher.update(x)
                        output.write(x)
                except Exception as e:
                    logger.error(f"Unable to read file: {i}: {repr(e)}")
                    raise
                finally:
                    f.close()
                    outname = None
                    if output is not sys.stdout.buffer:
                        output.close()
                if args.auth:
                    logger.debug("Checking authentication")
                    outname = doVerifyContents(outname, i, hasher.hexdigest())

        except TardisDB.AuthenticationException:
            logger.error("Authentication failed.  Bad password")
            sys.exit(1)
        except Exception as e:
            logger.error("Could not recover: %s: %s", i, e)
            eLogger.log(e)
            retcode += 1
    return retcode

def calculateBackupSet():
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
                raise ValueError(time.asctime(then))
        else:
            logger.critical("Could not parse date string: %s", args.date)
            raise ValueError(args.date)
    elif args.backup:
        bsetInfo = Util.getBackupSet(tardis, args.backup)
        if bsetInfo:
            bset = bsetInfo['backupset']
        else:
            logger.critical("No backupset at for name: %s", args.backup)
            raise ValueError(args.backup)
    return bset


def main():
    global logger, eLogger, crypt, tardis, args, owMode
    args = parseArgs()
    logger = Util.setupLogging(args.verbose, stream=sys.stderr)
    eLogger = Util.ExceptionLogger(logger, args.exceptions, True)

    try:
        password = Util.getPassword(args.password, args.passwordfile, args.passwordprog, prompt=f"Password: ")
        args.password = None
        (tardis, cache, crypt, client) = Util.setupDataConnection(args.repo, password, args.keys)

        r = Regenerator.Regenerator(cache, tardis, crypt=crypt)
    except TardisDB.AuthenticationException:
        logger.error("Authentication failed.  Bad password")
        sys.exit(1)
    except Exception as e:
        logger.error("Regeneration failed: %s", e)
        eLogger.log(e)
        sys.exit(1)

    retcode = 0
    try:
        bset = calculateBackupSet()

        outputdir = None
        outname   = None

        owMode    = OwMode(args.overwrite)

        if args.output:
            if len(args.files) > 1:
                outputdir = mkOutputDir(args.output)
            elif os.path.isdir(args.output):
                outputdir = args.output
            else:
                outname = args.output
        logger.debug("Outputdir: %s  Outname: %s", outputdir, outname)

        # do the work here
        if args.cksum:
            retcode = processChecksums(args.files, r, outputdir, outname)
        else: # Not checksum, but acutal pathnames
            retcode = processFiles(args.files, r, bset, outputdir, outname)
    except KeyboardInterrupt:
        logger.error("Recovery interupted")
    except TardisDB.AuthenticationException as e:
        logger.error("Authentication failed.  Bad password")
        eLogger.log(e)
    except Exception as e:
        logger.error("Regeneration failed: %s", e)
        eLogger.log(e)

    if errors:
        logger.warning("%d files could not be recovered.")

    return retcode

if __name__ == "__main__":
    sys.exit(main())
