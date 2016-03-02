Tardis-Backup
=============

A Time Machine style backup system.

Tardis is a system for making incremental backups of filesystems, much like Apple's TimeMachine.

Tardis began due to some frustrations with using pure rsync to do backups.  Tardis is more efficient with disk space,
it's able to coalesce duplicate copies of files, and stores file metadata separately from file data.  Tardis is also aimed
at having a relatively compact server, capable of running on small machines, such as a Raspberry PI.  Tardis is (hopefully)
relatively platform independent, although it's only been tested on linux so far.  It should work on MacOS, and should be
easy ported to Windows.

Tardis consists of several components:
* tardisd (Daemon.py): The tardis daemon process which maintains the backups
* tardis  (Client.py): The tardis client process, which creates backup data and pushes it to the server
* tardisfs (TardisFS.py): A FUSE based file system which provides views of the various backup sets.
* regenerate (Regenerate.py): A program to retrieve an individual verson of the file without using the TardisFS
* lstardis (List.py): List versions of files and directories in the database.
* tardiff (Diff.py): Show the differences between versions of backed up files, and the current version.
* sonic (Sonic.py): An administration tool, allowing things like setting and changing passwords, removing backup sets, purging orphans, etc.
* tardisremote (HttpInterface): A server, still under development, which provides a web api for retrieving information in the tardis database, for use by regenerate, tardisfs, and lstardis

Tardis is currently under development, but is at beta level.
Features currently planned to be implemented:

1. ~~Handling multiple filesystems~~ (mostly handled.  Some potential issues)
2. ~~Saving of extended attributes and access control lists~~
2. ~~Saving of per-connection configuration values in the server DB~~
3. ~~Authentication of password~~
4. ~~Encrypted encryption key stored on server, decrypted on client?~~
5. ~~Option to save key on the client.~~
5. ~~User authentication capability (this differs from 3 above. 3 is to make sure the password/encryption key remains the same.  Currently different backup sessions could use different keys, and basically create a mess of everything).~~
6. ~~Python EGG setup.~~
7. ~~Better daemon support.~~
8. ~~LSB init script (systemctl support)?~~
9. Space management.  ~~Multiple purge schedules for different priorities.~~  On demand purging when low on space.
10. ~~Client side configuration files.~~ (as argument files)
11. ~~Stand alone execution (no need for separate server)~~
12. ~~Remote access to data and files.~~
13. ~~Read password without echo.~~

Tardis relies on the ~~bson~~, msgpack, xattrs, pycrypto, daemonize, parsedatetime, flask, tornado, ~~pycurl,~~ requests, and termcolor packages.
Tardis uses the librsync package, but since that is not current on pypi, it's copied in here.  When/if a correct functional version appears on Pypi, we'll use it instead.  See https://github.com/smartfile/python-librsync

Note: as of version 0.15, references to host or hostname have been changed to client to eliminate confusion betweeen host and server.

Future Releases
===============
Several releases will be coming soon:
  * 0.24 Changes to the encryption format, and support for the ability to store the keys out of the database file.
  * 0.25 Changes to the encryption format to support HMAC based authentication, and tagging of files.  Fixes for bugs.  
  * 0.26 Improvements to all tools to bring compatibility together.  Functioning version of tardisremote.
  
Installation
============
Installing  up the server is relatively straightforward.
  * Install librsync, python fuse, and python development
    * Fedora: yum install librsync libacl-devel libffi-devel python-devel python-fuse python-setuptools
    * Ubuntu/Debian: apt-get install librsync1 libacl1-dev libffi-dev python-dev python-fuse libcurl4-openssl-dev python-setuptools
  * Run the python setup:
    * python setup.py install

Server Setup
============
  * Edit the config file, /etc/tardis/tardisd.cfg
      * Set the BaseDir variable to point at a location to store all your databases.
      * Set the Port to be the port you want to use.  Default is currently 7420.
  * If you want to use SSL, create a certificate and a key file (plenty of directions on the web).
  * Edit other parameters as necessary.
  * Create your backup directory, if need by (mkdir */path/to/your/backup/directory*)
  * Add a tardis user (adduser tardis)
  * Create a log directory (mkdir */var/log/tardisd*)
  * Copy the appropriate startup script as desired
      * Systemd/systemctl based systems (such as Fedora 20)
         * cp init/tardisd.service /usr/lib/systemd/system
         * systemctl enable tardisd.service
         * start the service
          * systemctl start tardisd.service
      * SysV init
         * cp init/tardisd /etc/init.d
         * chkconfig --add tardisd
         * chkconfig tardisd on
         * start the service
          * service tardisd start

Server Requirements
-------------------
The server should run on any system running Linux.  Fedora, Ubuntu, and Raspbian have all been used successfully

It does not need to be particularly powerful.  A Raspberry Pi Model B has been used, but is a bit underpowered.  A Raspberry Pi 2 Model B seems to work quite well, primarily due to the larger memory.

Typically, a faster processor and more memory will lead to shorter backup times, as will faster I/O connections to the disk drives.  On a benchmark system, a Raspberry Pi server would run a backup in about 40-50 minutes, a Raspberry Pi 2 will reduce that time to under 30 minutes, and a dual core 1.5GHz Celeron (with 4GB of memory, and USB 3.0 disk drives) will run the benchmark in 3-5 minutes.  

Running the Client
==================
Should probably run as root.  Basic operation is thus:
  tardis [--port <targetPort>] [--server <host>] [--ssl] /path/to/directory-to-backup <more paths here>
Use the --ssl if your connection is SSL enabled.
If you wish encrypted backups, add the --password or --password-file options to specify a password.  ~~Note, if you use encrypted backups, you must always specify the same password.  Tardis doesn't currently check, but you're in a heap of pain of you get it wrong.  Or at least a LOT of wasted disk space, and unreadable files.~~

Your first backup will take quite a while.  Subsequent backups will be significantly faster.

Once you have an initial backup in place, put this in your cron job to run daily.
You can also run hourly incremental backups with a -H option instead of the -A above.
Adding --purge to your command line will remove old backupsets per a schedule of hourly's after a day, daily's after 30 days, weekly's after 6 months, and monthly's never.

Note on Passwords
=================
There is no mechanism for recovering a lost password.  If you lose it, you're done.

Passwords can be changed with the sonic utility.

Running the Client without a Server locally
===========================================
It is possible to run the tardis client without connecting to a remote server.  When doing this, the server is run as a subprocess under the client.
Simply add the --local option to your tardis client, and it will invoke a server for duration of that run.
Ex:
    tardis --local ~
Will backup your home directory.

When running locally, Tardis will start a local server running for the duration of the backup job.  The server can be configured via a configuration file specified in the TARDIS_LOCAL_CONFIG
variable/configuration argument.  See below for details.

Listing Versions of Files Available
===================================
Files can be listed in the tardisfs, or via the lstardis application.

lstardis can list all versions of a file available.  See lstardis -h for details.

lstardis is new in version 0.15.

Recovering Files
================
Files can be recovered in two different ways: via the regenerate application, and via a tardisfs filesystem.

The filesystem approach is often the easiest method.  In this technique, a filesystem is mounted which contains the results of all the backupsets.  At the top level, there is a directory for each backup set.  Underneath these directories, are the full image of the backuped directories in a standard directory tree, as they appeared at the time of the backup.  Files can easily be copied out of this tree to their desired locations.

Files can also be recovered via the regenerate application. The regenerate application takes the name of the file to be recovered, and can also be given a date for which to regenerate the file.  Dates can be via the --date (-D) option, and can be specified via a large variety of forms.  For instance "regenerate -D '3 days ago' filename" will regenerate a version from 3 days earlier.  Dates can also be specified expclitly in a wide variety of formats, such as "03/15/2014" to specify March 15, 2014 (obviously).

Regenerate can be used to recover entire directory trees.  In general, using regenerate to recover files will be siginicantly faster than rsync'ing out of tardisfs.

See regenerate -h for details.

At present, the regenerate application does NO permission checking to determine if a user has permission to read a file.  Thus, any file in the database set can be accessed by anybody with access to the backup database.  If this is a problem in your environment, it is recommended to disable the regenerate application (or at least protect the database with a password that you don't share with all users), and allow access primarily through a tardisfs filesystem controlled by the super-user.  See Mounting the Filesystem below.

Environment Variables
=====================

<table>
    <tr>
        <th>Variable
        <th>Description
        <th>Default
        <th>tardis
        <th>tardisd
        <th>tardisfs
        <th>regenerate
        <th>lstardis
    </tr>
    <tr>
        <td>TARDIS_DB
        <td>Location of the tardis database
        <td>/srv/tardis
        <td>No (Except in local case) <td>Yes <td>Yes <td>Yes <td> Yes
    <tr>
        <td> TARDIS_PORT
        <td>Port to use to connect to the Tardis Daemon
        <td> 7420
        <td>Yes (except in local case) <td>Yes <td>No <td>No <td> No
    <tr>
        <td> TARDIS_DBNAME
        <td> Name of the database file containing tardis information
        <td> tardis.db
        <td> No <td> Yes <td> Yes <td> Yes <td> Yes
    <tr>
        <td> TARDIS_SERVER
        <td> Name (or IP address) of the tardis server
        <td> localhost
        <td> Yes <td> No <td> No <td> No <td> No
    <tr>
        <td> TARDIS_CLIENT
        <td> Name of the backup client.
        <td> Current hostname (essentialy output of /usr/bin/hostname)
        <td> Yes <td> No <td> Yes <td> Yes <td> Yes
    <tr>
        <td> TARDIS_DAEMON_CONFIG
        <td> Name of the file containing the daemon configuration
        <td> /etc/tardis/tardisd.cfg
        <td> No (except in local case) <td> Yes <td> No <td> No <td> No
    <tr>
        <td> TARDIS_LOCAL_CONFIG
        <td> Name of the file containing the configuration when running the daemon in local mode
        <td> /etc/tardis/tardisd.local.cfg
        <td> No (except in local case) <td> Yes (only in local case) <td> No <td> No <td> No
    <tr> 
        <td> TARDIS_EXCLUDES
        <td> Name of the file containing patterns to exclude below the current directory.
        <td> .tardis-excludes
        <td> Yes <td> No <td> No <td> No <td> No
    <tr>
        <td> TARDIS_LOCAL_EXCLUDES
        <td> Name of the file containing patterns to exclude <i>only</i> in the local directory.
        <td> .tardis-local-excludes
        <td> Yes <td> No <td> No <td> No <td> No
    <tr>
        <td> TARDIS_GLOBAL_EXCLUDES
        <td> Name of the file containing patterns to exclude globally
        <td> /etc/tardis/excludes
        <td> Yes <td> No <td> No <td> No <td> No
    <tr>
        <td> TARDIS_SKIPFILE
        <td> Name of a file whose presence excludes a current directory (and all directories below)
        <td> .tardis-skip
        <td> Yes <td> No <td> No <td> No <td> No
    <tr>
        <td> TARDIS_PIDFILE
        <td> File to indicate that the daemon is running.
        <td> /var/run/tardisd.pid
        <td> No <td> Yes <td> No <td> No <td> No
    <tr>
        <td> TARDIS_SCHEMA
        <td> File containing the schema for the database.
        <td> schema/tardis.sql
        <td> No <td> Yes <td> No <td> No <td> No
    <tr>
       <td> TARDIS_LS_COLORS
       <td> Description of colors for lstardis
       <td> 
       <td> No <td> No <td> No <td> No <td> Yes
    <tr>
       <td> TARDIS_DEFAULTS
       <td> Location of a defaults file.
       <td> /etc/tardis/system.defaults
       <td> Yes <td> Yes <td> Yes <td> Yes <td> Yes
</table>

System Defaults
---------------
The above environment variables can have default values set via the system defaults file.  This file is located at /etc/tardis/system.defaults, or can be overridden by the TARDIS_DEFAULTS environment variable.  The system.defaults file is not installed by default.

Format is a standard .ini file, with variables in the Tardis section, and each variable specified with the names in the table above.

The location of the defaults files can be overridden by the TARDIS_DEFAULTS environment variable.

Server Configuration File
=========================
The server configuration file, usually in /etc/tardis/tardisd.cfg, is in the standard .ini file format.  There is a single section, "[Tardis]", containing all the variables.  The following configuration variables are defined:

<table>
  <tr>
   <th> Name
   <th> Default Value
   <th> Definition
  <tr> <td> Port
   <td> 7420
   <td> Port to listen on
  <tr> <td> BaseDir
   <td> /srv/tardis
   <td> Directory containing all databases handled by this server
  <tr> <td> DBName
   <td> tardis.db
   <td> Name of the database containing all metadata
  <tr> <td> Schema
   <td> schema/tardis.sql
   <td> Path to the file containing the database schema.
  <tr> <td> LogFile
   <td> None
   <td> Filename for logging.  stderr if not specified.
  <tr> <td> JournalFile
   <td> tardis.journal
   <td> Journal file for logging which files are dependent on others.  Stored in the DB directory for each client.
  <tr> <td> Profile
   <td> False
   <td> If true, a profile of each session will be generated and printed to stdout
  <tr> <td> AllowNewHosts
   <td> False
   <td> If True, any new host can connect and create a backup set.  If false, a directory with the hostname that the client wil provide must be created prior to the client attempting to perform a backup.
  <tr> <td> RequirePassword
   <td> False
   <td> Require all backups to have a password.
  <tr> <td> LogExceptions
   <td> False
   <td> Log full detail of all exceptions, including call chain.
  <tr> <td> MaxDeltaChain
   <td> 5
   <td> Maximum number of delta's to request before requesting an entire new copy of a file.
  <tr> <td> MaxChangePercent
   <td> 50
   <td> Maximum percentage change in file size allowed before requesting an entire new copy of a file.
  <tr> <td> SaveFull
   <td> False
   <td> Always save entire copies of a file in the database.  Ignored if the client is sending encrypted data.
  <tr> <td> Single
   <td> False
   <td> Run a single client backup session, and exit.
  <tr> <td> Local
   <td> None
   <td> Path to a Unix Domain Socket to use.  If specified, overrides the Port value.
  <tr> <td> Verbose
   <td> 0
   <td> Level of verbosity.  0 is silent, 1 gives summaries of each client session, 2 and above get very noisy.
  <tr> <td> Daemon
   <td> False
   <td> Run as a daemon process, detaching from the initial process, and running in the background.
  <tr> <td> Umask
   <td> 2 (002)
   <td> Mode mask used when creating files in the database.
  <tr> <td> User
   <td> None
   <td> Name of the user to run as when run in daemon mode.
  <tr> <td> Group
   <td> None
   <td> Name of the group to run as when run in daemon mode.
  <tr> <td> PidFile
   <td> None
   <td> Path to the file indicating that a tardis daemon process is running.  Must be set if Daemon is true.
  <tr> <td> SSL
   <td> False
   <td> Use SSL over the socket.
  <tr> <td> CertFile
   <td> None
   <td> Path to the certificate file for SSL communications.  Must be set if SSL is true.
  <tr> <td> KeyFile
   <td> None
   <td> Path to the key file for SSL communications.  Must be set if SSL is true
  <tr> <td> MonthFmt, WeekFmt, DayFmt
   <td> Monthly-%Y-%m, Weekly-%Y-%U, Daily-%Y-%m-%d
   <td> Formats for the names of backup sets for Monthly, Weekly and Daily backups, when the client doesn't set a backup set name.  In a format accepted by Python's datetime.strftime() function
  <tr> <td> MonthPrio, WeekPrio, DayPrio
   <td> 40, 20, 10
   <td> Priority value for Monthly, Weekly, and Daily backups, when the client doesn't provide one.
  <tr> <td> MonthKeep, WeekKeep, DayKeep
   <td> 0, 180, 30
   <td> Number of days to keep for Monthly, Weekly, and Daily backups.  0 indicates keep forever.
  <tr> <td> DBBackups
   <td> 5
   <td> Number of backup iterations of the database to keep.
  
</table>
Mounting the filesystem
=======================
The backup sets can be mounted as a filesystem, thus:
   tardisfs -o database=/path/to/database [-o host=hostname] [-o password=[your_password]] mountpoint
/path/to/the/backup/directory will be the path specified in the BaseDir in the server host config.  The host parameter is the name of the host that you wish to mount backups for.

Password should only be set if a password is specified in the backup.  If you leave it blank (ie, password=), it will prompt you for a password during mount.

Other options are available via -help.  (details TBD)

Due to the nature of FUSE filesystems, allowing any user to mount the filesystem can create a potential security hole, as most permissions are ignored.  The most effective way to perserve some security is to mount the filesystem as root, with the "-o allow_other -o default_permissions" options specified.  This allows all users to access the file system, and enforces standard Unix file permission checking.

Logwatch Support
================
Basic logwatch support is available in the logwatch directory.  You have to install these files by hand, no support is in setup.py yet.

MacOS X Support
===============
I'm in the early stages of testing Tardis on MacOS X, but it appears that, for the most part, it works, at least the client.

Note, you need to use the [homebrew](http://brew.sh "Homebrew") to install Python, and librsync.  You'll also need to remove all references to pyacl and posix1e in setup.py and Tardis/Client.py.  I'll adjust the code later to do this automatically, once testing proceeds.

Beyond this, it appears to function as normal.

Tested only on Yosemite.

Bugs in 0.21
============
I've identified two bugs in the 0.21 release that can have major impacts.
  * File sizes are incorrectly recorded in compressed backups.  No real fix right now.  Data is just wrong in the database.
  * Encryption keys are improperly generated if you use the --client option to tardis or any of the command line tools.   Keys are generated as if you were using the value in the TARDIS_CLIENT variable (or the default hostname if you haven't specified TARDIS_CLIENT).  This could be a major problem for existing encrypted databases that used a non-default client value originally.

If you install after this message is here, from a post 0.21 version, these bugs are fixed.  If you have an encrypted or compressed (or both) database before, I recommend proceeding with extreme caution.  Maintain a 0.22 installation and use it to extract your backup data.

Note on Post 0.21 Installation
==============================
Sometime after the 0.21 release, the BSON package I was using in Tardis disappeared.  As a result, I've switched from using BSON to a different serialization format called MsgPack.  BSON is still supported if it's on your system, but MsgPack has become the default.

Also, post 0.21 I've introduced checking in the Daemon to make sure you have the correct database version.  If you are out of date, it will complain.  There are scripts in the schema directory called things like "convert2-3.py", "convert3-4.py", etc, to convert the various formats.  These scripts are invoked "python convert3-4.py /path/to/tardis.db".  Some are significant, for instance 4-5 is really slow (you can remove the SQL Update command and be just fine, it will be hugely faster, should you so desire).

0.22 Changes the database functionality in an attempt to make things a bit faster, and to fix an issue with encrypted backups, have added some new information to the database.  You don't need to do anything to deal with this, but it will cause a couple of backups after you upgrade to be significantly slower.  You can run the setDirHashes script in the tools directory.  This takes same sort of arguments as tardis, and will automatically generate the correct hash values.   Should only take a few minutes, depending on the speed of the machine you're running on, and the speed of the disk drive.

Note on 0.24 and 0.25 Releases
==============================
The 0.24 release changes the format of the encrypted files.  The goal is to make the encrypted files easier to recover should the database become damaged.  No longer will the file's initialization vector be stored in the database.  Instead, it will be stored as the first 16 bytes of the file.  In addition, the padding will be compatible with PKCS#7, ie padding with the number of bytes to delete.  As a result, files which are a multiple of the blocksize will be padded with an additional block.  Thus, files may increase by up to 32 bytes in practice, 16 for the init vector, and 16 for the padding.

The result of this is that encrypted backups with 0.24 and later are not compatible with files from 0.23 and earlier.  I am working on a script, but just need to find some time to complete it, hopefully in the next few days.

The 0.25 release again changes the format of the encrypted files, as well as the naming convention, adding an HMAC at the end of the files for authentication.  Prior to 0.25, all database files were name based on
the MD5 checksum of the original file.  Starting in 0.25, if a password is added, these files will be named using the HMAC-MD5 of the original file, or the MD5 checksum if no password is used.
This is regardless of the setting of the --crypt flag to tardis.

Correspondingly, the 0.25 release adds a --authenticate/--noauthenticate switch to the regenerate program. This authenticates both the components of the files, and the fully recovered output. 
When converting to a 0.25 from a previous version, the --noauthenticate switch may be needed for regenerate to correctly regenerate data files.

0.24 also introduces a new way to store keys.   Keys are normally stored in encrypted format in the database.  As of 0.24, keys can be stored independently in a user controlled file.  They still remain encrypted.
This key database is accessed via the --keys option to the client and regenerate, and the "keys=filename" option to tardisfs.

The "keys" file can support multiple backup targets in a single file. 

If this file is used, it must NOT be lost.  If you lose the keys file, there is no way to reconstruct it.  Even if you back it up into tardis, once lost, you will not be
able to recover it.

The contents of this file are kept encrypted.
