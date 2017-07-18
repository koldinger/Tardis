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
Tardis relies on the msgpack, xattrs, pycryptodome (pycryptodomex), daemonize, parsedatetime, flask, tornado, requests, requests-cache, passwordmeter, python-snappy, 
and termcolor packages, and their associated libraries.
Tardis uses a modified version of the librsync library, which adapts it to support he most recent versions of librsync.
When/if a correct functional version appears on Pypi, we'll use it instead.  See https://github.com/smartfile/python-librsync

Important Release Notes
=======================
Post 0.31.11 changes the directory hashing scheme.  It is recommended that you run the `tools/setDirHashes.py` program (or run `encryptDB.py --dirhashes`, but only if your database is encrypted) to reset the hashes to the new scheme.  This is not necessary, but without it your next backup job will run longer than usual.  It will self correct after the first backup run.

Future Releases
===============
Several releases will be coming soon:
  * 0.32.0 Brings in a modification the communications protocol, and changes the login  mechanism to use SRP (Secure Remote Password) authentication.  **This will require simultaneous upgrades of all the tools, client and server, and manual intervention to add SRP credentials to any encrypted database.**
  * 0.32.1 Will bring automatic database upgrades.  This should be the final new feature before 1.0
  * 0.32.2+ Will be bug fixes, if necessary.
  * 1.0.0 Formal release
  * 2.0.0 Will (hopefully) introduce a web interface to allow controlling backup jobs.
  
Installation
============
Installing  up the server is relatively straightforward.
  * Install librsync, python fuse, and python developmen, and a couple other packages.
    * Fedora: `{yum|dnf} install librsync libacl-devel libffi-devel python-devel python-fuse python-setuptools gmp snappy-devel`
    * Ubuntu/Debian: a`pt-get install librsync1 libacl1-dev libffi-dev python-dev python-fuse libcurl4-openssl-dev python-setuptools libgmp3-dev libsnappy-dev`
  * Run the python setup:
    * `python setup.py install`

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
         * `cp init/tardisd.service /usr/lib/systemd/system`
         * `systemctl enable tardisd.service`
         * start the service
           * `systemctl start tardisd.service`
      * SysV init
         * `cp init/tardisd /etc/init.d`
         * `chkconfig --add tardisd`
         * `chkconfig tardisd on`
         * start the service
           * `service tardisd start`
     * Repeat the process with the tardisremote scripts, if you wish to support accessing the database via the remote protocol.

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
If you wish encrypted backups, add the --password or --password-file options to specify a password.

Your first backup will take quite a while.  Subsequent backups will be significantly faster.

Once you have an initial backup in place, put this in your cron job to run daily.
You can also run hourly incremental backups with a -H option instead of the -A above.
Adding --purge to your command line will remove old backupsets per a schedule of hourly's after a day, daily's after 30 days, weekly's after 6 months, and monthly's never.

Note on Passwords
=================
*There is no mechanism for recovering a lost password.  If you lose it, you're done.*

Passwords can be changed with the sonic utility.

All client tools take a couple of password options.  `--password` or `-P` will allow you to specify a password on the command line, or if no password is specified, it will prompt you to enter one.  The second option is `--password-file` or `-F`, in which case you can specify a path to the file containing the password in plaintext.  The path can be either a file path (relative or absolute) on the current system, or a URL of a remote file (file:, http:, https:  or ftp:).  A third option is `--password-prog`, after which you can specify a program command line to generate a password.  The program should output the password to standard output, and the first line will be read and used as the password.

Tardisfs supports all the same options, with slightly different syntax.  All are specified via the -o syntax to fuse mount.  `-o password=*password*` will use *password* as the password, `-o password=` will prompt for a password, `-o pwfile=*path*` will read the password from *path* (which accepts the same options as `--password-file` above), and `-o pwprog=*program*` will run *program*, same as `--password-prog` above.

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
Files can be listed in the `tardisfs`, or via the `lstardis` application.

`lstardis` can list all versions of a file available.  See `lstardis -h` for details.

Comparing versions of files
===========================
`tardiff` can directly compare two versions of a file in the database, or a file in the database, and it's corresponding version
in the filesystem.

See `tardiff -h` for details.

Recovering Files
================
Files can be recovered in two different ways: via the `regenerate` application, and via a `tardisfs` filesystem.

The filesystem approach is often the easiest method.  In this technique, a filesystem is mounted which contains the results of all the backupsets.  At the top level, there is a directory for each backup set.  Underneath these directories, are the full image of the backuped directories in a standard directory tree, as they appeared at the time of the backup.  Files can easily be copied out of this tree to their desired locations.

Files can also be recovered via the regenerate application. The regenerate application takes the name of the file to be recovered, and can also be given a date for which to regenerate the file.  Dates can be via the --date (-d) option, and can be specified via a large variety of forms.  For instance `regenerate -d '3 days ago' filename` will regenerate a version from 3 days earlier.  Dates can also be specified expclitly in a wide variety of formats, such as "03/15/2014" to specify March 15, 2014 (obviously).

Regenerate can be used to recover entire directory trees.  In general, using regenerate to recover files will be siginicantly faster than rsync'ing out of tardisfs.

See `regenerate -h` for details.

At present, the regenerate application does NO permission checking to determine if a user has permission to read a file.  Thus, any file in the database set can be accessed by anybody with access to the backup database.  If this is a problem in your environment, it is recommended to disable the regenerate application (or at least protect the database with a password that you don't share with all users), and allow access primarily through a tardisfs filesystem controlled by the super-user.  See Mounting the Filesystem below.

Utility Functions
=================
The sonic program is useful for manipulating a backup.  Sonic provides various functions whch don't fit well elsewhere.
These include:
   * create -- Create a new backup (can only be run on the server machine)
   * setpass -- Set a password into a backup.  Note, this will not encrypt any current contents of the backup.
   * chpass -- Change the password of a backup.
   * keys -- Extract or insert the encyrption keys of an encrypted backup.
   * list -- List all backup sets.
   * files -- Print a list of files that were updated in a specified backup set.
   * info -- Print information about each backup set.  Very slow, not recommended (deprecated)
   * purge -- Purge old backup sets, based on the criteria presented.
   * delete -- Delete a specific backup set.
   * orphans -- Purge out orphanned data in the backup set.  Can be very slow running.
   * getconfig -- Get a server side configuration value, or all values.
   * setconfig -- Set a server side configuration value.

These options are available as subcommands, for instance:
    sonic list <options>
Each subcommand takes a different set of options, although many are common.


Environment Variables
=====================

| Variable | Description | Default | Users |
| -------- | ----------- | ------- | ----- |
| TARDIS_DB             | Location of the tardis database| /srv/tardis | User Tools |
| TARDIS_PORT           | Port to use to connect to the Tardis Daemon | 7420 | Client, Daemon |
| TARDIS_DBNAME         | Name of the database file containing tardis information| tardis.db | Daemon, Remote, User Tools |
| TARDIS_SERVER         | Name (or IP address) of the tardis server| localhost | Client |
| TARDIS_CLIENT         | Name of the backup client. |Current hostname | Client, User Tools |
| TARDIS_DAEMON_CONFIG  | Name of the file containing the daemon configuration| /etc/tardis/tardisd.cfg| Daemon |
| TARDIS_LOCAL_CONFIG   | Name of the file containing the configuration when running the daemon in local mode|  /etc/tardis/tardisd.local.cfg| Daemon |
| TARDIS_EXCLUDES       | Name of the file containing patterns to exclude below the current directory.| .tardis-excludes | Client |
| TARDIS_LOCAL_EXCLUDES | Name of the file containing patterns to exclude *only* in the local directory.| .tardis-local-excludes| Client |
| TARDIS_GLOBAL_EXCLUDES| Name of the file containing patterns to exclude globally| /etc/tardis/excludes| Client |
| TARDIS_SKIP           | Name of a file whose presence excludes a current directory (and all directories below)| .tardis-skip| Client |
| TARDIS_PIDFILE        | File to indicate that the daemon is running.| /var/run/tardisd.pid | Daemon |
| TARDIS_SCHEMA         | File containing the schema for the database.| schema/tardis.sql | Daemon |
| TARDIS_LS_COLORS      | Description of colors for lstardis | | lstardis |
| TARDIS_REMOTE_PORT    | Port used for the HTTP Remote interface| 7430 | Remote, User Tools |
| TARDIS_REMOTE_CONFIG  | Configuration file for tardisremote| /etc/tardis/tardisremote.cfg | Remote |
| TARDIS_REMOTE_PIDFILE | Path to the pidfile for tardisremote daemon.| /var/run/tardisremote.pid| Remote |
| TARDIS_DEFAULTS       | Location of a defaults file.| /etc/tardis/system.defaults | All |
| TARDIS_RECENT_SET     | Name to use for most recent, complete backup | Current | User tools |
| TARDIS_SEND_CONFIG    | Send the running configuration to the server, mainly for debug. | True | Client

Notes:
    * User tools are lstardis, regenerate, tardiff, and sonic.
    * Client is the tardis app.
    * Daemon is the tardisd app.

System Defaults
---------------
The above environment variables can have default values set via the system defaults file.  This file is located at /etc/tardis/system.defaults, or can be overridden by the TARDIS_DEFAULTS environment variable.
The system.defaults file is not installed by default.

Format is a standard .ini file, with variables in the Tardis section, and each variable specified with the names in the table above.

The location of the defaults files can be overridden by the TARDIS_DEFAULTS environment variable.

Configuration
=============
All applications in the Tardis suite can take options from multiple locations.  These locations are, in order:
the default value, the system default, the configuration file, and the command line.
Thus, the system default overrides the built in default, the configuration overrides either of those, and the command line arguments
override all of the other options.  Note that some options can only be specified on the command line.

Command line arguments for many tools can be specified in a file, accessed via the @ symbol.  For instance 
    tardis @file -list
will read _file_ as if it were arguments presented on the command line.

Client Configuration Files
==========================
Client tools can read from multiple configuration files.
By default, configurations are read from Tardis section, but can be overridden by using the --job option.

| Name            | Default Value       | Environment Var   | Definition |
| ---             | ------------        | ----------------- | ---------- |
| Server          | localhost           | TARDIS_SERVER     | Server to use for backups |
| Port            | 7420                | TARDIS_PORT       | Port to listen on |
| Client          | hostname            | TARDIS_CLIENT     | Name of the system to backup |
| Force           | False               |                   | Force the backup, even if another one might still be running. |
| Full            | False               |                   | Perform a full backup (no delta's, full files for previous deltas. |
| Timeout         | 300                 |                   | Time out (in seconds) for connections. |
| Password        |                     |                   | Password.  Only of on the 3 password configs can be set. |
| PasswordFile    |                     |                   | File name of a file containing the password |
| PassswordProg   |                     |                   | Program to prompt for a password. |
| Crypt           | True                |                   | Encrypt data in the backup.  A Password must be set to enable tihs. |
| KeyFile         |                     |                   | File containing the keys. |
| CompressData    | none                |                   | Compress data using this algorithm.  Choices are none, zlib, bzip, lzma |
| CompressMin     | 4096                |                   | Minimum size file to compress. |
| NoCompressFile  |                     | TARDIS_NOCOMPRESS | File containing a list of mime type files to not attempt to compress
| NoCompress      |                     |                   | Mime types to not compress |
| SendClientConfig| True                | TARDIS_SEND_CONFIG| Send the client configuration (arguments) to the server. |
| Local           | False               |                   | Perform a local backup.  Spawns a server as a child process. |
| LocalServerCmd  | tardisd --config    |                   | Command for running the local server. |
| CompressMsgs    | none                |                   | Compress messages to the server.  Choices are none, zlib, zlib-stream, snappy |
| ChecksumContent | 0                   |                   | Always checksum files greater than this size. |
| Purge           | False               |                   | Purge old content ||
| IgnoreCVS       | False               |                   | Ignore source code control files (CVS, SVN, RCS, and git) |
| SkipCaches      | False               |                   | Skip cachedir directories |
| SendSig         | False               |                   | Always send a signature.  Only valid for non-encrypted backups. |
| ExcludePatterns |                     |                   | Filename patterns to ignore.  Glob file format |
| ExcludeFiles    |                     |                   | File containing patterns to ignore. |
| ExcludeDirs     |                     |                   | Directories to exclude. |
| GlobalExcludeFileName |               |                   | Path to a global file containing filename patterns to exclude.|
| ExcludeFileName | .tardis-exclude     |                   | Check for this file in each directory, and exclude files which match it's pattern in current directory and all below. |
| LocalExcludeFileName | .tardis-local-exclude |            | Same, but only in the current directory. |
| SkipFileName    | .tardis-skip        |                   | If this file exists, skip this directory and all below. |
| LogFiles        |                     |                   | List of files to log to. |
| Verbosity       | 0                   |                   | Verbosity level. |
| Stats           | False               |                   | Print some stats on the backup when complete. |
| Report          | False               |                   | Print a list of all files backed up when complete. |
| Directories     | .                   |                   | List of directories to backup. |


Server Configuration File
=========================
The server configuration file, usually in /etc/tardis/tardisd.cfg, is in the standard .ini file format.  There is a single section, "[Tardis]", containing all the variables.  The following configuration variables are defined:

| Name            | Default Value       | Environment Var | Definition |
| ---             | ------------        | --------------- | ---------- |
| Port            | 7420                | TARDIS_PORT     | Port to listen on |
| BaseDir         | /srv/tardis         | TARDIS_DB       | Directory containing all databases handled by this server |
| DBName          | tardis.db           | TARDIS_DBNAME   | Name of the database containing all metadata |
| Schema          | schema/tardis.sql   | TARDIS_SCHEMA   | Path to the file containing the database schema. |
| LogFile         | None                |                 | Filename for logging.  stderr if not specified. |
| JournalFile     | tardis.journal      |                 | Journal file for logging which files are dependent on others.  Stored in the DB directory for each client. |
| Profile         | False               |                 | If true, a profile of each session will be generated and printed to stdout| 
| AllowNewHosts   | False               |                 | If True, any new host can connect and create a backup set.  If false, a directory with the hostname that the client wil provide must be created prior to the client attempting to perform a backup. |
| RequirePassword | False               |                 | Require all backups to have a password. |
| SaveConfig      | True                |                 | Save the client's configuration, if sent. |
| LogExceptions   | False               |                 | Log full detail of all exceptions, including call chain. |
| MaxDeltaChain   | 5                   |                 | Maximum number of delta's to request before requesting an entire new copy of a file. |
| MaxChangePercent| 50                  |                 | Maximum percentage change in file size allowed before requesting an entire new copy of a file. |
| SaveFull        | False               |                 | Always save entire copies of a file in the database.  Ignored if the client is sending encrypted data. |
| AllowSchemaUpgrades | False           |                 | Allow the server to automatically upgrade the database schemas |
| Single          | False               |                 | Run a single client backup session, and exit. |
| Local           | None                |                 | Path to a Unix Domain Socket to use.  If specified, overrides the Port value.
| Verbose         | 0                   |                 | Level of verbosity.  0 is silent, 1 gives summaries of each client session, 2 and above get very noisy. |
| Daemon          | False               |                 | Run as a daemon process, detaching from the initial process, and running in the background. |
| Umask           | 2 (002)             |                 | Mode mask used when creating files in the database. |
| User            | None                |                 | Name of the user to run as when run in daemon mode. |
| Group           | None                |                 | Name of the group to run as when run in daemon mode. |
| PidFile         | None                |                 | Path to the file indicating that a tardis daemon process is running.  Must be set if Daemon is true. |
| SSL             | False               |                 | Use SSL over the socket. |
| CertFile        | None                |                 | Path to the certificate file for SSL communications.  Must be set if SSL is true. |
| KeyFile         | None                |                 | Path to the key file for SSL communications.  Must be set if SSL is true. |
| SkipFileName    | .tardis-skip        | TARDIS_SKIP     | Skip file name to be created in the backup directories. |
| Formats         | Monthly-%Y-%m, Weekly-%Y-%U, Daily-%Y-%m-%d | Formats of names to use for the different types of variables.  A common and whitespace separated list of formats.  Format is of the same type as used by pythons time.strptime() function.  Each name will be checked in order. |
| Priorities      | 40, 20, 10          |                 | Priority value corresponding to the names in the Formats value. |
| KeepPeriods     | 0, 180, 30          |                 | Number of days to keep for each backup type, corresponding to the names in the Formats value. |
| DBBackups       | 5                   |                 | Number of backup iterations of the database to keep. |

TardisRemote Configuration File
===============================

| Name            | Default Value       | Environment Var | Definition |
| ---             | ------------        | --------------- | ---------- |
| Port            | 7420                | TARDIS_PORT     | Port to listen on |
| Database        | /srv/tardis         | TARDIS_DB       | Directory containing all databases handled by this server |
| DBName          | tardis.db           | TARDIS_DBNAME   | Name of the database containing all metadata |
| LogFile         | None                |                 | Filename for logging.  stderr if not specified. |
| LogExceptions   | False               |                 | Log full detail of all exceptions, including call chain. |
| Verbose         | 0                   |                 | Level of verbosity.  0 is silent, 1 gives summaries of each client session, 2 and above get very noisy. |
| Daemon          | False               |                 | Run as a daemon process, detaching from the initial process, and running in the background. |
| User            | None                |                 | Name of the user to run as when run in daemon mode. |
| Group           | None                |                 | Name of the group to run as when run in daemon mode. |
| PidFile         | None                |                 | Path to the file indicating that a tardis daemon process is running.  Must be set if Daemon is true. |
| SSL             | False               |                 | Use SSL over the socket. |
| CertFile        | None                |                 | Path to the certificate file for SSL communications.  Must be set if SSL is true |
| KeyFile         | None                |                 | Path to the key file for SSL communications.  Must be set if SSL is true |
| Compress        | True                |                 | Allow compression of data across HTTP, if the cilent accepts it. |
| AllowCache      | True                |                 | Allow the client to cache responses to HTTP requests. |
| AllowSchemaUpgrades | False           |                 | Allow the server to automatically upgrade the database schemas |

Mounting the filesystem
=======================
The backup sets can be mounted as a filesystem, thus:
   tardisfs -o database=/path/to/database [-o host=hostname] [-o password=[your_password]] mountpoint
/path/to/the/backup/directory will be the path specified in the BaseDir in the server host config.  The host parameter is the name of the host that you wish to mount backups for.

Password should only be set if a password is specified in the backup.  If you leave it blank (ie, password=), it will prompt you for a password during mount.

tardisfs options are specified in a format to enable fstab mounting.  Each option is specified as `-o name=value`.  For instance, `-o database=/nfs/tardis -o client=hostname`.  Options can be specified in a fstab, such as:
```
tardisfs#0				/mnt/tardis/ClientName	fuse	user,noauto,default_permissions,allow_other,database=/nfs/tardis/,client=ClientName	0 2
```

Due to the nature of FUSE filesystems, allowing any user to mount the filesystem can create a potential security hole, as most permissions are ignored.  The most effective way to perserve some security is to mount the filesystem as root, with the "-o allow_other -o default_permissions" options specified.  This allows all users to access the file system, and enforces standard Unix file permission checking.

Encrypting an Unencrypted Backup
================================
If you've built an unencrypted backup, and wish to add encryption, this can be accomplished, primarily using the encryptDB.py application in the tools directory.  Note, this is only semi-debugged.  Use at your own risk.

The following steps should be performed:
   * Add a password to the database:
      * `sonic setpass [-D /path/to/database] [-C client] [--password [password]| --password-file path | --password-prog program]`
   * Encrypt the filenames.  This step must be performed only once, unless it fails.  It should either encrypt all the filenames, or none.  If executed more than once, it will gladly doubly encrypt the passwords.  This can be a mess.
      * `python tools/encryptDB.py [-D /path/to/database] [-C client] [--password [password]| --password-file path | --password-prog program] --filenames`
   * Generate new directory hashes.  This step is optional, but will improve performance (and database size) on the next backup.  If interrupted, this step can be restarted.  It will regenerate any information already calculated, but this is fine, just slow.
      * `python tools/encryptDB.py [-D /path/to/database] [-C client] [--password [password]| --password-file path | --password-prog program] --dirhashes`
   * Encrypt the files.  This step can be run multiple times, and will only encrypt files which have not been encrypted already, and thus restarted.  It *SHOULD* leave the backup in a consistent state if you cancel out, but again, use at your own risk.  This takes a LONG time.  During this phase, the database should still be accessible, but some data is encrypted and some is not.  This should be transparent to any users.  You *should* even be able to run backups while this takes place.
      * `python tools/encryptDB.py [-D /path/to/database] [-C client] [--password [password]| --password-file path | --password-prog program] --files`
   * Generate new metadata files.  This is optional, but can be useful should the database become corrupted.  This also takes a LONG time, but can be run entirely transparently to any other activities.
      * `python tools/encryptDB.py [-D /path/to/database] [-C client] [--password [password]| --password-file path | --password-prog program] --meta`

Logwatch Support
================
Basic logwatch support is available in the logwatch directory.  You have to install these files by hand, no support is in setup.py yet.

MacOS X Support
===============
I'm in the early stages of testing Tardis on MacOS X, but it appears that, for the most part, it works, at least the client.

Note, you need to use the [homebrew](http://brew.sh "Homebrew") to install Python, and librsync.

Tested only on Yosemite.

Notes on Data Storage
=====================
Data is stored in a database directory on the backup server.  There is one directory for each client backedup, and named based on the client name.

Within this directory are several files:
*  tardis.db - A SQLite3 database containing the metadata of all the files.
*  tardis.db.{date}-{time}.gz - Several backup databases containing the last few database snapshots, in case the main database becomes corrupted.
*  tardis.journal - A text file containing enough information to recover the contents of various files, namely the hash value of the file, it's basis file (None if it is not a delta, otherwise the hash of the delta file), and finally it's initialization vector.

There are also up to 256 subdirectories, number in hex from 00-ff, containing the data.  Within these are a second level of subdirectories, which then contain the actual data.  The actual data for each individual file is stored in named with the hash value (either the MD5, or the HMAC-MD5, if a password is set) of the contents of the file.  The contents is the fully reconstructed contents, not the actual contents of the current file.

If the data is unencrypted, it is stored directly in the file, as either the raw data of the file (possibly compressed, if the client so specified) or as an rdiff delta.

If the data is encrypted, the above data is encapsulated in the following format: the first 16 bytes (128 bits) are the initilization vector for the encryption, currently AES-256-CBC.  After this comes the data, as above, encrypted.  This data is padded ala PKCS#7, in binary.  The last 64 bytes (512 bits) of the file contain an HMAC of the data (including the PAD) using HMAC-SHA512.

Along with each file xxx, there is a corresponding file xxx.sig, containing the rdiff signature of the file, and a file xxx.meta, which contains information allowing reconstruction of the file (if not it's filename) should the database be corrupted.
