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
* tardisd (TardisDaemon): The tardis daemon process which maintains the backups
* tardis  (TardisClient): The tardis client process, which creates backup data and pushes it to the server
* TardisFS: A FUSE based file system which provides views of the various backup sets.
* regenerate (Regenerate): A program to retrieve an individual verson of the file without using the TardisFS

Tardis is currently under development, but is at beta level.
Features currently planned to be implemented:

1. ~~Handling multiple filesystems~~ (mostly handled.  Some potential issues)
2. Saving of extended attributes
2. ~~Saving of per-connection configuration values in the server DB~~
3. ~~Authentication of password~~
4. Encrypted encryption key stored on server, decrypted on client?
5. ~~User authentication capability (this differs from 3 above. 3 is to make sure the password/encryption key remains the same.  Currently different backup sessions could use different keys, and basically create a mess of everything).~~
6. ~~Python EGG setup.~~
7. ~~Better daemon support.~~
8. ~~LSB init script (systemctl support)?~~
9. Space management.  Multiple purge schedules for different prioritys.  On demand purging when low on space.
10. ~~Client side configuration files.~~ (as argument files)
11. ~~Stand alone execution (no need for separate server)~~
12. Remote access to data and files.
13. ~~Read password without echo.~~

Tardis relies on the bson, xattrs, pycrypto, and daemonize packages.
~~Tardis currently uses the librsync from rdiff-backup, but I hope to remove that soon.~~
Tardis uses the librsync package, but since that is not current on pypi, it's copied in here.  When/if a correct functional version appears on Pypi, we'll use it instead.  See https://github.com/smartfile/python-librsync

Installation
============
Installing  up the server is relatively straightforward.
  * Install librsync, python fuse, and python development
    * Fedora: yum install librsync  python-devel python-fuse python-setuptools
    * Ubuntu/Debian: apt-get install librsync python-dev python-fuse python-setuptools
  * Run the python setup:
    * python setup.py install

Server Setup
============
  * Edit the config file, /etc/tardis/tardisd.cfg
      * Set the BaseDir variable to point at a location to store all your databases.
      * Set the Port to be the port you want to use.  Default is currently 7430.
  * If you want to use SSL, create a certificate and a key file (plenty of directions on the web).
  * Edit other parameters as necessary.
  * Copy the appropriate startup script as desired
      * Systemd/systemctl based systems (such as Fedora 20
         * cp init/tardisd.service /usr/lib/systemd/system
         * systemctl enable tardisd.service
      * SysV init
         * cp init/tardisd /etc/init.d
         * chkconfig --add tardisd
         * chkconfig tardisd on
         * service tardisd start

Running the Client
==================
Should probably run as root.  Basic operation is thus:
  tardis [--port <targetPort>] [--server <host>] [--ssl] /path/to/directory-to-backup <more paths here>
Use the --ssl if your connection is SSL enabled.
If you wish encrypted backups, add the --password or --password-file options to specify a password.  Note, if you use encrypted backups, you must always specify the same password.  Tardis doesn't currently check, but you're in a heap of pain of you get it wrong.  Or at least a LOT of wasted disk space, and unreadable files.

Your first backup will take quite a while.  Subsequent backups will be significantly faster.

Once you have an initial backup in place, put this in your cron job to run daily.
You can also run hourly incremental backups with a -H option instead of the -A above.
Adding --purge to your command line will remove old backupsets per a schedule of hourly's after a day, daily's after 30 days, weekly's after 6 months, and monthly's never.

Running the Client without a Server locally
===========================================
It is possible to run the tardis client without connecting to a remote server.  When doing this, the server is run as a subprocess under the client.
Simply add the --local option to your tardis client, and it will invoke a server for duration of that run.
Ex:
    tardis --local ~
Will backup your home directory.


Environment Variables
=====================

<table>
    <tr>
        <td>Variable
        <td>Description
        <td>Default
        <td>tardis
        <td>tardisd
        <td>tardisfs
        <td>regenerate
    </tr>
    <tr>
        <td>TARDIS_DB
        <td>Location of the tardis database
        <td>/srv/tardis
        <td>No (Except in local case)
        <td>Yes
        <td>Yes
        <td>Yes
    <tr>
        <td> TARDIS_PORT
        <td>Port to use to connect to the Tardis Daemon
        <td> 7430
        <td>Yes (except in local case)
        <td>Yes
        <td>No
        <td>No
    <tr>
        <td> TARDIS_DBNAME
        <td> Name of the database file containing tardis information
        <td> tardis.db
        <td> No
        <td> Yes
        <td> Yes
        <td> Yes
    <tr>
        <td> TARDIS_SERVER
        <td> Name (or IP address) of the tardis server
        <td> localhost
        <td> Yes
        <td> No
        <td> No
        <td> No
    <tr>
        <td> TARDIS_HOST
        <td> Name of the backup set.
        <td> Current hostname (/usr/bin/hostname)
        <td> Yes
        <td> No
        <td> Yes
        <td> Yes
    <tr>
        <td> TARDIS_DAEMON_CONFIG
        <td> Name of the file containing the daemon configuration
        <td> /etc/tardis/tardisd.cfg
        <td> No (except in local case)
        <td> Yes
        <td> No
        <td> No
    <tr>
        <td> TARDIS_LOCAL_CONFIG
        <td> Name of the file containing the configuration when running the daemon in local mode
        <td> /etc/tardis/tardisd.local.cfg
        <td> No (except in local case)
        <td> Yes (only in local case)
        <td> No
        <td> No
    <tr> 
        <td> TARDIS_EXCLUDES
        <td> Name of the file containing patterns to exclude below the current directory.
        <td> .tardis-excludes
        <td> Yes
        <td> No
        <td> No
        <td> No
    <tr>
        <td> TARDIS_LOCAL_EXCLUDES
        <td> Name of the file containing patterns to exclude <i>only</i> in the local directory.
        <td> .tardis-local-excludes
        <td> Yes
        <td> No
        <td> No
        <td> No
    <tr>
        <td> TARDIS_GLOBAL_EXCLUDES
        <td> Name of the file containing patterns to exclude globally
        <td> /etc/tardis/excludes
        <td> Yes
        <td> No
        <td> No
        <td> No
    <tr>
        <td> TARDIS_SKIPFILE
        <td> Name of a file whose presence excludes a current directory (and all directories below)
        <td> .tardis-skip
        <td> Yes
        <td> No
        <td> No
        <td> No
    <tr>
        <td> TARDIS_PIDFILE
        <td> File to indicate that the daemon is running.
        <td> /var/run/tardisd.pid
        <td> No
        <td> Yes
        <td> No
        <td> No
    <tr>
        <td> TARDIS_SCHEMA
        <td> File containing the schema for the database.
        <td> schema/tardis.sql
        <td> No
        <td> Yes
        <td> No
        <td> No
</table>

Mounting the filesystem
=======================
The backup sets can be mounted as a filesystem, thus:
   tardisfs -o database=/path/to/database [-o host=hostname] [-o password=[your_password]] mountpoint
/path/to/the/backup/directory will be the path specified in the BaseDir in the server host config.  The host parameter is the name of the host that you wish to mount backups for.

Password should only be set if a password is specified in the backup.  If you leave it blank (ie, password=), it will prompt you for a password during mount.

Other options are available via -help.  (details TBD)

