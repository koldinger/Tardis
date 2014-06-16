Tardis
======

A TimeMachine that mostly works.

Tardis is a system for making incremental backups of filesystems, much like Apple's TimeMachine,
although not quite as polished.

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

Tardis is currently under development, but appears to be sufficiently bug free to start some use.
Features currently planned to be implemented:

1. Handling multiple filesystems
2. Saving of extended attributes
2. Saving of per-connection configuration values in the server DB
3. Authenitcation of password
4. Encrypted encryption key stored on server, decrypted on client?
5. User authentication capability (this differs from 3 above. 3 is to make sure the password/encryption key remains the same.  Currently different backup sessions could use different keys, and basically create a mess of everything).
6. ~~Python EGG setup.~~
7. ~~Better daemon support.~~
8. LSB init script (systemctl support)?
9. Space management.  Multiple purge schedules for different prioritys.  On demand purging when low on space.
10. Client side configuration files.

Tardis relies on the bson, xattrs, pycrypto, and daemonize packages.
Tardis currently uses the librsync from rdiff-backup, but I hope to remove that soon.

Setup
=====
Setting up the server is relatively straightforward.
Install into a directory (will be replaced with egg support at a later date).
Edit the config file, tardisd.cfg (in /etc, should you so desire)
Set the BaseDir variable to point at a location to store all your databases.
Set the port to be the port you want to use.  Default is currently 9999.
If you want to use SSL, create a certificate and a key file (plenty of directions on the web).
Set the 
Start the client as a "service" (better configuration coming later):
  nohup tardisd --config <path-to-your-tardisd.cfg> &

Running the Client
==================
Should probably run as root.  Basic operation is thus:
  tardis [--port <targetPort>] --server <host> [--ssl] -A /path/to/directory-to-backup <more paths here>
Use the --ssl if your connection is SSL enabled.
If you wish encrypted backups, add the --password or --password-file options to specify a password.  Note, if you use encrypted backups, you must always specify the same password.  Tardis doesn't currently check, but you're in a heap of pain of you get it wrong.  Or at least a LOT of wasted disk space, and unreadable files.

Your first backup will take quite a while.  Subsequent backups will be significantly faster.

Once you have an initial backup in place, put this in your cron job to run daily.
You can also run hourly incremental backups with a -H option instead of the -A above.
Adding --purge to your command line will remove old backupsets per a schedule of hourly's after a day, daily's after 30 days, weekly's after 6 months, and monthly's never.

Mounting the filesystem
=======================
The backup sets can be mounted as a filesystem, thus:
   tardisfs -o path=/path/to/the/backup/directory [-o password=your_password] mountpoint
/path/to/the/backup/directory will be the path specified in the BaseDir in the server host config, plus the hostname of the machine you've backup up.  The password option should be specified if the backups are encrypted.


