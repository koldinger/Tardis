QuickStart
==========
Install Tardis on your local machine.  :ref:Installation

Local Backup
------------
If you wish to perform a simple backup to a local disk, without the overhead of running a server, simply
    * configure the backup location, in /etc/tardis/system.defaults
           [Tardis]

           TARDIS_DB: <path/to/database/directory>

    * Run a local backup command:
           tardis --local directory_to_backup [other_directories_to_backup]

Your first backup job is likely to be very long.  Subsequent backups will run significantly faster.

If you wish to use encyrpted backups, add the --password (or -P) command line option:
   tardis --password [password] --local directory_to_backup [other_directories_to_backup]
If you don't specify a password, you will be prompted to enter a password.
Note, if you don't specify a password on the command line, you must either have another option come after the --password option, or if it's the last option,
add the -- to separate the directory list from the options.  If not, you may end up with the first directory specified as the password.

If you wish to have compressed backups, add the --compress-data (or -Z) option:
    tardis --local [--password [password]] --compress-data [minimum_size] [--]

Note that the password must be specified the first time you attempt to backup, or you must add it later with the :ref:'sonic' command.

Recovering a Local Backup
-------------------------

There are two methods to recover backed-up files, via a filesystem, or via the regenerate command.

Command Line Recovery
^^^^^^^^^^^^^^^^^^^^^
The 'regenerate' command is used to regenerate files.  To regenerate a file in the current directory, simply perform:
    regenerate filename [filenames]
will regenerate the as of the most recent backupset, and send it to standard out.

If you have an encrypted backup, specify the --password/-P options, as above
    regenerate --password [password] [--] filename [filenames]

You can also specify an output file (if you want to recover only a single file) or a directory, via the --output/-o option.
    regenerate [--password [password]] -o directory filename [filenames]
If you have versions of the file currently in your directories, you can specify the --overwrite/-O option.  --overwrite optionally takes several modes,
always, never, newer, older, to specify when to overwrite the existing file:
    regenerate [--password [password]] -O -o directory [--] filename [filenames]

If your filename is a directory, regenerate will recursively regenerate the directory.

If you wish to recover a version of the file that is not the most recent, you can specify --backup/-b option, with the name of the backupset, or the date the
backup was created, and regenerate it it that way.
    regenerate --backup name [--password [password]] -O -o directory [--] filename [filenames]
eg:
    regenerate --backup Monthly-2016-03 -o tmp fileA fileB
will get fileA and fileB from the Monthly-2016-03 backupset, and save them in the directory tmp.
You can also use the --date/-d to specify the date at which to recover the backup.  The date can be verbose and relative, such as "yesterday", "last january", etc.
    regenerate --date "last tuesday" -o tmp fileA fileB
will get fileA and fileB from the current backupset as of last tuesday.

Also, the --last/-l will regenerate the last version of a file that was backed up, even if it has been deleted from recent backup sets.

Filesystem recovery
^^^^^^^^^^^^^^^^^^^
The Tardis filesystem creates a read-only filesystem that 

To mount the filesystem, use the tardisfs command:
    tardisfs [-o password=[password]] mountpoint
where mountpoint is an empty directory in which you wish to mount the filesystem.  The filesystem can be unmounted with the command:
    'fusermount -u mountpoint'

On the tardisfs command, if you specify the password= option without a password, you will be prompted to enter it.

The filesystem will contain a set of directories, one for each backupset in the database.  Thus, you may see something like this:
    % ls -F mountpoint
    Current@    Daily-2016-04-27 Daily-2016-04-26 Monthly-2016-04 Weekly-2016-17
There will always be a "Current" link, pointing to the most recent complete backup.

Remote Backups
--------------
Tardis can backup to remote servers.  To do this, you need to configure the remote backup server, and run the tardis daemon application (tardisd).

Server Configuration
^^^^^^^^^^^^^^^^^^^^
On the server, perform the original steps above specifying a location for the database. 
You can specify this either via the /etc/tardis/system.defaults file, as above, or via a server specific configuration file, /etc/tardis/tardisd.cfg.

In the latter, you should specify it thus:
    [Tardis]

    BaseDir=/path/to/backup/directory

    LogFile=/path/to/logfile

Start the server.

Backup to Remote Server
^^^^^^^^^^^^^^^^^^^^^^^
Backup to a remote server works exactly like backing up to a local server, except you specify the --server/-s option instead of the --local
option.
    tardis --server servername [--password [password]] [--compress-data [minimum_size]] [--] directory [directories]
servername is either the DNS name of the server, or it's IP address.

Recovery from Remote Server
^^^^^^^^^^^^^^^^^^^^^^^^^^^
To recover from a remote backup server, the server must export the database, either via a network filesystem such as NFS or SMB/CIFS (Samba), or via the
tardisremote.

Recovery with Network Filesystem
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If using a remote filesystem, please see other sources to determine how to export the filesystem from the server, and mount it on the client.  The directory
exported should be the same as the BaseDir option in the tardisd.cfg file.

To regenerate with the regenerate program, on the client you can either specify the mounted location in the /etc/tardis/system.defaults file (the TARDIS_DB option)
or via the --database/-D option:
    regenerate --database /path/to/mountpoint [other regenerate options]

Similarly, for the tardisfs program, you can add the '-o database=/path/to/mountpoint' option:
    tardisfs -o database=/path/to/mountpoint [-o password=[password]] mountpoint

Recovery with TardisRemote
~~~~~~~~~~~~~~~~~~~~~~~~~~
On the server, configure the tardisremote application, and start it running.  Tardisremote will read the /etc/tardis/tardisremote.cfg file for configuration.  It will
export an HTTP server on port 7430 (by default) which exposes a web application.

On the client, specify a URL to the server via the database option:
    regenerate --database http://server_name [other generate options]

For tardisfs:
    tardisfs -o database=http://server_name [other generate options] mountpoint

Note: tardisremote is still under development, and shows some random data corruption problems on some platforms.  At present, we don't believe this is a bug in
tardisremote itself, but instead in the Flask or Tornado tools that tardisremote uses to serve the files.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

