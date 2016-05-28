Sonic
=====

Sonic is the swiss army knife tool to perform many configuration options on a database.

create
------

Creates a new backup client in the database, and optionally sets a password.  
MUST be run on the backup server.

setpass
-------
Adds a password to the backup client.  Only works with backup clients that do not have a password currently.
Note, you should not run this on any backup clients for which data is already saved.  It can leave the database in an awkward state.

chpass
------
Change the password on a given database.

keys
----

Manipulate the encryption keys, either extracting them from, or insterting them into the backup server.


list
----

Lists the backupsets that exist in the database.


info
----
[Deprecated]
Prints info about each set in the database.  Can be very slow.

purge
-----

Purges out old backup sets, according to a specified schedule.

orphans
-------

Removes any "orphaned" files, ie those that are not currently in use anywhere in any backup sets.

getconfig
---------
Prints the contents of configuration variables stored in the database.

setconfig
---------
Allows setting configuration values in the database.
