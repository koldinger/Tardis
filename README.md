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

1: Saving of extended attributes
2: Encrypted archives
3: SSL encrypted transport
4: rdiff based file storage (necessary for 2)
5: user authentication capability
6: Python EGG setup.
7: Better daemon support.
8: LSB init script (systemctl support)?

Tardis relies on the bson and xattrs packages.
