Components
==========

User Tools
++++++++++

:any:`tardis`
-------------
The client application which performs the backups

:any:`regenerate`
-----------------
A tool for recovering backed up files

:any:`lstardis`
---------------
A program to list which versions of files are available

:any:`tardiff`
-------------
A program to show differences between different backed up versions of files, and optionally the current version.

:any:`sonic`
------------
An administrative program

Tardis provides an additional method of regenerating files, namely through a file-system interface:
    * :any:`tardisfs`
        A FUSE (File System in User Space) filesystem which provides access to all functions.

In addition, the following two services run on servers which support Tardis.   Users will not typically interact with these.
    * :any:`tardisd`
        A server side daemon to receive the backup data from tardis.
    * :any:`tardisremote`
        An optional http server to serve backedup datab.

