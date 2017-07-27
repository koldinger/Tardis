Installation
============
Installing  up the server is relatively straightforward.
  * Install librsync, python fuse, and python development
    * Fedora: ``{yum|dnf} install librsync libacl-devel libffi-devel python-devel python-fuse python-setuptools gmp snappy-devel openssl-devel``
    * Ubuntu/Debian: ``apt-get install librsync1 libacl1-dev libffi-dev python-dev python-fuse libcurl4-openssl-dev python-setuptools libgmp3-dev libsnappy-dev``
  * Run the python setup:
    * ``python setup.py install``

This will install the client, tardisd (the backup daemon), tardisremote (the remote access recovery server), and all the command line tools.  It will install
initialization scripts for tardisd, and tardisremote, but they won't be enabled.
