Installation
============
Installing  up the server is relatively straightforward.
  * Install librsync, python fuse, and python development
      * Fedora: yum install librsync libacl-devel libffi-devel python-devel python-fuse python-setuptools gmp
      * Ubuntu/Debian: apt-get install librsync1 libacl1-dev libffi-dev python-dev python-fuse libcurl4-openssl-dev python-setuptools gmp
  * Run the python setup:
    * python setup.py install
