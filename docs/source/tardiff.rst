tardiff
=======
tardiff can show the differences between different versions of a file which exist in the database, and the current version.

.. code-block::

usage: tardiff [-h] [--database DATABASE] [--dbname DBNAME] [--client CLIENT]
               [--backup BACKUP [BACKUP ...]] [--password [PASSWORD] |
               --password-file PASSWORDFILE | --password-prog PASSWORDPROG]
               [--crypt] [--keys KEYS] [--color] [--unified [UNIFIED] |
               --context [CONTEXT] | --ndiff] [--reduce-path [N]] [--recurse]
               [--list] [--verbose] [--version]
               files [files ...]

Diff files in Tardis

positional arguments:
  files                 File to diff

optional arguments:
  -h, --help            show this help message and exit
  --database DATABASE, -D DATABASE
                        Path to database directory (Default: /nfs/blueberrypi)
  --dbname DBNAME, -N DBNAME
                        Name of the database file (Default: tardis.db)
  --client CLIENT, -C CLIENT
                        Client to process for (Default: linux.koldware.com)
  --backup BACKUP [BACKUP ...], -b BACKUP [BACKUP ...]
                        Backup set(s) to use (Default: ['Current'])
  --password [PASSWORD], -P [PASSWORD]
                        Encrypt files with this password
  --password-file PASSWORDFILE, -F PASSWORDFILE
                        Read password from file. Can be a URL (HTTP/HTTPS or
                        FTP)
  --password-prog PASSWORDPROG
                        Use the specified command to generate the password on
                        stdout
  --[no]crypt           Are files encrypted, if password is specified.
                        Default: True
  --keys KEYS           Load keys from file.
  --[no]color           Use colors
  --unified [UNIFIED], -u [UNIFIED]
                        Generate unified diff
  --context [CONTEXT], -c [CONTEXT]
                        Generate context diff
  --ndiff, -n           Generate NDiff style diff
  --reduce-path [N], -R [N]
                        Reduce path by N directories. No value for "smart"
                        reduction
  --[no]recurse         Recurse into directories. Default: False
  --[no]list            Only list files that differ. Do not show diffs.
                        Default: False
  --verbose, -v         Increase the verbosity
  --version             Show the version
