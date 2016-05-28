Regenerate
==========
The regenerate application recovers versions of files from the backups.

Note, you can also use the :any:`tardisfs` file system to make data avaible in a file system like view.

<pre>
usage: regenerate [-h] [--output OUTPUT] [--checksum] [--database DATABASE]
                  [--dbname DBNAME] [--client CLIENT]
                  [--backup BACKUP | --date DATE | --last]
                  [--password [PASSWORD] | --password-file PASSWORDFILE |
                  --password-prog PASSWORDPROG] [--crypt] [--keys KEYS]
                  [--recurse] [--authenticate]
                  [--authfail-action {keep,rename,delete}] [--reduce-path [N]]
                  [--set-times] [--set-perms] [--set-attrs] [--set-acl]
                  [--overwrite [{always,newer,older,never}]] [--hardlinks]
                  [--verbose] [--version]
                  files [files ...]

Regenerate a Tardis backed file

positional arguments:
  files                 List of files to regenerate

optional arguments:
  -h, --help            show this help message and exit
  --output OUTPUT, -o OUTPUT
                        Output file
  --checksum, -c        Use checksum instead of filename
  --database DATABASE, -D DATABASE
                        Path to database directory (Default: /nfs/blueberrypi)
  --dbname DBNAME, -N DBNAME
                        Name of the database file (Default: tardis.db)
  --client CLIENT, -C CLIENT
                        Client to process for (Default: linux.koldware.com)
  --backup BACKUP, -b BACKUP
                        Backup set to use
  --date DATE, -d DATE  Regenerate as of date
  --last, -l            Regenerate the most recent version of the file
  --password [PASSWORD], -P [PASSWORD]
                        Encrypt files with this password
  --password-file PASSWORDFILE, -F PASSWORDFILE
                        Read password from file. Can be a URL (HTTP/HTTPS or
                        FTP)
  --password-prog PASSWORDPROG
                        Use the specified command to generate the password on
                        stdout
  --[no]crypt           Are files encyrpted, if password is specified.
                        Default: True
  --keys KEYS           Load keys from file.
  --[no]recurse         Recurse directory trees. Default: True
  --[no]authenticate    Authenticate files while regenerating them. Default:
                        True
  --authfail-action {keep,rename,delete}
                        Action to take for files that do not authenticate.
                        Default: rename
  --reduce-path [N], -R [N]
                        Reduce path by N directories. No value for "smart"
                        reduction
  --[no]set-times       Set file times to match original file. Default: True
  --[no]set-perms       Set file owner and permisions to match original file.
                        Default: True
  --[no]set-attrs       Set file extended attributes to match original file.
                        May only set attributes in user space. Default: True
  --[no]set-acl         Set file access control lists to match the original
                        file. Default: True
  --overwrite [{always,newer,older,never}], -O [{always,newer,older,never}]
                        Mode for handling existing files. Default: never
  --[no]hardlinks       Create hardlinks of multiple copies of same inode
                        created. Default: True
  --verbose, -v         Increase the verbosity
  --version             Show the version
</pre>
