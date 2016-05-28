lstardis
========
The contents of a Tardis backup set can be read via the lstardis application.  lstardis is similar in many ways to a standard ls, except that in addition to listing
any files, it lists backupsets where the files exist.

<pre>
usage: lstardis [-h] [--database DATABASE] [--client CLIENT] [--long]
                [--hidden] [--reverse] [--annotate] [--size] [--human]
                [--dirinfo] [--checksums] [--chainlen] [--inode] [--versions]
                [--all] [--deletions] [--times] [--headers] [--colors]
                [--columns COLUMNS] [--dbname DBNAME] [--recurse]
                [--maxdepth MAXDEPTH] [--recent] [--glob] [--reduce [REDUCE]]
                [--realpath] [--range RANGE | --dates DATERANGE]
                [--password [PASSWORD] | --password-file PASSWORDFILE |
                --password-prog PASSWORDPROG] [--crypt] [--keys KEYS]
                [--version]
                [directories [directories ...]]

List Tardis File Versions

positional arguments:
  directories           List of directories/files to list

optional arguments:
  -h, --help            show this help message and exit
  --database DATABASE, -D DATABASE
                        Database to use. Default: /nfs/blueberrypi
  --client CLIENT, -C CLIENT
                        Client to list on. Default: linux.koldware.com
  --long, -l            Use long listing format.
  --hidden, -a          Show hidden files.
  --reverse, -r         Reverse the sort order
  --annotate, -f        Annotate files based on type.
  --size, -s            Show file sizes
  --human, -H           Format sizes for easy reading
  --dirinfo, -d         Maxdepth to recurse directories. 0 for none
  --checksums, -c       Print checksums.
  --chainlen, -L        Print chainlengths.
  --inode, -i           Print inode numbers
  --[no]versions        Display versions of files. Default: True
  --all                 Show all versions of a file. Default: False
  --[no]deletions       Show deletions. Default: True
  --[no]times           Use file time changes when determining diffs. Default:
                        False
  --[no]headers         Show headers. Default: True
  --[no]colors          Use colors. Default: False
  --columns COLUMNS     Number of columns to display
  --dbname DBNAME       Name of the database file. Default: tardis.db
  --recurse, -R         List Directories Recurively
  --maxdepth MAXDEPTH   Maximum depth to recurse directories
  --[no]recent          Show only the most recent version of a file. Default:
                        False
  --[no]glob            Glob filenames
  --reduce [REDUCE]     Reduce paths by N directories. No value for smart
                        reduction
  --[no]realpath        Use the full path, expanding symlinks to their actual
                        path components
  --range RANGE         Use a range of backupsets. Format: 'Start:End' Start
                        and End can be names or backupset numbers. Either
                        value can be left off to indicate the first or last
                        set respectively
  --dates DATERANGE     Use a range of dates for the backupsets. Format:
                        'Start:End'. Start and End are names which can be
                        intepreted liberally. Either can be left off to
                        indicate the first or last set respectively
  --version             Show the version

Password/Encryption specification options:
  --password [PASSWORD], -P [PASSWORD]
                        Encrypt files with this password
  --password-file PASSWORDFILE, -F PASSWORDFILE
                        Read password from file. Can be a URL (HTTP/HTTPS or
                        FTP)
  --password-prog PASSWORDPROG
                        Use the specified command to generate the password on
                        stdout
  --[no]crypt           Encrypt data. Only valid if password is set
  --keys KEYS           Load keys from file.
</pre>
