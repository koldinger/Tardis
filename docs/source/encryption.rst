Encryption
==========

Backup sets can be optionally encrypted.  Tardis uses AES CBC with 256-bit keys.

All file names are also encrypted in the database, using the less secure AES EBC mode, also with 256-bit keys.

Separate, unrelated, keys are used for the filenames and the file data.

Keys
----
Keys are generated randomly when the database is created.
Keys are always stored encrypted, whether they are stored in the database, or in a 
The keys are encrypted with a key derived from the current password.  

Keys can be either stored in the database directly, or in a user controlled "key database" file.

Key Flow
--------

When you attempt to access the database, the password will be hashed using a "Password Based Key Deviration Function" (PBKDF), namely
`PBKDF2 <https://en.wikipedia.org/wiki/PBKDF2>`_.
This is used to generate two keys, one of which is used to generate the authentication token used to login, and the other of which generates the
encrypts the two keys.

Once the keys are generated, the token key is used to encrypt a string and pass it into the database for authentication.  When the server returns
the keys, the key key (the second of the two keys) is used to decrypt the two main keys, namely the filename key, and the contents key.

All key manipulation, and encryption/decryption is performed in the client apps.  At no time is any information sufficient to decrypt anything sent to the
server.

Filename Encryption
-------------------

File names are encrypted via AES 256 in ECB mode.  In general, ECB mode is less secure than the CBC mode used to encrypt the contents of the files.
ECB mode was used as it does not rely on a Nonce or Initialization vector.  This means that a name can be encrypted multiple times without having to somehow
know the initialization vector.

It may be possible to attack the file names.  However, attacking the file names does give access to the contents of the files, as the contents are encrypted with a separate,
unrelated key.  Both keys (content and filenmae) are generated randomly and encrypted.

Authentication
--------------

Encrypted files can be authenticated in two separate manners.   First, all files are named within the database by a hash of the data in the file.  If the backup is not encrypted, this is simply
the `MD5 <https://en.wikipedia.org/wiki/MD5>`_ hash of the data.  If the backup is encrypted, the `HMAC-MD5 <https://en.wikipedia.org/wiki/Hash-based_message_authentication_code>`_ of the same data is used.

When the backup is encrypted, the data format also includes a HMAC-SHA512 authentication code in each data file.

Unencrypted files can be mildly authenticated by checking that the MD5 hash of the file matches what's stored in the backup database.  This is open to attack, but is sufficient to determine if data is 
corrupted in transmission.
Encrypted files can be authenticated via both the overall HMAC-MD5 of the entire file, and the HMAC-SHA512 of each component file used to generate the complete file.

Data Format
-----------

Data files are encrypted and saved in the following format:
    * Bytes 0-15 contain the Initialization Vector used for this file.
    * Bytes 16-(length - 64) contain the data, padded per `PKCS7 <https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7>`_ and encrypted with AES-CBC 256.
    * The last 64 bytes of the file contain the HMAC-SHA512 of the encrypted data.

Notes
-----

Encryption is handled via the `pycryptodome <https://pypi.python.org/pypi/pycryptodome>`_ library.  pycryptodome supports the AES-NI instructions on processors which have them.  This can
result in a significant speedup.

Hashing is done via the standard hashlib and hmac libraries from Python.
