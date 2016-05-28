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
.. link:: PBKDF2 <https://en.wikipedia.org/wiki/PBKDF2>
This is used to generate two keys, one of which is used to generate the authentication token used to login, and the other of which generates the
encrypts the two keys.

Once the keys are generated, the token key is used to encrypt a string and pass it into the database for authentication.  When the server returns
the keys, the key key (the second of the two keys) is used to decrypt the two main keys, namely the filename key, and the contents key.

Notes
-----
