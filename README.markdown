Cryptography example
==============================

How to "do encryption" using cryptographic primitives. Inspired by [Cryptographic Right Answers](http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html) by Colin Percival.

Requirements and Installation
-----------------------------

-   You need Python 2.x, and this is cross-platform, i.e. works on Windows, Max OS X, and Linux.
-   You will require [PyCrypto](https://www.dlitz.net/software/pycrypto/). If you're on Windows, [here are the binaries](http://www.voidspace.org.uk/python/modules.shtml).
-   If you want to run the tests (recommended) you need [nose](http://readthedocs.org/docs/nose/en/latest/). You can install nose via [pip](http://www.pip-installer.org/en/latest/index.html).  In order to install both pip and nose one could, for example, run (with cygwin on Windows):

        curl http://python-distribute.org/distribute_setup.py | python
        curl https://raw.github.com/pypa/pip/master/contrib/get-pip.py | python
        pip install nose

Quick start
-----------

```py
>>> from utilities import crypto
>>> plaintext = "this is some text"
>>> key = "this is my key"
>>> ciphertext = crypto.encrypt_string(plaintext, key)
>>> plaintext_after = crypto.decrypt_string(ciphertext, key)
>>> print plaintext_after
this is some text
```

What happens if someone alters the encrypted string? You'll get one of two exceptions:

```py
>>> ciphertext_altered = ciphertext[:-1] + '\0'
>>> plaintext_after = crypto.decrypt_string(ciphertext_altered, key)
Traceback (most recent call last):
  File "<pyshell#14>", line 1, in <module>
    plaintext_after = crypto.decrypt_string(ciphertext_altered, key)
  File ".\utilities\crypto.py", line 76, in decrypt_string
    decrypt_file(ciphertext_obj, key, plaintext_obj)
  File ".\utilities\crypto.py", line 172, in decrypt_file
    raise HMACIsNotValidException
HMACIsNotValidException
```

or:

```py
>>> ciphertext_truncated = ciphertext[:-5]
>>> plaintext_after = crypto.decrypt_string(ciphertext_truncated, key)
Traceback (most recent call last):
  File "<pyshell#16>", line 1, in <module>
    plaintext_after = crypto.decrypt_string(ciphertext_truncated, key)
  File ".\utilities\crypto.py", line 76, in decrypt_string
    decrypt_file(ciphertext_obj, key, plaintext_obj)
  File ".\utilities\crypto.py", line 168, in decrypt_file
    raise InvalidFormatException("len(hmac) %s != hmac_size %s" % (len(hmac), hmac_size))
InvalidFormatException: 'len(hmac) 27 != hmac_size 32'
```

You can do streaming symmetric encryption and decryption of files, such that very large files do not get fully loaded into memory:

```py
>>> plaintext_filepath = "c:\file1.txt"
>>> ciphertext_filepath = "C:\file2.txt"
>>> key = "my little key"
... with open(plaintext_filepath, "rb") as f_in:
...     with open(ciphertext_filepath, "rb+") as f_out:
...         crypto.encrypt_file(f_in,
...                             key,
...                             f_out)
>>> plaintext_after_filepath = "c:\file3.txt"
>>> with open(ciphertext_filepath, "rb") as f_in:
...     with open(plaintext_after_filepath, "wb") as f_out:
...               crypto.decrypt_file(f_in,
...                                   key,
...                                   f_out)
```

And by adding a compress flag you can compress plaintext before encryption for both strings and files:

```py
>>> plaintext = "X" * 1024 * 1024
>>> key = "my little key"
>>> ciphertext = crypto.encrypt_string(plaintext, key, compress=True)
>>> print len(ciphertext)
141
```

Features
--------

Design
------

As stated in [Cryptographic Right Answers](http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html):

-   Encrypting data: Use AES in CTR (Counter) mode, and append an HMAC.
-   AES key length: Use 256-bit AES keys.
-   Hash / HMAC algorithm: Use SHA256 / HMAC-SHA256.
-   Password handling: As soon as you receive a password, hash it using scrpt or PBKDF2 and erase the plaintext password from memory.

Following from this, the process for encrypting a file is:

and the process for decrypting a file:

the file format of an encrypted file is:

API
---

Development notes
-----------------

-   While developing I like installing [watchdog](https://github.com/gorakhargosh/watchdog) and then using the following command from the root of the git repo to auto-rerun the nose unit tests:

        I:\Programming\crypto_example>watchmedo shell-command --patterns="*.py" --recursive --command="nosetests --no-skip --detailed-errors --stop --verbosity=2 --test test/"

TODO
----

-   Make a unit-tested example in iOS.
-   Make a unit-tested example in Android.
-   Using Android emulators / iOS simulators / web server magic, run functional verification on the lot to prove each can talk to the other.

