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

