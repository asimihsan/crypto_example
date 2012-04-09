Symmetric cryptography example
==============================

How to "do encryption" using cryptographic primitives. Inspired by `cryptographic right answers`_ by Colin Percival.

Quick start
-----------

Features
--------

Design
------

As stated in `cryptographic right answers`_:

-   Encrypting data: Use AES in CTR (Counter) mode, and append an HMAC.
-   AES key length: Use 256-bit AES keys.
-   Hash / HMAC algorithm: Use SHA256 / HMAC-SHA256.
-   Password handling: As soon as you receive a password, hash it using scrpt or PBKDF2 and erase the plaintext password from memory.

Following from this, the process for encrypting a file is:

and the process for decrypting a file:

the file format of an encrypted file is:

API
---

TODO
----

-   Make a unit-tested example in iOS.
-   Make a unit-tested example in Android.
-   Using Android emulators / iOS simulators / web server magic, run functional verification on the lot to prove each can talk to the other.

.. links:
.. _cryptographic right answers: http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html
