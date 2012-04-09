#!/usr/bin/env python2.7

# ---------------------------------------------------------------------------
# Copyright (c) 2012 Asim Ihsan (asim dot ihsan at gmail dot com)
# Distributed under the MIT/X11 software license, see the accompanying
# file license.txt or http://www.opensource.org/licenses/mit-license.php.
# ---------------------------------------------------------------------------

import os
import sys
import tempfile
import cStringIO as StringIO

src_path = os.path.abspath(os.path.join(__file__, os.pardir, os.pardir, "src"))
assert(os.path.isdir(src_path))
sys.path.append(src_path)
from utilities import crypto

from nose.tools import raises, assert_false, assert_true, assert_not_equal, assert_equal, assert_less
from nose.plugins.skip import SkipTest, Skip
_multiprocess_can_split_ = True

def test_encrypt_then_decrypt_string():
    plaintext = "this is some text"
    key = "this is my key"
    ciphertext = crypto.encrypt_string(plaintext, key)
    plaintext_after = crypto.decrypt_string(ciphertext, key)
    assert_equal(plaintext_after, plaintext)

@raises(crypto.HMACIsNotValidException)
def test_encrypt_then_alter_raises_exception():
    plaintext = "this is some text"
    key = "this is my key"
    ciphertext = crypto.encrypt_string(plaintext, key)
    ciphertext = ciphertext[:-len(plaintext)] + '\0' * len(plaintext)
    plaintext_after = crypto.decrypt_string(ciphertext, key)

@raises(crypto.InvalidFormatException)
def test_decrypt_then_damage_raises_exception():
    plaintext = "this is some text"
    key = "this is my key"
    ciphertext = crypto.encrypt_string(plaintext, key)
    ciphertext = ciphertext[:len(ciphertext)-5]
    plaintext_after = crypto.decrypt_string(ciphertext, key)

@raises(crypto.HMACIsNotValidException)
def test_decrypt_with_wrong_password_raises_exception():
    plaintext = "this is some text"
    key = "this is my key"
    ciphertext = crypto.encrypt_string(plaintext, key)
    another_key = "this is my key 2"
    plaintext_after = crypto.decrypt_string(ciphertext, another_key)

def test_encrypt_then_decrypt_empty_string():
    plaintext = ""
    key = "this is my key"
    ciphertext = crypto.encrypt_string(plaintext, key)
    plaintext_after = crypto.decrypt_string(ciphertext, key)
    assert_equal(plaintext_after, plaintext)

def test_compressed_encrypt_then_decrypt_string():
    plaintext = "X" * 4096
    key = "this is my key"
    ciphertext = crypto.encrypt_string(plaintext, key, compress=True)
    assert_less(len(ciphertext), len(plaintext) / 10)
    plaintext_after = crypto.decrypt_string(ciphertext, key)
    assert_equal(plaintext, plaintext_after)

def test_compressed_encrypt_then_decrypt_random_string():
    plaintext = os.urandom(1024 * 1024)
    key = "this is my key"
    ciphertext = crypto.encrypt_string(plaintext, key, compress=True)
    plaintext_after = crypto.decrypt_string(ciphertext, key)
    assert_equal(plaintext, plaintext_after)

def _test_encrypt_then_decrypt_file(plaintext_size,
                                    chunk_size,
                                    wrong_password=False,
                                    alter_file=False,
                                    truncate_header=False,
                                    truncate_body=False,
                                    compress=False):
    tempfile.tempdir = os.path.join(__file__, os.pardir)
    plaintext_file = tempfile.NamedTemporaryFile(delete=False)
    ciphertext_file = tempfile.NamedTemporaryFile(delete=False)
    plaintext_after_file = tempfile.NamedTemporaryFile(delete=False)
    plaintext_filepath = plaintext_file.name
    ciphertext_filepath = ciphertext_file.name
    plaintext_after_filepath = plaintext_after_file.name
    plaintext_file.close()
    ciphertext_file.close()
    plaintext_after_file.close()
    try:
        key = "this is my key"
        # --------------------------------------------------------------------
        #   Write plaintext to file.
        # --------------------------------------------------------------------
        with open(plaintext_filepath, "wb") as f:
            cnt = 0
            while cnt < plaintext_size:
                current_chunk_size = min(4096, plaintext_size - cnt)
                f.write("X" * current_chunk_size)
                cnt += current_chunk_size
        # --------------------------------------------------------------------

        # --------------------------------------------------------------------
        #   Encrypt plaintext file to ciphertext file.
        #
        #   Notice that the output, ciphertext file requires read and
        #   write access.
        # --------------------------------------------------------------------
        with open(plaintext_filepath, "rb") as f_in:
            with open(ciphertext_filepath, "rb+") as f_out:
                crypto.encrypt_file(f_in,
                                    key,
                                    f_out,
                                    chunk_size=chunk_size,
                                    compress=compress)
        # --------------------------------------------------------------------

        # --------------------------------------------------------------------
        #   If wrong password then let's adjust the password.
        # --------------------------------------------------------------------
        if wrong_password:
            key = "this is my key 2"
        # --------------------------------------------------------------------

        # --------------------------------------------------------------------
        #   If alter file then let's alter the file.
        #   If truncate_body then let's skip the last ten bytes from the
        #   file.
        #   If truncate_header then let's skip the first ten bytes from the
        #   file.
        # --------------------------------------------------------------------
        if alter_file:
            with open(ciphertext_filepath, "rb+") as f:
                f.seek(-10, os.SEEK_END)
                f.write('\0' * 10)
        if truncate_header or truncate_body:
            with open(ciphertext_filepath, "rb") as f:
                contents = f.read()
            if truncate_header:
                with open(ciphertext_filepath, "wb") as f:
                    f.write(contents[10:])
            else:
                with open(ciphertext_filepath, "wb") as f:
                    f.write(contents[:-10])
        # --------------------------------------------------------------------

        # --------------------------------------------------------------------
        #   Decrypt ciphertext file to another plaintext file.
        # --------------------------------------------------------------------
        with open(ciphertext_filepath, "rb") as f_in:
            with open(plaintext_after_filepath, "wb") as f_out:
                crypto.decrypt_file(f_in, key, f_out, chunk_size=chunk_size)
        # --------------------------------------------------------------------

        with open(plaintext_filepath, "rb") as f_original:
            with open(plaintext_after_filepath, "rb") as f_after:
                while True:
                    f_original_chunk = f_original.read(chunk_size)
                    f_after_chunk = f_after.read(chunk_size)
                    assert_equal(f_original_chunk, f_after_chunk)
                    if f_original_chunk == '':
                        break
    finally:
        for (file_obj, filepath) in [(plaintext_file, plaintext_filepath),
                                     (ciphertext_file, ciphertext_filepath),
                                     (plaintext_after_file, plaintext_after_filepath)]:
            os.remove(filepath)

def test_encrypt_then_decrypt_file_normal():
    _test_encrypt_then_decrypt_file(plaintext_size = 17,
                                    chunk_size = 4096)

def test_encrypt_then_decrypt_empty_file():
    _test_encrypt_then_decrypt_file(plaintext_size = 0,
                                    chunk_size = 4096)

def test_encrypt_then_decrypt_file_lower_boundary_1():
    _test_encrypt_then_decrypt_file(plaintext_size = 1,
                                    chunk_size = 1)

def test_encrypt_then_decrypt_file_lower_boundary_2():
    _test_encrypt_then_decrypt_file(plaintext_size = 100,
                                    chunk_size = 1)

def test_encrypt_then_decrypt_file_upper_boundary_1():
    _test_encrypt_then_decrypt_file(plaintext_size = 4096,
                                    chunk_size = 4096)

def test_encrypt_then_decrypt_file_upper_boundary_2():
    _test_encrypt_then_decrypt_file(plaintext_size = 4095,
                                    chunk_size = 4096)

def test_encrypt_then_decrypt_file_upper_boundary_3():
    _test_encrypt_then_decrypt_file(plaintext_size = 4097,
                                    chunk_size = 4096)

@raises(crypto.HMACIsNotValidException)
def test_decrypt_file_with_wrong_password_raises_exception():
    _test_encrypt_then_decrypt_file(plaintext_size = 4097,
                                    chunk_size = 4096,
                                    wrong_password=True)

@raises(crypto.HMACIsNotValidException)
def test_encrypt_then_alter_file_raises_exception():
    _test_encrypt_then_decrypt_file(plaintext_size = 4097,
                                    chunk_size = 4096,
                                    alter_file=True)

@raises(crypto.InvalidFormatException)
def test_encrypt_then_truncate_file_header_raises_exception():
    _test_encrypt_then_decrypt_file(plaintext_size = 4097,
                                    chunk_size = 4096,
                                    truncate_header=True)

@raises(crypto.InvalidFormatException)
def test_encrypt_then_truncate_file_body_raises_exception():
    _test_encrypt_then_decrypt_file(plaintext_size = 4097,
                                    chunk_size = 4096,
                                    truncate_body=True)

def test_encrypt_massive_file():
    _test_encrypt_then_decrypt_file(plaintext_size = 50 * 1024 * 1024,
                                    chunk_size = 4096)

# Want to test if 4GB+ files work, but skip in general.
def test_encrypt_massive_file_2():
    raise SkipTest
    _test_encrypt_then_decrypt_file(plaintext_size = 5 * 1024 * 1024 * 1024, # 5 GB
                                    chunk_size = 4096)

def test_compressed_encrypt_file():
    _test_encrypt_then_decrypt_file(plaintext_size = 4096,
                                    chunk_size = 4096,
                                    compress = True)

def test_compressed_encrypt_massive_file():
    _test_encrypt_then_decrypt_file(plaintext_size = 50 * 1024 * 1024,
                                    chunk_size = 4096,
                                    compress = True)

def test_ciphertext_not_repeated():
    plaintext = "this is some text"
    key = "this is my key"
    all_ciphertexts = [crypto.encrypt_string(plaintext, key) for i in xrange(100)]
    unique_ciphertexts = set(all_ciphertexts)
    assert_equal(len(unique_ciphertexts), len(all_ciphertexts))

def test_massive_encrypt_then_decrypt():
    plaintext = "X" * 50 * 1024 * 1024
    key = "this is my key"
    ciphertext = crypto.encrypt_string(plaintext, key)
    plaintext_after = crypto.decrypt_string(ciphertext, key)
    assert_equal(plaintext, plaintext_after)

