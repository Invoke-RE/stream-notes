#!/usr/bin/env python3

import struct
import zlib
import json
import sys
import re
from binaryninja.types import SymbolType
from binaryninja.enums import SymbolBinding 
from binaryninja import BinaryViewType
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
"""
This function decrypts data using AES-256 in CBC mode where the key is derived using SHA256 and a hard-coded strings
"""
def decrypt_aes(aes_key_data, iv_xor_ct_data):
    h = SHA256.new()
    h.update(aes_key_data)
    aes256key = h.digest()
    print("AES256 Key: {}".format(aes256key))

    cipher = AES.new(aes256key, AES.MODE_CBC, iv_xor_ct_data[:16])
    xor_key_ct = iv_xor_ct_data[16:]
    xor_key = unpad(cipher.decrypt(xor_key_ct), AES.block_size)
    return xor_key

def xor_byte_data(data, key):
    rbytes = bytes()
    for i, b in enumerate(data):
        rbytes += (b ^ key[i % len(key)]).to_bytes(1, byteorder='little')
    return rbytes

def print_str_from_table(rstr):
    print(rstr.split(b'\x00')[0])

if __name__ == '__main__':
    bin_path = sys.argv[1]
    bv = BinaryViewType['PE'].open(bin_path)
    bv.update_analysis_and_wait()
    ct = bv.read(0x1800288b0, 0x165b)
    iv_xor_ct_data = bv.read(0x180028730, 0xc0)
    aes_key_data = bv.read(0x180028800, 0xa7)
    xor_key = decrypt_aes(aes_key_data, iv_xor_ct_data)
    dec_str_offset = 0x113a
    dec_str_len = 0x5ab
    decrypted_str_table = xor_byte_data(ct, xor_key)
    print_str_from_table(decrypted_str_table[dec_str_offset:dec_str_offset+dec_str_len])
	
