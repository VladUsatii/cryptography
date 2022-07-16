#!/usr/bin/env python3
import sys, os
"""
TESTING AES CBC MODE
"""
from AES_CBC import *

key, iv = os.urandom(16), os.urandom(16)
a = AES_CBC_MODE(key)
msg = b'This is some filler text and I am making sure that my cipher can handle big messages.'
b = a.encrypt_with_IV(msg, iv)
c = a.decrypt_with_IV(b)
del (key, iv, a, b, c)

"""
TESTING AES CTR MODE
"""
from AES_CTR import *

key, iv = os.urandom(16), os.urandom(16)
a = AES_CTR_MODE(key)
msg = b'This is some more filler that I have added.'
b = a.encrytp_with_IV(msg, iv)
c = a.decrypt_with_IV(b)
del (key, iv, a, b, c)

"""
COURSERA STUFF

CBC DECODING PROMPTS (1-2)
CTR DECODING PROMPTS (3-4)
"""

# MESSAGE 1

key = binascii.unhexlify("140b41b22a29beb4061bda66b6747e14".encode('utf-8'))
ct  = binascii.unhexlify("4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81".encode('utf-8'))
a = AES_CBC_MODE(key)
print(a.decrypt_with_IV(ct))
del (key, ct, a)

# MESSAGE 2

key = binascii.unhexlify("140b41b22a29beb4061bda66b6747e14".encode('utf-8'))
ct  = binascii.unhexlify("5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253".encode('utf-8'))
a = AES_CBC_MODE(key)
print(a.decrypt_with_IV(ct))
del (key, ct, a)

# MESSAGE 3

key = binascii.unhexlify("36f18357be4dbd77f050515c73fcf9f2".encode('utf-8'))
ct  = binascii.unhexlify("69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329".encode('utf-8'))
a = AES_CTR_MODE(key)
print(a.decrypt_with_IV(ct))
del (key, ct, a)

# MESSAGE 4

key = binascii.unhexlify("36f18357be4dbd77f050515c73fcf9f2".encode('utf-8'))
ct  = binascii.unhexlify("770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451".encode('utf-8'))
a = AES_CTR_MODE(key)
print(a.decrypt_with_IV(ct))
del (key, ct, a)

