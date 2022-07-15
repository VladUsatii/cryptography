"""
AES CTR Mode Implementation

Author: Vlad Usatii @ gemcoin

Description: This is the implementation that I made for Cryptography I at Stanford MOOC. It is pure Python3 with no cryptography imports. The IV is prepended to the ciphertext.

"""
import sys, os, random
import binascii
from utils import *
from AES_CBC import AES_CBC_MODE # the CTR mode is basically CBC but with an incremental nonce/ XOR

def inc_bytes(a) -> bytes:
	op = list(a)
	for x in reversed(range(len(op))):
		if op[x] == 0xFF:
			op[x] = 0
		else:
			op[x] += 1
			break
	return bytes(op) # increments by 1

class AES_CTR_MODE(object):
	def __init__(self, key: bytes):
		self.a = AES_CBC_MODE(key)

	def encrypt(self, pt: bytes, iv: bytes) -> bytes:
		assert len(iv) == 16, "Incorrect IV length."

		blocks = []
		nonce = iv
		for pt_block in self.a.block_split(pt, pad=False):
			block = xor_bytes(pt_block, self.a.encrypt_block(nonce))
			blocks.append(block)
			nonce = inc_bytes(nonce)

		return b''.join(blocks)

	def decrypt(self, ct: bytes, iv: bytes) -> bytes:
		assert len(iv) == 16, "Incorrect IV length."

		blocks = []
		nonce = iv
		for ct_block in self.a.block_split(ct, pad=False):
			block = xor_bytes(ct_block, self.a.encrypt_block(nonce))
			blocks.append(block)
			nonce = inc_bytes(nonce)
		return b''.join(blocks)

	def encrypt_with_IV(self, data: bytes, iv: bytes) -> bytes:
		return b''.join([iv, self.encrypt(data, iv)])

	def decrypt_with_IV(self, data: bytes) -> bytes:
		return self.decrypt(data[16:], data[:16])
