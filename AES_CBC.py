"""
AES CBC Mode Implementation

Author: Vlad Usatii @ gemcoin

Description: This is the implementation that I made for Cryptography I at Stanford MOOC. It is pure Python3 with no cryptography imports. The IV is prepended to the ciphertext.

"""
import sys, os, random
import binascii
from utils import *

class AES_CBC_MODE(object):
	rounds_by_key_size = {16: 10, 24: 12, 32: 14}
	def __init__(self, key: bytes, key_len=128):
		if len(key) == 16 and isinstance(key, bytes):
			self.key = key
		else:
			raise Exception("Key must be 16 random bytes.")

		if key_len in [128, 192, 256]:
			self.key_len = key_len
		else:
			raise Exception("Key length must be 128, 192, or 256 bits.")

		assert len(key) in AES_CBC_MODE.rounds_by_key_size, "Invalid key."

		self.n_rounds = AES_CBC_MODE.rounds_by_key_size[len(key)]
		self._key_matrices = self._expand_key(key)

	def _expand_key(self, key):
		cols = self.toMatrix(key)
		iter_size = len(key) // 4

		i = 1
		while len(cols) < (self.n_rounds + 1) * 4:
			word = list(cols[-1])

			# key scheduling
			if len(cols) % iter_size == 0:
				word.append(word.pop(0))
				word = [s_box[b] for b in word]
				word[0] ^= r_con[i]
				i += 1
			elif len(key) == 32 and len(cols) % iter_size == 4:
				# run the word through S-box in 4th iter with {0,1}^8 key
				word = [s_box[b] for b in word]

			word = xor_bytes(word, cols[-iter_size])
			cols.append(word)

		expansion = [cols[4*i : 4*(i+1)] for i in range(len(cols) // 4)]
		return expansion

	# checks if data has been inputted correctly before encryption.
	def prereqs(self, iv, data) -> bool:
		assert len(iv) == 16, "Must be an IV of length 16 bytes."
		assert isinstance(iv, bytes), "IV must be of type bytes."
		assert len(data) > 0, "Data can not be empty."
		assert isinstance(data, bytes), "Data must be of type bytes."

		return True

	# converts 16-byte arrays to a 4x4 matrix, or from a matrix to bytearray.
	def toMatrix(self, pt) -> list:
		return [list(pt[i:i+4]) for i in range(0, len(pt), 4)]
	def toBytes(self, matrix) -> bytes:
		return bytes(sum(matrix, []))

	# splits blocks before feeding them into rounds with round key
	def block_split(self, pt, block_size=16, pad=True):
		assert len(pt) % block_size == 0 or not pad, f"Your plaintext size: {len(pt)}"
		return [pt[i:i+16] for i in range(0, len(pt), block_size)]

	def encrypt_block(self, xored_bytes) -> bytes:
		assert len(xored_bytes) == 16, "This encryption function only supports split blocks."

		p_state = self.toMatrix(xored_bytes)
		add_round_key(p_state, self._key_matrices[0])

		for x in range(1, self.n_rounds):
			sub_bytes(p_state)
			shift_rows(p_state)
			mix_cols(p_state)
			add_round_key(p_state, self._key_matrices[x])

		sub_bytes(p_state)
		shift_rows(p_state)
		add_round_key(p_state, self._key_matrices[-1])
		return self.toBytes(p_state)

	def decrypt_block(self, ct):
		assert len(ct) == 16, "Ciphertext is of the wrong format."
		c_state = self.toMatrix(ct)

		add_round_key(c_state, self._key_matrices[-1])
		inv_shift_rows(c_state)
		inv_sub_bytes(c_state)

		for x in range(self.n_rounds - 1, 0, -1):
			add_round_key(c_state, self._key_matrices[x])
			inv_mix_cols(c_state)
			inv_shift_rows(c_state)
			inv_sub_bytes(c_state)

		add_round_key(c_state, self._key_matrices[0])
		return self.toBytes(c_state)

	def encrypt(self, data: bytes, iv: bytes) -> bytes:
		prereqs = self.prereqs(iv, data)
		if prereqs is not True: raise Exception("Data does not match prerequisites for encryption.")

		plaintext = pad_PKC55(data)
		blocks = []
		previous = iv
		for pt_block in self.block_split(plaintext):
			block = self.encrypt_block(xor_bytes(pt_block, previous))
			blocks.append(block)
			previous = block
		return b''.join(blocks)

	def decrypt(self, data: bytes, iv: bytes) -> bytes:
		assert len(iv) == 16, "Invalid IV length."

		blocks = []
		previous = iv
		for ct_block in self.block_split(data):
			blocks.append(xor_bytes(previous, self.decrypt_block(ct_block)))
			previous = ct_block
		return unpad_PKC55(b''.join(blocks))

	def encrypt_with_IV(self, data: bytes, iv: bytes) -> bytes:
		return b''.join([iv, self.encrypt(data, iv)])

	def decrypt_with_IV(self, data: bytes) -> bytes:
		iv = data[:16]
		ct = data[16:]
		return self.decrypt(ct, iv)

	def __repr__(self):
		return f'AES_CBC(key={self.key} , key_len=' + str(self.key_len) + ')'
