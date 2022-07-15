# AES CTR

To use AES CTR in your protocol, I've written the most basic code possible to show that ```pt(K, n_j) = D(IV, E(pt, IV))```:

```python3
import sys, os
from AES_CTR import *

key, iv = os.urandom(16), os.urandom(16)
a = AES_CTR_MODE(key)

msg = b'This is a test message.'

# TWO ENCRYPTION OPTIONS, BASED ON PROTOCOL

# (1) Prepend the IV to the message
ct = a.encrypt_with_IV(msg, iv)

# (2) Encrypt with assumption that the decryptor knows the IV
ct = a.encrypt(msg, iv)

# To output ciphertext in hex
import binascii
ct_hex = binascii.hexlify(ct)

# To output ciphertext back in bytes
ct     = binascii.unhexlify(ct_hex.encode('utf-8'))

# TWO DECRYPTION OPTIONS, BASED ON PROTOCOL

# (1) Slice out the IV and decode the message
pt = a.decrypt_with_IV(ct)

# (2) Assume that the node knows the IV
pt = a.decrypt(ct, iv)
```
