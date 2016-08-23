#!/usr/bin/env python2
import z3

# Read file2's encrypted data
with open('file2', 'rb') as f:
    data = f.read()
assert data[:0xb] == b'Keep me too'
data = data[0xb:]

# Define the set of valid bytes in the base64 cleartext file
VALID_BYTES = frozenset(
    [ord(x) for x in '\r\n/+='] +
    list(range(ord('0'), ord('9') + 1)) +
    list(range(ord('A'), ord('Z') + 1)) +
    list(range(ord('a'), ord('z') + 1)))


# Define the two crypt() results as unknown variables with conditions
def z3_crypt_b64(val):
    """Return a z3 expression of val being a base64 character from crypt()"""
    return z3.Or(
        z3.And(ord('0') <= val, val <= ord('9')),
        z3.And(ord('A') <= val, val <= ord('Z')),
        z3.And(ord('a') <= val, val <= ord('z')),
        val == ord('.'),
        val == ord('/'))


s = z3.Solver()
hash_alg1 = z3.BitVec('hash1', 8 * 22)
for i in range(0, hash_alg1.size(), 8):
    s.add(z3_crypt_b64(z3.Extract(i + 7, i, hash_alg1)))
hash_alg6 = z3.BitVec('alg6', 8 * 86)
for i in range(0, hash_alg6.size(), 8):
    s.add(z3_crypt_b64(z3.Extract(i + 7, i, hash_alg6)))

# key = hash_alg1 ^ hash_alg6, with cycles (946 is the least common multiple of 22 and 86)
key = z3.BitVec('key', 8 * 946)
for i in range(key.size() // 8):
    i_alg1 = i % 22
    alg1_char = z3.Extract(8 * i_alg1 + 7, 8 * i_alg1, hash_alg1)
    i_alg6 = i % 86
    alg6_char = z3.Extract(8 * i_alg6 + 7, 8 * i_alg6, hash_alg6)
    s.add(z3.Extract(8 * i + 7, 8 * i, key) == alg1_char ^ alg6_char)

# Find available bytes for each byte of the key
for bytepos in range(key.size() // 8):
    selectedbytes = frozenset([ord(data[off]) for off in range(bytepos, len(data), 946)])
    avail_keys = set()
    for k in range(256):
        if all(sb ^ k in VALID_BYTES for sb in selectedbytes):
            avail_keys.add(k)
    assert len(avail_keys) > 0
    keybyte = z3.Extract(8 * bytepos + 7, 8 * bytepos, key)
    s.add(z3.Or([keybyte == x for x in avail_keys]))

# Crack the key
while s.check() == z3.sat:
    m = s.model()
    hash1 = m[hash_alg1].as_long()
    hash6 = m[hash_alg6].as_long()
    s.add(hash_alg1 != hash1)
    hash1bytes = b''.join([chr((hash1 >> i) & 0xff) for i in range(0, hash_alg1.size(), 8)])
    hash6bytes = b''.join([chr((hash6 >> i) & 0xff) for i in range(0, hash_alg6.size(), 8)])
    print("Hash $1$: {}".format(hash1bytes.decode('ascii')))
    print("Hash $6$: {}".format(hash6bytes.decode('ascii')))

    # Decrypt the file
    keyval = m[key].as_long()
    s.add(key != keyval)
    keybytes = [(keyval >> i) & 0xff for i in range(0, key.size(), 8)]
    clearbytes = bytearray(len(data))
    for i in range(len(data)):
        clearbytes[i] = ord(data[i]) ^ keybytes[i % 946]
    with open('file2_decrypted.out.b64', 'wb') as f:
        f.write(clearbytes)
