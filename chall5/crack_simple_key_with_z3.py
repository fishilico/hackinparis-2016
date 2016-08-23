#!/usr/bin/env python2
import z3

# Initialize unknown key
key = z3.BitVec('K', 0x18 * 8)
BYTE_key = [z3.Extract(i + 7, i, key) for i in range(0, key.size(), 8)]

# Translate decryptSimple() instruction to z3 equations
s = z3.Solver()
s.add(BYTE_key[0x15] ^ BYTE_key[0x16] == BYTE_key[0x17] + 0x1D)
s.add(BYTE_key[0x14] ^ BYTE_key[0x15] == BYTE_key[0x16] - 0x69)
s.add(BYTE_key[0x13] ^ BYTE_key[0x14] == BYTE_key[0x15] - 0x69)
s.add(BYTE_key[0x12] ^ BYTE_key[0x13] == BYTE_key[0x14] - 0x0C)
s.add(BYTE_key[0x11] ^ BYTE_key[0x12] == BYTE_key[0x13] + 4)
s.add(BYTE_key[0x10] ^ BYTE_key[0x11] == BYTE_key[0x12] - 0x27)
s.add(BYTE_key[0x0F] ^ BYTE_key[0x10] == BYTE_key[0x11] - 0x18)
s.add(BYTE_key[0x0E] ^ BYTE_key[0x0F] == BYTE_key[0x10] - 0x4E)
s.add(BYTE_key[0x0D] ^ BYTE_key[0x0E] == BYTE_key[0x0F] - 0x48)
s.add(BYTE_key[0x0C] ^ BYTE_key[0x0D] == BYTE_key[0x0E] - 0x73)
s.add(BYTE_key[0x0B] ^ BYTE_key[0x0C] == BYTE_key[0x0D] - 0x2A)
s.add(BYTE_key[0x0A] ^ BYTE_key[0x0B] == BYTE_key[0x0C] - 0x60)
s.add(BYTE_key[0x09] ^ BYTE_key[0x0A] == BYTE_key[0x0B] - 0x1D)
s.add(BYTE_key[0x08] ^ BYTE_key[0x09] == BYTE_key[0x0A] - 0x52)
s.add(BYTE_key[0x07] ^ BYTE_key[0x08] == BYTE_key[0x09] - 6)
s.add(BYTE_key[0x06] ^ BYTE_key[0x07] == BYTE_key[0x08])
s.add(BYTE_key[0x05] ^ BYTE_key[0x06] == BYTE_key[0x07] - 0x0F)
s.add(BYTE_key[0x04] ^ BYTE_key[0x05] == BYTE_key[0x06] - 0x47)
s.add(BYTE_key[0x03] ^ BYTE_key[0x04] == BYTE_key[0x05] - 0x74)
s.add(BYTE_key[0x02] ^ BYTE_key[0x03] == BYTE_key[0x04] - 0x6F)
s.add(BYTE_key[0x01] ^ BYTE_key[0x02] == BYTE_key[0x03] - 0x10)
s.add(BYTE_key[0x00] ^ BYTE_key[0x01] == BYTE_key[0x02] + 0x0A)
s.add(BYTE_key[0x01] + BYTE_key[0x00] == 0x76)
s.add(BYTE_key[0x00] == 0x46)

# Find all solutions
while s.check() == z3.sat:
    m = s.model()
    keyval = m[key].as_long()
    s.add(key != keyval)
    keybytes = b''.join([chr((keyval >> i) & 0xff) for i in range(0, key.size(), 8)])
    print(repr(keybytes))
