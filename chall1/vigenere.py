#!/usr/bin/env python3

# Encrypted data from the PNG image
TEXT = b'ixeas://yddotyprujw.nzm/udue/nsaco2016/ef7118o5-p1au-49g0-84f7-3850h4n21210.mie'

# Begin of the clear text
BEGIN = b'httpshackinpariscom'

STRIPPEDTEXT = [c for c in TEXT if ord('a') <= c <= ord('z')]
KEY = [(STRIPPEDTEXT[i] - BEGIN[i] + 26) % 26 for i in range(len(BEGIN))]

# Show key: bellardbellardbella -> bellard
print('Key is: ' + ''.join(chr(ord('a') + k) for k in KEY))

KEY = KEY[:len('bellard')]

decrypted = []
pos = 0
for c in TEXT:
    if ord('a') <= c <= ord('z'):
        d = ((c - ord('a') - KEY[pos % len(KEY)] + 260) % 26) + ord('a')
        pos += 1
    else:
        d = c
    decrypted.append(d)
print('decrypted: ' + ''.join(chr(x) for x in decrypted))
