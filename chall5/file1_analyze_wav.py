#!/usr/bin/env python3
import struct

with open('file1_video_payload.out', 'rb') as f:
    # skip header and footer
    WAVDATA = f.read()[44:0x69ed48]

# Extract message
for i in range(576, len(WAVDATA), 46907):
    sample = struct.unpack('b', WAVDATA[i:i+1])[0]
    if sample < 0:
        break
    print(chr(sample), end='')
print('')
