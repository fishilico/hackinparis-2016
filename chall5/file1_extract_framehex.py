#!/usr/bin/env python3
"""Extract the file from the hexdump which is in file1 video"""
from PIL import Image, ImageDraw
import numpy


# Loads the images of the 16 hexadecimal digits
hexchardata = [None] * 16

for i in range(16):
    im = Image.open('file1-frames/frame%05d.png' % (i+1))
    im2 = im.crop((41 + 2 * 18, 780, 41 + (2+1) * 18, 804))
    draw = ImageDraw.Draw(im2)
    hexchardata[i] = numpy.array([(r + g + b) / 3. for r, g, b in im2.getdata()])


def ocr_hexdigit(chardata):
    """Return the digits which is the closest to the character image data"""
    mind = None
    minc = None
    for c in range(16):
        dist = sum(abs(chardata - hexchardata[c]))
        if mind is None or dist < mind:
            minc = c
            mind = dist
    return minc

with open('file1_framehex.out', 'wb') as fout:
    for iframe in range(1009):
        im = Image.open('file1-frames/frame%05d.png' % (iframe+1))
        # char width 18, height 23, 60 cols: 4 hexdigits, 1 ":", 8 spaces, 16*3-1 chars
        # Read the address (4 hex digits)
        addr = 0
        for col in range(4):
            im2 = im.crop((41 + col * 18, 780, 41 + (col+1) * 18, 804))
            chardata = numpy.array([(r + g + b) / 3. for r, g, b in im2.getdata()])
            addr += ocr_hexdigit(chardata) << (4*(3-col))
        assert addr == iframe * 16, "wrong address"

        # Read the 16 bytes of data of the frame
        hexdigits = bytearray(16)
        for col in range(16):
            xpos = 41 + (3 * col + 13) * 18
            im2 = im.crop((xpos, 780, xpos + 18, 804))
            chardata = numpy.array([(r + g + b) / 3. for r, g, b in im2.getdata()])
            curbyte = ocr_hexdigit(chardata) * 16

            xpos += 18
            im2 = im.crop((xpos, 780, xpos + 18, 804))
            chardata = numpy.array([(r + g + b) / 3. for r, g, b in im2.getdata()])
            curbyte += ocr_hexdigit(chardata)

            hexdigits[col] = curbyte

        fout.write(hexdigits)
