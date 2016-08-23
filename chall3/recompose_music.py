#!/usr/bin/env python3
"""Recompose the music to find out what are the differences"""
import math
import struct
import os.path
import subprocess
import tempfile

# CHIP16 ROM
with open(os.path.join(os.path.dirname(__file__), 'output.c16'), 'rb') as f:
    DATA = f.read()
ROM = DATA[16:]
assert len(ROM) == 0x22ce

SOUND = ROM[0x0f52:0x1c8e]
assert len(SOUND) == 4*847

# Decode data
MUSIC_FROM_ROM = [struct.unpack('<HH', SOUND[i:i+4]) for i in range(0, len(SOUND), 4)]

# Create a pitch2note array
NOTE_MAP = ('A', 'Bb', 'B', 'C', 'C#', 'D', 'Eb', 'E', 'F', 'F#', 'G', 'G#')


def pitch2note(p):
    if p < 1:
        return '-'
    delta_A4 = round(12. * math.log2(p/440))
    assert delta_A4 > -48
    range_id = (delta_A4 + 12*4) // 12
    pos = (delta_A4 + 12*4) % 12
    # a range is from C to B, not starting A
    if pos >= 3:
        range_id += 1
    note = NOTE_MAP[pos]
    return note + str(range_id)


def chord2pitch(c):
    # split number
    assert len(c) in (2, 3)
    assert c[:-1] in NOTE_MAP
    pos = NOTE_MAP.index(c[:-1])
    range_id = int(c[-1:])
    if pos >= 3:
        range_id -= 1
    delta_A4 = (range_id - 4) * 12 + pos
    pitch_float = 440. * math.pow(2, delta_A4 / 12.)
    return math.floor(pitch_float)


def dump_chord_pitch_association():
    for r in range(2, 7):
        for c in NOTE_MAP[3:] + NOTE_MAP[:3]:
            p = chord2pitch(c + str(r))
            n = pitch2note(p)
            print('{:3s} {:4d} {:3s}'.format(c + str(r), p, n))
            assert c + str(r) == n


# Music data
THEME1 = 'A3 A3 C4 A3 D4 A3 E4 D4 C4 C4 E4 C4 G4 C4 E4 C4 G3 G3 B3 G3 C4 G3 D4 C4 F3 F3 A3 F3 C4 F3 C4 B3'


def get_theme1(is_last=False, is_after_theme2=False):
    res = []
    for c in THEME1.split(' '):
        res.append((chord2pitch(c), 256))
        res.append((0, 320))
    if is_last:
        # last pitch is longer
        res[-2] = (res[-2][0], 512)
    if is_after_theme2:
        # beginning is slightly different
        res[0] = (res[0][0], 120)
        res[1] = (res[1][0], 192)
    return res[:-1]


def get_theme2():
    res = []
    for i in range(8):
        if (i % 4) != 3:
            res.append((chord2pitch('A5'), 368))
            res.append((0, 416))
            res.append((chord2pitch('G5'), 368))
            res.append((0, 416))
            res.append((chord2pitch('F5'), 368))
            res.append((0, 416))
            res.append((chord2pitch('E5'), 368))
            res.append((0, 416))
            res.append((chord2pitch('D5'), 328))
            res.append((0, 640))
        else:
            res.append((chord2pitch('E5'), 368))
            res.append((0, 416))
            res.append((chord2pitch('D5'), 368))
            res.append((0, 416))
            res.append((chord2pitch('C5'), 368))
            res.append((0, 416))
            res.append((chord2pitch('B4'), 368))
            res.append((0, 416))
            if i == 3:
                res.append((chord2pitch('A4'), 328))
                res.append((0, 640))
            else:
                res.append((0, 320))
                res.append((chord2pitch('A4'), 8))
    return res


MSG = (
    'X-0 X-0 Eb5-564 A5-0 Eb6-0 X-640 ' +
    'X-0 X-0 Eb5-564 A5-0 Eb6-0 X-640 ' +
    'X-0 X-0 A5-564 Eb5-0 Eb6-0 X-640 ' +
    'X-0 X-0 Eb6-564 A5-0 Eb5-0'
)


def decode_msg(msg):
    res = []
    for data in msg.split(' '):
        c, d = data.split('-')
        res.append((0 if c == 'X' else chord2pitch(c), int(d)))
    return res


def sleep(d):
    return [(0, d)]


MUSIC = (
    get_theme1() + sleep(320) + get_theme1() +
    sleep(46400) +
    decode_msg(MSG) +
    sleep(25216) +
    get_theme1() + sleep(320) + get_theme1() +
    sleep(25344) +
    get_theme2() + get_theme1(is_after_theme2=True) + sleep(320) + get_theme1() +
    sleep(21824) +
    decode_msg(MSG) +
    sleep(1088) +
    get_theme2() + get_theme1(is_after_theme2=True) + sleep(320) + get_theme1() +
    sleep(27968) +
    get_theme1() + sleep(320) + get_theme1(is_last=True)
)


# Format things
def format_music(mus):
    return '\n'.join('{0[0]} {0[1]}'.format(x) for x in mus)


with tempfile.NamedTemporaryFile(prefix='recompose') as filerom:
    with tempfile.NamedTemporaryFile(prefix='recompose') as filemus:
        filerom.write(format_music(MUSIC_FROM_ROM).encode('ascii'))
        filemus.write(format_music(MUSIC).encode('ascii'))
        filerom.flush()
        filemus.flush()
        subprocess.call(['diff', '-y', '--suppress-common-lines', filerom.name, filemus.name])
