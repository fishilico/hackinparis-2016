Hack In Paris Challenge 3
=========================

The challenge began on Friday March, 4th, with a `tweet <https://twitter.com/hackinparis/status/705869825009197056>`_ which appeared at 13:37::

    No, just had a setback!
    READY? Here it is!
    #HIPChall n°3
    https://hackinparis.com/challenge-3.html …

The web page given by the tweet contains the following message::

    Hi !

    I really like old-school games like space invaders.
    I was looking for the new version of Tetris, however it seems that it's not
    Tetris but a secret game used by a secret group !
    When I launched the game, it asked for a password... So I tried to use my
    reverse-engineering skills to find the password, but IDA won't load this
    file... :(
    Can you help me find the password ?

     https://hackinparis.com/data/chall2016/step-3/output.c16

    The fingerprints for output.c16 :

     md5 e85b598ea1e89816c2264105f964c26a
     sha256 1bfbb466e645b04d533df2b0834cbe52f18389e56896b1bf0b4b219707d7a017

    Please send your conclusions (and the validation flag) to
    merenwen@hackinparis.com

``output.c16`` is a 8926-byte file containing the following strings::

    $ strings output.c16
    CH16
    Hack In Paris - CHIP16 !                merenwen@hackinparis.com
    Please, enter the password :
    Bad password !
    You lucky bastard.

CHIP16 refers to a kind of hardware which has been used to run games.
It uses an RISC instruction set which uses 16-bit addresses and 32-bit instructions.
More information can be found at this really well-written and short wiki: https://github.com/chip16/chip16

More precisely, here is some information which is quite useful to analyze the given ROM file:

* The ROM is loaded at address ``0x0000``.
* The stack is 512-byte-long and starts at ``0xFDF0``.
* There are Input/Output ports starting at ``0xFFF0``, and the byte at this address is used to read the state of a game controller.
* The screen resolution is 320x240.  It is updated at a frequency of 60 Hz, and there is an instruction, ``VBLNK``, which waits for the next VBLANK signal (which advertises every frame).

https://github.com/chip16/chip16/wiki/Machine-Specification describes Chip16 file format, with the following 16-byte header::

    Offset  Size    Meaning
    0x00    4       Magic number ('CH16')
    0x04    1       Reserved (0)
    0x05    1       Specification version H.L (0xHL)
    0x06    4       ROM size in bytes (excluding header)
    0x0A    2       Start address (initial value of PC register)
    0x0C    4       CRC32 checksum of ROM (excluding header) (polynomial: 0x04C11DB7)

In ``output.c16``, the first 16 bytes are::

    43 48 31 36 : "CH16"
    00          : (reserved)
    11          : Use spec 1.1
    ce 22 00 00 : ROM Size without header 0x22ce = 8910 bytes
    00 00       : Start address (0x0000)
    47 d3 6c 2d : CRC32 checksum

With the information of the wiki it is possible to disassemble the ROM.
As CHIP16 assembly code is not very easily readable, I implemented an instruction decoder in pseudo-code, which was written in Python.

Disassemble the ROM
-------------------

The execution of the ROM starts at address ``0x0000`` (according to the file header) with the following instruction::

    0000: 14 00 7a 02    call 0x027a

It thus calls a function at ``0x027a``, which is::

    027a: c0 00 00 00    push R0
    027e: c0 01 00 00    push R1
    0282: 20 00 4c 03    R0 <- 0x034c
    0286: 20 01 ca 02    R1 <- 0x02ca ; address of the welcome message
    028a: 31 01 00 00    *[R0] <- R1
    028e: 40 00 02 00    R0 += 0x0002
    0292: 20 01 0b 03    R1 <- 0x030b ; addr of "Please, enter the password :"
    0296: 31 01 00 00    *[R0] <- R1
    029a: 40 00 02 00    R0 += 0x0002
    029e: 20 01 28 03    R1 <- 0x0328 ; addr of "*"
    02a2: 31 01 00 00    *[R0] <- R1
    02a6: 40 00 02 00    R0 += 0x0002
    02aa: 20 01 2a 03    R1 <- 0x032a ; addr of "Bad Password !"
    02ae: 31 01 00 00    *[R0] <- R1
    02b2: 40 00 02 00    R0 += 0x0002
    02b6: 20 01 39 03    R1 <- 0x0339 ; addr of "You lucky bastard."
    02ba: 31 01 00 00    *[R0] <- R1
    02be: c1 01 00 00    pop R1
    02c2: c1 00 00 00    pop R0
    02c6: 15 00 00 00    return

This code copies 5 pointers to ASCII strings into a 10-byte array (5 2-byte items) at ``0x034c``.

Then the execute resumes back to ``0x0004``::

    0004: 03 00 00 00    Set BG color to 0
    0008: 20 0b 00 00    R11 <- 0x0000
    000c: 20 0c 00 00    R12 <- 0x0000
    0010: 20 03 00 00    R3 <- 0x0000
    0014: 20 0a 00 00    R10 <- 0x0000
    0018: 14 00 68 01    call 0x0168<draw_str_from_bank[r10]_and_newline>
    001c: 20 0a 01 00    R10 <- 0x0001
    0020: 14 00 68 01    call 0x0168<draw_str_from_bank[r10]_and_newline>

This initializes some registers and calls a function at ``0x0168``, which I named ``draw_str_from_bank[r10]_and_newline`` because its analysis reveals it draws the characters of the string at index R10 in the array at ``0x034c``, followed by a new line.
Here this function is called twice, with R10=0 at first, and R10=1 secondly.
This produces the following output on the screen::

    Hack In Paris - CHIP16!
    merenwen@hackinparis.com
    Please, enter the password :

Then the following code is executed::

    0024: 20 0a 05 00    R10 <- 0x0005
    0028: 14 00 62 02    call 0x0262<sleep(R10)>
    002c: c0 0f 00 00    push R15
    0030: 22 0f f0 ff    R15 <- *[0xfff0] ; Read I/O input
    0034: 60 0f ff 00    R15 &= 0x00ff
    0038: 12 00 44 00    if cond0, jmp 0x0044
    003c: c1 00 00 00    pop R0
    0040: 10 00 48 00    jmp 0x0048
    0044: c1 00 00 00    pop R0

    0048: 20 0a 02 00    R10 <- 0x0002 ; index of "*"
    004c: 63 0f 01 00    Test(R15 & 0x0001)
    0050: 12 00 5c 00    if cond0, jmp 0x005c
    0054: 14 00 84 01    call 0x0184<draw_str_from_bank[r10]_and_r3+=1>
    0058: c0 0f 00 00    push R15

    005c: 63 0f 02 00    Test(R15 & 0x0002)
    0060: 12 00 6c 00    if cond0, jmp 0x006c
    0064: 14 00 84 01    call 0x0184<draw_str_from_bank[r10]_and_r3+=1>
    0068: c0 0f 00 00    push R15

    006c: 63 0f 04 00    Test(R15 & 0x0004)
    0070: 12 00 7c 00    if cond0, jmp 0x007c
    0074: 14 00 84 01    call 0x0184<draw_str_from_bank[r10]_and_r3+=1>
    0078: c0 0f 00 00    push R15

    007c: 63 0f 08 00    Test(R15 & 0x0008)
    0080: 12 00 8c 00    if cond0, jmp 0x008c
    0084: 14 00 84 01    call 0x0184<draw_str_from_bank[r10]_and_r3+=1>
    0088: c0 0f 00 00    push R15

    008c: 20 0f 00 00    R15 <- 0x0000
    0090: 53 03 08 00    Cmp(R3 - 0x0008)
    0094: 12 00 9c 00    if Z, jmp 0x009c
    0098: 10 00 24 00    jmp 0x0024

This is a loop (it ends with a jump to the beginning) which waits for 8 key presses from the first controller (which input is read from address ``0xfff0``).
For each key pressed, it prints a star on the screen, increases R3 by 1 and pushes the key value onto the stack.
Once 8 keys have been recorded, the code jumps to the next instructions, at ``0x009c``::

    009c: 20 04 01 00    R4 <- 0x0001
    00a0: c1 0d 00 00    pop R13
    00a4: 53 0d 02 00    Cmp(R13 - 0x0002)
    00a8: 17 01 0c 01    if !Z, call 0x010c<set_0_to_r4>
    00ac: c1 0d 00 00    pop R13
    00b0: 53 0d 01 00    Cmp(R13 - 0x0001)
    00b4: 17 01 0c 01    if !Z, call 0x010c<set_0_to_r4>
    00b8: c1 0d 00 00    pop R13
    00bc: 53 0d 02 00    Cmp(R13 - 0x0002)
    00c0: 17 01 0c 01    if !Z, call 0x010c<set_0_to_r4>
    00c4: c1 0d 00 00    pop R13
    00c8: 53 0d 01 00    Cmp(R13 - 0x0001)
    00cc: 17 01 0c 01    if !Z, call 0x010c<set_0_to_r4>
    00d0: c1 0d 00 00    pop R13
    00d4: 53 0d 04 00    Cmp(R13 - 0x0004)
    00d8: 17 01 0c 01    if !Z, call 0x010c<set_0_to_r4>
    00dc: c1 0d 00 00    pop R13
    00e0: 53 0d 04 00    Cmp(R13 - 0x0004)
    00e4: 17 01 0c 01    if !Z, call 0x010c<set_0_to_r4>
    00e8: c1 0d 00 00    pop R13
    00ec: 53 0d 08 00    Cmp(R13 - 0x0008)
    00f0: 17 01 0c 01    if !Z, call 0x010c<set_0_to_r4>
    00f4: c1 0d 00 00    pop R13
    00f8: 53 0d 08 00    Cmp(R13 - 0x0008)
    00fc: 17 01 0c 01    if !Z, call 0x010c<set_0_to_r4>
    0100: 53 04 00 00    Cmp(R4 - 0x0000)
    0104: 12 00 3c 01    if Z, jmp 0x013c<show_failure_msg>
    0108: 14 00 14 01    call 0x0114<show_good_msg>

    set_0_to_r4:
    010c: 20 04 00 00    R4 <- 0x0000
    0110: 15 00 00 00    return

These instructions pop the 8 key presses in the opposite order they have been pushed on the stack and compares them with the sequence "2 1 2 1 4 4 8 8".
If the key presses match this sequence, the code calls function ``0x0114`` which displays the winning message, draw an image and play some music.
Otherwise the code jumps to ``0x013c``, which displays "Bad password !" and jumps back to ``0x0014``, which prompts for the password again.

The password is therefore the sequence of key presses leading to the sequence "8 8 4 4 1 2 1 2" in I/O port ``0xfff0``.

Both the already-mentioned wiki (https://github.com/chip16/chip16/wiki/Machine-Specification#controller-layout) and the code of an emulator written in C++, https://github.com/refractionpcsx2/refchip16/blob/master/RefChip16/InputDevice.cpp#L69, give the following key-binding::

    Bit 0 (value   1) = Up
    Bit 1 (value   2) = Down
    Bit 2 (value   4) = Left
    Bit 3 (value   8) = Right
    Bit 4 (value  16) = Select
    Bit 5 (value  32) = Start
    Bit 6 (value  64) = A Button
    Bit 7 (value 128) = B Button

This allows to finally find the flag of the third Hack In Paris challenge: **Right Right Left Left Up Down Up Down**.


Appendix - Additional findings
------------------------------

When the correct password is entered, an image is displayed.
As this image uses a 16-bit palette (4 bits per pixel), it can be obtained with a hexadecimal dump (it is a 50x32 image)::

    $ dd if=output.c16 bs=1 skip=$((0x1c8e+0x10)) | xxd -c50 -p
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeeeeffffffffffffffffffffffff
    ffffffffffffffffffe8aaaaaaaaa8effffffffffffffffffffffffffffffffffffaaaaaaaaaaaaaa8ffffffffffffffffff
    fffffffffffffffeaaaaaaaaaaaaaaaaaffffffffffffffffffffffffffffffffaaaaaaaaaa8aaaaaaaaffffffffffffffff
    ffffffffffffffaaaaaaaaaaef9aaaaaaaaffffffffffffffffffffffffffffaaaaaaaaaaaff99aaaaaaa8ffffffffffffff
    ffffffffffffeaaaaaaaaaaefe9999aaaaaaefffffffffffffffffffffffffaaaaaaaaaaaffe99999aaaaaefffffffffffff
    ffffffffffffaaaaaaaaaaeffe9999999aaeaffffffffffffffffffffffff8aaaaaaaaaafff8999999988aa8ffffffffffff
    fffffffffffaaaaaaaaaaffff899999aea9aaafffffffffffffffffffffff8eaaaaaaaaffffe88eeea99999affffffffffff
    fffffffffffaaa8aaaaaffffffffff9999999afffffffffffffffffffffffaaaaa8ea8fffffffffa9999999affffffffffff
    fffffffffffaaaaaaaaffffffffff99999999afffffffffffffffffffffffaaaaaaa8fffffffff8999999998ffffffffffff
    fffffffffffeaaaaaaaaaea8ffffa99999999effffffffffffffffffffffffaaaaaaa88aa8fff888aaa999afffffffffffff
    ffffffffffff8aaaa88aaaaefff99999aeeaeffffffffffffffffffffffffffaa88aaaaaaeffa99999999affffffffffffff
    ffffffffffffff8aaaaaaaafff999999999effffffffffffffffffffffffffffaaaaaaaaaff899999999afffffffffffffff
    fffffffffffffffaaaaaaaaff9999999aafffffffffffffffffffffffffffffffffaaaaaaf8999999affffffffffffffffff
    ffffffffffffffffffeaaaa8a9999aefffffffffffffffffffffffffffffffffffffffe8aaaaaaefffffffffffffffffffff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

Moreover a music is played.
The code uses the same code as https://github.com/tykel/midi16/blob/master/src/chip16.c#L28 to play a song from the data which lies at address ``0x0f52``.
Each music note is encoded on 2 16-bit Little Endian integers: the first one for the pitch (in Hertz) and the second one for the sound duration (in milliseconds).
The music is the theme of Mortal Kombat, with some variations inside.

Finally the characters are displayed using a font at ``0x0352``.
Each character of this font is a 8x8 image encoded on 32 bytes.
In fact the font bitmap which is used is ``font.bmp`` in a text printing sample program which can be found at https://github.com/chip16/chip16/tree/master/src/Samples/Text: https://raw.githubusercontent.com/chip16/chip16/master/src/Samples/Text/font.bmp
