Hack In Paris Challenge 4
=========================

The challenge began on Friday April, 8th, with a `tweet <https://twitter.com/hackinparis/status/718461407596015616>`_::

    Make your dream come true, #HIPChall n°4 is up!
    #YubiKeyNeo & 2 #goldenticket for #HIP16
    Hack, Love, Share, & enjoy!
    https://hackinparis.com/challenge-4.html …

The web page given by the tweet contains the following message::

    Hi !

    I have found a strange PDF file that seems to contain some interesting data but I didn't know how to extract and read them.

    Can you help me?

    https://hackinparis.com/data/chall2016/step-4/dump.pdf

    md5 fac78b48bf9603fd52b2f2156d587f1d
    sha1 0a7cc0598b5432f7c387a6b5cf8d73409209bcfd

    Please send your conclusions (and the validation flag) to merenwen@hackinparis.com

A PDF file which is also an ELF file and a ZIP file
---------------------------------------------------

The downloaded file is a polyglot file: it is both an ELF file, a PDF file and a ZIP file::

    $ binwalk dump.pdf
    DECIMAL       HEXADECIMAL     DESCRIPTION
    --------------------------------------------------------------------------------
    0             0x0             ELF, 32-bit LSB executable, Intel 80386, version 1 (SYSV)
    716           0x2CC           PDF document, version: "1.4"
    [...]
    842635        0xCDB8B         Zip archive data, encrypted at least v1.0 to extract, compressed size: 57, uncompressed size: 45, name: README.txt
    842776        0xCDC18         Zip archive data, encrypted at least v2.0 to extract, compressed size: 14476, uncompressed size: 17920, name: pass.png
    857334        0xD14F6         Zip archive data, encrypted at least v1.0 to extract, compressed size: 15269, uncompressed size: 15257, name: a.zip
    872915        0xD51D3         End of Zip archive

The PDF file contains the hexdump of this image:

.. image:: chall4/pdfimg.png

The ZIP file requires a password to be extracted and the ELF file seems to test a password given by its standard input.
Here is an extract of the output of ``objdump -Mintel -d dump.pdf`` with some comments::

     80480f1:    bb 01 00 00 00           mov    ebx,0x1
     80480f6:    b8 03 00 00 00           mov    eax,0x3
     80480fb:    89 e1                    mov    ecx,esp
     80480fd:    ba 64 00 00 00           mov    edx,0x64
     8048102:    cd 80                    int    0x80         # syscall(read, fd=1, buf=esp, count=100)
     8048104:    83 f8 0c                 cmp    eax,0xc
     8048107:    0f 85 8a 00 00 00        jne    0x8048197    # Read 12 bytes
     804810d:    89 e2                    mov    edx,esp
     804810f:    8b 02                    mov    eax,DWORD PTR [edx]
     8048111:    3d 46 6b 6f 70           cmp    eax,0x706f6b46
     8048116:    75 7f                    jne    0x8048197    # The first ones have to be "Fkop"
     8048118:    83 c2 04                 add    edx,0x4
     804811b:    8b 1a                    mov    ebx,DWORD PTR [edx]
     804811d:    31 d8                    xor    eax,ebx
     804811f:    3d 72 4a 00 00           cmp    eax,0x4a72
     8048124:    75 71                    jne    0x8048197   # The 4 next ones have to be "4!op"
     8048126:    83 c2 04                 add    edx,0x4
     8048129:    8b 1a                    mov    ebx,DWORD PTR [edx]
     804812b:    31 d8                    xor    eax,ebx
     804812d:    3d 3e 27 39 0a           cmp    eax,0xa39273e
     8048132:    75 63                    jne    0x8048197    # The 4 next ones have to be "Lm9\n"

The password seems to be ``Fkop4!opLm9``::

    $ ./dump.pdf
    What's the pass?
    Fkop4!opLm9
    Rename the file in chall.zip and use this password.

How to crack an encrypted message in a corrupted image
------------------------------------------------------

The ZIP archive can then be decrypted.  It contains three files:

* ``README.txt``: contains "The archive password is in the PNG picture."
* ``pass.png``: an invalid PNG image (it can't be opened with a standard image viewer)
* ``a.zip``: an encrypted ZIP archive

The PNG image is invalid because the CRC field of every chunk is zero.
The CRC checksums can be fixed using a program such as http://schaik.com/png/pngcsum.html , which allows viewing the image.
It contains the following text::

    CGEJDH AGBIBJ AFEGBG BJAFEH EJDHAJ AIEJBI EFBJAH
    EHDHAG AJEGCG CGDIAJ AJAIEG BGBGEI BFDICG BIEIDF
    AFDIBF AFEFEH AJCIDI AJAJBJ AGDIEH AFDJEH BGBGEF
    DIBGDF EIEJEG AFEJCG EJBIBI DICGAF BGEIEJ DFDIDH
    AFEFDI CFEHDF AIEHBG DIDGEI AGEHAH EHDHAG EIEJEG
    AFEFDI BIEHAG EFAFDF BJAJAJ DJEJBI BFBFEJ DHAFAI
    EJBIAG DIAFEI EJEGAJ EFEJEG BGBFDJ BIEHAF DIEHAF
    EHDHBG EJDJDI BICGBJ AJDIBG DIAFAF DIBIAJ AFEFDI
    DFBJAJ AJDJEJ BIBFEH AJAFDG AFBJDH AJDIEI AJBJDI
    EHEJCI AJDFEF DIAJBG

The first column only contains letters A, C, D, E, the second one only F, G, H, I, J, the third one B, D, E...
It seems more logical to combine the letters by pairs: the first letter being in {A, B, C, D, E} and the second one in {F, G, H, I, J}.
This looks like an encryption with the Polybius square algorithm, where each letter pair is associated to a character.
As it is a substitution cipher, it may be possible to guess some words... for example "password" seems to be ``DF BJ AJ AJ DJ EJ BI BF`` (which appears 2 times).

This leads to the following substitution array::

       A? B? C? D? E?
    ?F  t  d  z  p  h
    ?G  g  l  c  b  u
    ?H  v  ?  ?  n  i
    ?I  f  r  m  e  y
    ?J  s  a  ?  w  o

The message is therefore: "Congratulations for having successfully decrypted this message. It will help you to correctly open the zip file by giving you the right password. Don't forget you should write it in lowercase letters. The password is tbtanseysaeiomsphesl".

This gives the password which is needed to decrypt a file named ``chall.bin`` in ``a.zip`` archive.
This file is an ELF program::

    $ file chall.bin
    chall.bin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
    interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24,
    BuildID[sha1]=88f9eadd2bf8128ca309a8dc627e18c82c2755a3, stripped

``chall.bin``, a brainfuck interpreter in bytecode
--------------------------------------------------

``chall.bin`` is an interpreter for a custom bytecode language.
The state of the interpreted program (the "virtual machine") is allocated on the stack of function ``main()`` (at ``.text:400B28``) and initialized by the function at address ``.text:400D2A``.
This state has the following structure:

* offsets 0x00..0x27: ``int32 regs[10]``, ten 32-bit integer *registers*
* offsets 0x28..0x2b: ``int32 sp``, the *stack pointer*, offset of the "top" of the stack (which is reverted like x86 CPU)
* offsets 0x2c..0x2f: ``int32 ip``, the *instruction pointer*, offset of the current instruction in the program
* offsets 0x30..0x33: ``int32 sf``, the *sign flag*
* offsets 0x34..0x37: ``int32 zf``, the *zero flag*
* offsets 0x38..0x3b: ``int32 memsize``, the size of allocated virtual memory (500 000 bytes)

There are 16 kinds of instruction, of different sizes.
The first byte tells the operation code of the instruction (4 low bits) and whether its execution depends on the SF flag to be set (bit 5, 0x10) or on the ZF flag (bit 6, 0x20).

* If the opcode is between 0 and 9, the instruction is an arithmetic instruction between two operands and is encoded on 10 bytes.
* If the opcode is between 10 and 12, the instruction only has one operand and is encoded on 6 bytes.
* Otherwise, the opcode is between 12 and 15, has no operand and is encoded on one single byte.

When an instruction has an operand, its second byte defines the kind of operand: 1 for an immediate 32-bit value, 2 for a register value and 4 for the value at the address of the given register.

The instructions are (with ``x`` being the first operand and ``y`` the second one):

* opcode 0: ``x |= y`` (OR)
* opcode 1: ``x ^= y`` (XOR)
* opcode 2: ``x &= y`` (AND)
* opcode 3: ``x += y`` (ADD)
* opcode 4: ``x -= y`` (SUB)
* opcode 5: ``x *= y`` (MUL)
* opcode 6: ``x /= y`` (DIV)
* opcode 7: ``x %= y`` (MOD)
* opcode 8: ``x <<= y`` (SHL)
* opcode 9: ``x >>= y`` (SHR)
* opcode A: ``PUSH x``
* opcode B: ``POP x``
* opcode C: ``CALL x``
* opcode D: ``RET``
* opcode E: ``READ(fd=r0, buf=r1, size=r2)`` and replace ``\n`` with ``0`` on the first byte of the buffer
* opcode F: ``WRITE(fd=r0, buf=r1, size=r2)``

The instructions are read from ``.rodata:402280`` and the memory of the interpreter is initialized with the content of ``.rodata:41A920``.
The interpreted program decrypt the data using the following algorithm (written in Python 3):

.. code-block:: python

    with open('chall.bin', 'rb') as f:
        filedata = f.read()
    memdata = filedata[0x1A920:0x1A920 + 43850]

    cleardata = bytearray(len(memdata))
    for i, x in enumerate(memdata):
        cleardata[i] = x ^ (i % 100)

The decrypted data is interpreted as Brainfuck language (https://en.wikipedia.org/wiki/Brainfuck) with the following character conversion:

* 0, 1: ``+`` (increment the byte at the data pointer, which is ``r1``)
* 2, 3: ``-`` (decrement the byte at the data pointer)
* 4, 5: ``<`` (decrement the data pointer by one cell, which measures 4 bytes)
* 6, 7: ``>`` (increment the data pointer by one cell)
* 8, 9: ``[`` (conditional jump forwards to the matching ``]`` if the byte at the data pointer is zero)
* a, b: ``]`` (conditional jump backwards to the matching ``[`` if the byte at the data pointer is not zero)
* c, d: ``.`` (write the byte at the data pointer to the standard output)
* e, f: ``,`` (read one byte from the standard input into the byte at the data pointer)
* space or ``\n``: exit the program

The Brainfuck program is quite simple:

* It begins by writing "What is the magic word ?"
* It then reads the standard input and compare with some values. If the input does not match, it outputs "Ah ah ah! You didn't say the magic word!" and quits.
* If the input is correct, it outputs "Well done!"

The input which is correct is the key, **HIP{f3a306095ecc4dad3d0056ad7b0c135afd89e3127e279e4f906711bf6357f03c}**
