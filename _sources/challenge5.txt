Hack In Paris Challenge 5
=========================

The challenge began on Friday May, 20th, with a `tweet <https://twitter.com/hackinparis/status/733687357233352704>`_::

    #HIPChall n°5 is on!
    #BeagleBoneBlack & 2 #goldenticket for #HIP16
    Hack, Love, Share, & enjoy!
    https://hackinparis.com/challenge-5.html …

The web page contains this message::

    Hi!

    I was following a white rabbit but I've lost it.
    Can you find it for me?

    Alice

    https://hackinparis.com/data/chall2016/step-5/chall.img

    md5:    351804dc726752fda5db3fe69f6c5c34
    sha256:    078a5cd5a40e320f0811ef99644e19c5825d81818aa517c6d771860124de3577

    Please send your conclusions (and the validation flag) to merenwen@hackinparis.com


``chall.img`` is a FAT32 filesystem labeled ``challHIP`` which contains many useless files and a GIF image:

.. image:: chall5/Nothing_to_find_here.gif

Binwalk spots a ZIP archive in this mess::

    $ binwalk chall.img

    DECIMAL       HEXADECIMAL     DESCRIPTION
    --------------------------------------------------------------------------------
    1320448       0x142600        GIF image data, version "89a", 350 x 260
    2720256       0x298200        Zip archive data, at least v2.0 to extract, compressed size: 18046268, uncompressed size: 22653106, name: file1
    20766587      0x13CDF7B       Zip archive data, at least v2.0 to extract, compressed size: 247210, uncompressed size: 281973, name: file2
    21013860      0x140A564       Zip archive data, at least v2.0 to extract, compressed size: 4067, uncompressed size: 13383, name: step1.bin
    21018223      0x140B66F       End of Zip archive
    49586962      0x2F4A312       MySQL MISAM compressed data file Version 7
    50839721      0x307C0A9       Certificate in DER format (x509 v3), header length: 4, sequence length: 9733

Let's extract this 18 MB archive!
::

    $ dd if=chall.img of=chall.zip bs=1 skip=$((0x298200)) count=$((0x0140b684-0x298200+16))
    $ unzip chall.zip
    Archive:  chall.zip
      inflating: file1
      inflating: file2
      inflating: step1.bin

``step1.bin``
-------------

``step1.bin`` is a Linux program which is very simple to reverse-engineer as it contains all its symbol.
The analysis of ``main()`` (at ``.text:4010F3``) reveals that this programs can decrypt files which either begin with "Keep me please" or "Keep me too".
As life is well done, the two other files which are part of the initial ZIP archive match these patterns::

    $ xxd file1 |head -n1
    00000000: 4b65 6570 206d 6520 706c 6561 7365 135b  Keep me please.[

    $ xxd file2 |head -n1
    00000000: 4b65 6570 206d 6520 746f 6f50 2f4b 2a77  Keep me tooP/K*w

The first file is decrypted with function ``decryptSimple()`` at ``.text:40095D``.
This function verifies that the key given to the program satisfies a set of basic equations and then decrypt the data.
It is possible to solve the equations by hand.
It is also possible to use ``z3`` to kindly ask the computer to find the key:

.. include:: chall5/crack_simple_key_with_z3.py
    :code: python

The output of this Python program is::

    'F0llow_7he_White_R4bbit\x00'

To decrypt ``file1`` all what is needed is to run ``step1.bin``::

    $ ./step1.bin file1 F0llow_7he_White_R4bbit 2> file1_decrypted.out.b64
    Would you like some wine?

    $ base64 -d file1_decrypted.out.b64 > file1_decrypted.out
    $ file file1_decrypted.out
    file1_decrypted.out: RIFF (little-endian) data, AVI, 1280 x 820, ~24 fps,
    video: FFMpeg MPEG-4, audio: MPEG-1 Layer 3 (stereo, 44100 Hz)

The function ``decryptMoreComplex()`` at ``.text:400F49`` is a more complex: it computes the ``crypt()`` hash of the encryption key with two algorithms and salts (``$6$4Fz7Ehwg$`` and ``$1$4Fz7Ehwg$``) and uses the results to xor the file.
Nevertheless if the decrypted file is a base64-encode file like ``file1``, it is possible to crack this algorithm using z3:

.. include:: chall5/crack_decryptMoreComplex_key_with_z3.py
    :code: python

This script finds the two hashes and successfully decrypts ``file2``.
However this does not seem to be the intended way of solving this challenge, as the key to decrypt ``file2`` is also buried deep into ``file1``.
Let's describe the standard solving path instead of taking this amazing shortcut!


``file1``
---------

The decrypted ``file1`` is an MPEG video which contains an hexadecimal line at the bottom, which seems to dump a file.
Using ``ffmpeg`` to extract the video frames and after doing some custom OCR, the file is extracted::

    $ mkdir file1-frames/
    $ ffmpeg -i file1_decrypted.out file1-frames/frame%05d.png
    $ ./file1_extract_framehex.py
    $ file file1_framehex.out
    file1_framehex.out.bin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
    dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux
    2.6.24, BuildID[sha1]=796e8cb3fec1f948780986af22fbd1348c3db003, stripped

This function decrypts a payload which is present after the video data with a key which is tested by a function at ``.text:40084D``.
A little bit of z3 solving allows to retrieve the encryption key, ``Have_you_guessed_the_riddle_yet``::

    $ ./file1_framehex.out file1_decrypted.out Have_you_guessed_the_riddle_yet 2> file1_video_payload.out
    Curiouser and curiouser!
    $ file file1_video_payload.out
    file1_video_payload.out: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, stereo 44100 Hz

Running ``strings`` on this new file reveals this message::

    The first part of the password is "Use_me_to_d3crypt_". It can be used to
    decrypt the next step. But, before using it, have you find the second part?

Audacity shows weird peaks in the wave signal of this audio file.
This is due to some bytes which have been hidden into the data with a given period.
Some experiments lead to extracting one byte every 46907 bytes starting from offset 576:

.. include:: chall5/file1_analyze_wav.py
    :code: python

The message is::

    Congratulation for finding me !

    The second part of the password is "the_last_3ncrypted_file"
    It can be used to decrypt the next step.
    @<;;

The password ``Use_me_to_d3crypt_the_last_3ncrypted_file`` can be used to decrypt ``file2``::

    $ ./step1.bin file2 Use_me_to_d3crypt_the_last_3ncrypted_file 2> file2_decrypted.out.b64
    Begin at the beginning, and go on till you come to the end: then stop.

    $ base64 -d < file2_decrypted.out.b64 > file2_decrypted.out
    $ file file2_decrypted.out
    file2_decrypted.out: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
    statically linked, BuildID[sha1]=8c36a356734d8731a544c3d66f2eafc2d25475de, stripped


``file2``
---------

``file2`` is a x86-32 bit Linux program which is verifying a password given as a parameter::

    $ ./file2_decrypted.out
    Usage: ./chall.bin <pass>
    $ ./file2_decrypted.out '<pass>'
    Wait please...
    Oh my ears and whiskers. You are completely wrong :(

This program decrypts itself using XOR encryption with many level of decryption.
Too many for attempting to decrypt it by hand, and as the program re-encrypts itself before exiting, it is not possible to catch the exit system call to dump the decrypted program.
Moreover ``strace`` shows that this program calls ``signal(SIGTRAP...)`` many times, with increasing addresses.

gdb can detects that the program reached some deeply-buried addresses using these instructions::

    watch *0x080754FD if $pc >= 0x80753F9
    commands
    break *0x080754FD
    continue
    end
    r pass

gdb would display something similar to::

    Starting program: /tmp/chall5/file2_decrypted.out pass
    Wait please...

    Hardware watchpoint 1: *0x080754FD

    Old value = -419722244
    New value = -419722923
    0x080753fb in ?? ()
    => 0x080753fb:    83 c2 04    add    $0x4,%edx
    Breakpoint 2 at 0x80754fd

    Hardware watchpoint 1: *0x080754FD

    Old value = -419722923
    New value = -2082109099
    0x080753fb in ?? ()
    => 0x080753fb:    83 c2 04    add    $0x4,%edx
    Breakpoint 3 at 0x80754fd

    Breakpoint 2, 0x080754fd in ?? ()
    => 0x080754fd:    55    push   %ebp

The ``backtrace`` command shows that the program is now under 500 levels of decryption/calls.
To extract it::

    dump memory file2_clear.out 0x8048000 0x807b000

Some reverse-engineering work leads to understanding that the function at ``.text:080754FD`` is testing the password, which is read through a pointer is ``esi`` register, by hashing it with an algorithm similar to MD5 but with different constants.
Here is the algorithm with the differences with the one from Wikipedia (https://en.wikipedia.org/wiki/MD5)::

    //Note: All variables are unsigned 32 bit and wrap modulo 2^32 when calculating
    var int[64] s, K

    //s specifies the per-round shift amounts
    s[ 0..15] := { 7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22 }
    s[16..31] := { 5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20 }
    s[32..47] := { 4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23 }
    s[48..63] := { 6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21 }

    // K[0..27] differs with MD5. It is at .text:08075A5B
    K[0..63] := {
        0x14F02B43, 0x89C0E4CA, 0x2EE6E47B, 0x177ECEBF,
        0xA20C3D34, 0x5124C3C0, 0x1AEEF40C, 0x31675B41,
        0xCDB50C26, 0xF0789AA0, 0xFB54C0D4, 0xD58AD882,
        0x393E1CD7, 0x04BD0A4B, 0x28C0426E, 0xCA5F186C,
        0xC662BCD1, 0x0F06B131, 0x5A70DAF6, 0x7A7FF510,
        0x7829CDD8, 0xA1EB40D7, 0xDB2A8729, 0xB51A8A3D,
        0xD84E797A, 0xCC1F406D, 0xE182486D, 0x26E4F7DD,
    // from K[28..31], the arrays are the same:
        0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
        0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
        0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
        0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
        0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
        0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
        0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
        0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
        0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
    }

    //Initialize variables with custom constants
    var int a0 := 0xFD45F22F   //A
    var int b0 := 0x1431EE0C   //B
    var int c0 := 0x1458EF65   //C
    var int d0 := 0x455684AA   //D

    //Pre-processing: adding a single 1 bit
    append "1" bit to message
    //Pre-processing: padding with zeros
    append "0" bit until message length in bits ≡ 448 (mod 512)
    append original length in bits mod (2 pow 64) to message

    //Process the message in successive 512-bit chunks:
    for each 512-bit chunk of message
        break chunk into sixteen 32-bit words M[j], 0 ≤ j ≤ 15
    //Initialize hash value for this chunk:
        var int A := a0
        var int B := b0
        var int C := c0
        var int D := d0
    //Main loop:
        for i from 0 to 63
            if 0 ≤ i ≤ 15 then
                F := (B and C) or ((not B) and D)
                g := i
            else if 16 ≤ i ≤ 31
                F := (D and B) or ((not D) and C)
                g := (5×i + 1) mod 16
            else if 32 ≤ i ≤ 47
                F := B xor C xor D
                g := (3×i + 5) mod 16
            else if 48 ≤ i ≤ 63
                F := C xor (B or (not D))
                g := (7×i) mod 16
            dTemp := D
            D := C
            C := B
            B := B + leftrotate((A + F + K[i] + M[g]), s[i])
            A := dTemp
        end for
    //Add this chunk's hash to result so far:
        a0 := a0 + A
        b0 := b0 + B
        c0 := c0 + C
        d0 := d0 + D
    end for

    var char digest[16] := a0 append b0 append c0 append d0 //(Output is in little-endian)

    //leftrotate function definition
    leftrotate (x, c)
        return (x << c) binary or (x >> (32-c));

To crack this password, the most straightforward way seems to be to bruteforce it using https://crackstation.net/ wordlist and a C program which rips the function.

.. include:: chall5/runhashes.c
    :code: c

After less than 30 seconds, this program tested more than 13 million passwords and found ``bunnyrabbit``.
Let's try this with the real program::

    $ ./file2_decrypted.out bunnyrabbit
    Wait please...
    Congratulation! You found the White Rabbit!

          ***
         ** **
        **   **
        **   **         ****
        **   **       **   ****
        **  **       *   **   **
         **  *      *  **  ***  **
          **  *    *  **     **  *
           ** **  **  **       **
           **   **  **
          *           *
         *             *
        *    0     0    *
        *   /   @   \   *
        *   \__/ \__/   *
          *     W     *
            **     **
              *****

    The flag is the sha256sum of the password.
    Send it (and your write-up if you have one) to merenwen@hackinparis.com

The flag is the SHA256 hash of "bunnyrabbit", which is **7794db9a8656587526b3764d8f1354614ea13c035fe03fda47dd41bd1e5762a7**.
