Hack In Paris Challenge 1
=========================

The challenge began on Friday December, 18th 2015, with a `tweet <https://twitter.com/hackinparis/status/677775353893515264>`_::

    #HIPChall Number 1 : http://bit.ly/1YpnZnB
    A Throwing Star LAN Tap and Two #HIPGoldenTickets to win!
    Be the first, Be Fair play, Have Fun!

This tweet indicates a web site, https://hackinparis.com/data/chall2016/, which only contains a PNG image, https://hackinparis.com/data/chall2016/chall1.png:

.. image:: chall1/chall1.png
    :scale: 50 %

Wireshark reveals an unknown section named ``vGNr``, containing::

    ixeas://yddotyprujw.nzm/udue/nsaco2016/ef7118o5-p1au-49g0-84f7-3850h4n21210.mie

This looks like an URL encrypted using a Vigenère cipher.
By supposing the URL to begin with ``https://hackinparis.com/``, it is very easy to find the encryption key.
This can be accomplished for example with such a Python script.

.. include:: chall1/vigenere.py
    :code: python

The encryption key is ``bellard`` and the decrypted URL https://hackinparis.com/data/chall2016/db7118d5-e1ad-49d0-84e7-3850d4c21210.bin.
Here is the output of some commands::

    $ file db7118d5-e1ad-49d0-84e7-3850d4c21210.bin
    db7118d5-e1ad-49d0-84e7-3850d4c21210.bin: BPG (Better Portable Graphics)

    $ strings -tx -7 db7118d5-e1ad-49d0-84e7-3850d4c21210.bin
        151 RUItUEMtQ0lEQ0JFiesabi46
        222 __main__s
        24e structR
        28e __name__t
        29b decodet
        2ac raw_inputt
        2cb encode(
        2ee <module>
        85e #Fr 3/J
        922 %%o\;Sb

So the file is a BPG image with some Python code embedded.
Using the specification (http://bellard.org/bpg/bpg_spec.txt), here is the decode header::

    Offset  Hex data    Field name                  Description
    ------  ----------  --------------------------  ------------
        0   425047fb    file_magic                  "BPG\xfb"
        4   20          pixel_format (3 bits)       1: 4:2:0. Chroma at position (0.5, 0.5) (JPEG chroma position)
                        alpha1_flag (1)             0: no alpha plane
                        bit_depth_minus_8 (4)       0: bit depth is 8
        5   08          color_space (4)             0
                        extension_present_flag (1)  1: there is extension data
                        alpha2_flag (1)             0
                        limited_range_flag (1)      0
                        animation_flag (1)          0
        6   8310        picture_width               Width 0x190 = 400
        8   8240        picture_height              Height 0x140 = 320
        a   00          picture_data_length
        b   8616        extension_data_length       Extension data Length = 0x316
        d   00          first extension_tag
        e   8613        first extension_tag_length  First tag length = 0x313 = 787

Let's extract the extension tag, which is 787 bytes from offset 0x10::

    $ dd if=db7118d5-e1ad-49d0-84e7-3850d4c21210.bin of=bpgdata.bin skip=16 count=787 bs=1
    787+0 records in
    787+0 records out
    787 bytes copied, 0.00316447 s, 249 kB/s

    $ file bpgdata.bin
    bpgdata.bin: python 2.7 byte-compiled

Using uncompyle2 (https://github.com/wibiti/uncompyle2) leads to the following Python code:

.. code-block:: python

    #Embedded file name: _.py
    import sys
    from struct import pack
    A = 'RUItUEMtQ0lEQ0JF'
    B = 1650553701
    C = 13876
    D = '\xd5\x81\xd4m\x84\xf3\x84\x99\xf4\xf3\x82m\xf7\x99\xf4\x94\xa2m\x99\x85\x88\xa3\xf0\x95\xc1'
    E = '\xc3\x96\x95\x87\x99\x81\xa3\xa9k@\x95\x96\xa6@\xa2\x85\x95\x84@\xa3\x88\x89\xa2@\x97\x81\xa2\xa2\xa6\x96\x99\x84@\xa3\x96z@\x94\x85\x99\x85\x95\xa6\x85\x95@`\x81\xa3`@\x88\x81\x83\x92\x89\x95\x97\x81\x99\x89\xa2@`\x84\x96\xa3`@\x83\x96\x94@O'
    F = '\xd5\x96\x97\x85'
    G = 'LLL@\xc8\x81\x83\x92\xc9\x95\xd7\x81\x99\x89\xa2@\xf2\xf0\xf1\xf6@`@\xc3\x88\x81\x93\x93@\xf1@nnn'
    H = '\xc5\x95\xa3\x85\x99@\x97\x81\xa2\xa2\xa6\x96\x99\x84z@'
    if __name__ == '__main__':
        I = A.decode(pack('>IH', B, C))[::-1]
        print G.decode(I)
        print ''
        code = raw_input(H.decode(I))
        if len(code) > 0:
            if code.encode(I) == D[::-1]:
                print E.decode(I)
            else:
                print F.decode(I)

Adding some print statements allows to quickly discover the content of variables::

    pack('>IH', B, C) = 'base64'
    I = 'EBCDIC-CP-BE'
    G.decode(I) = '<<< HackInParis 2016 - Chall 1 >>>'
    H.decode(I) = 'Enter password: '
    E.decode(I) = 'Congratz, now send this password to: merenwen -at- hackinparis -dot- com !'
    F.decode(I) = 'Nope'
    D[::-1].decode(I) = 'An0ther_sm4r7_b34rd3d_MaN'

The flag of the first challenge is thus: **An0ther_sm4r7_b34rd3d_MaN**
