Hack In Paris Challenge 2
=========================

The challenge began on Wednesday February, 3rd 2016, with a `tweet <https://twitter.com/hackinparis/status/694807800380260352>`_::

    #HIPChall Number 2 : http://bit.ly/1QbHueV  #FrenchTouch
    A #BLESnifferp and Two #HIPGoldenTickets to win!
    Be the first, Be Fair play, Enjoy

This tweet indicates a web site again, The link to https://hackinparis.com/challenge-2.html.
It contains this message::

    CHALLENGE #HIPCHALL - STEP 2
    Hello,

    You are investigating on behalf of a subsidiary of the ANFN group based
    on a suspicion of industrial espionage ; an employee has refused to
    report to the internal interview and did not cooperate with the analysis
    of his post. You got a memory image by a roundabout way.
    The image is available at the following address:

     https://hackinparis.com/data/chall2016/step-2/dump.7z

    The fingerprints for memdump_0x0-0x100000000_20160127-125924.bin :

     md5 e60e726b0bd6f3ed02c063ea4df43add
     sha256 6081121b669bbd6e16da754799ba1f366953e7ab159149b1943b436a5d11bbef

    Once you have completed the analysis, please send your conclusions
    (and the validation flag) to merenwen@hackinparis.com.

The given 7zip file contains ``memdump_0x0-0x100000000_20160127-125924.bin``, which is 4GB-large (4294967295 bytes).
Its MD5 and SHA256 sums match the ones which are given in the message.

Running volatility (https://github.com/volatilityfoundation/volatility) on the file to get information about this captured image leads (after 30 minutes on my laptop) to the following result::

    $ volatility -f memdump_0x0-0x100000000_20160127-125924.bin imageinfo
    Volatility Foundation Volatility Framework 2.5
    INFO    : volatility.debug : Determining profile based on KDBG search...
              Suggested Profile(s) : Win7SP0x64, Win7SP1x64, Win2008R2SP0x64, Win2008R2SP1x64
                         AS Layer1 : AMD64PagedMemory (Kernel AS)
                         AS Layer2 : FileAddressSpace (/tmp/memdump_0x0-0x100000000_20160127-125924.bin)
                          PAE type : No PAE
                               DTB : 0x187000
                              KDBG : 0xf80003a4d0a0
              Number of Processors : 1
         Image Type (Service Pack) : 1
                    KPCR for CPU 0 : 0xfffff80003a4ed00
                 KUSER_SHARED_DATA : 0xfffff78000000000
               Image date and time : 2016-01-27 12:06:45 UTC+0000
         Image local date and time : 2016-01-27 13:06:45 +0100

    $ volatility -f memdump_0x0-0x100000000_20160127-125924.bin kdbgscan
    Volatility Foundation Volatility Framework 2.5
    **************************************************
    Instantiating KDBG using: memdump_0x0-0x100000000_20160127-125924.bin WinXPSP2x86 (5.1.0 32bit)
    Offset (P)                    : 0x3a4d0a0
    KDBG owner tag check          : True
    Profile suggestion (KDBGHeader): Win7SP1x64
    PsActiveProcessHead           : 0x3a83590
    PsLoadedModuleList            : 0x3aa1890
    KernelBase                    : 0xfffff8000385e000

    $ volatility -f memdump_0x0-0x100000000_20160127-125924.bin kdbgscan --profile=Win7SP1x64
    Volatility Foundation Volatility Framework 2.5
    **************************************************
    Instantiating KDBG using: Kernel AS Win7SP1x64 (6.1.7601 64bit)
    Offset (V)                    : 0xf80003a4d0a0
    Offset (P)                    : 0x3a4d0a0
    KDBG owner tag check          : True
    Profile suggestion (KDBGHeader): Win7SP1x64
    Version64                     : 0xf80003a4d068 (Major: 15, Minor: 7601)
    Service Pack (CmNtCSDVersion) : 1
    Build string (NtBuildLab)     : P7?
    PsActiveProcessHead           : 0xfffff80003a83590 (2 processes)
    PsLoadedModuleList            : 0xfffff80003aa1890 (1 modules)
    KernelBase                    : 0xfffff8000385e000 (Matches MZ: True)
    Major (OptionalHeader)        : 6
    Minor (OptionalHeader)        : 1
    KPCR                          : 0xfffff80003a4ed00 (CPU 0)

The version field "Major: 15, Minor: 7601" states that the image has been taken from a system running Windows 7 SP1.
The volatility profile to use is therefore Win7SP1x64.

However with this profile, ``psscan`` does not show good results::

    $ volatility -f memdump_0x0-0x100000000_20160127-125924.bin --profile=Win7SP1x64 --dtb=0x187000 --kdbg=0x3a4d0a0 psscan
    Volatility Foundation Volatility Framework 2.5
    Offset(P)          Name                PID   PPID PDB                Time created                   Time exited
    ------------------ ---------------- ------ ------ ------------------ ------------------------------ ------------------------------
    0x00000000433d2040 System                4      0 0x0000000000187000 2016-01-27 11:24:51 UTC+0000

The system might not have been running when the image has been taken...

A quick keyword analysis of the strings which can be found in the memory dump (using ``strings -tx`` and ``strings -tx -e l`` to print sequences of printable characters with their hexadecimal offsets) shows::

    a0b03db @\malwhere\malwhere.exe
    e12b688 "C:\malware.exe"
    33dc8648 C:\malware.exe
    af219078 C:\malware.exe

    1daf6a80 .+:\\HACKING\\VYMPIRE\\CRYPT\\child\\.+.vbp

    # These are strings from Metasploit framework
    50c702e0 http://www.amazon.com/Oracle-Hackers-Handbook-Hacking-Defending/dp/0470080221
    7045f3aa ent feedback. Some people just seem to enjoy hacking SAP :)
    91183fc8 lent feedback. Some people just seem to enjoy hacking SAP :)
    b2d5ec88 http://sh0dan.org/oldfiles/hackingcitrix.html

There are also two interesting email addresses, xavuddyhe-7642@yopmail.com (used as LastPass account, according to an XML file at offset ``b400420c``) and fla@ndh.com (used as Google account, according to structures at offset ``1b481b5c``).

The memory dump also contains information about files which may have been loaded into RAM (which explains the Metasploit strings).
To dump such files, ``mftparser`` command can be used in Volatility::

    volatility -f memdump_0x0-0x100000000_20160127-125924.bin --profile=Win7SP1x64 \
    --dtb=0x187000 --kdbg=0xf80003a4d0a0 --kpcr=0xfffff80003a4ed00 mftparser

Analyzing the output of this command (with file paths) shows the following things:

* Some files contain data in memory (with a ``$DATA`` part), other not.
* The Metasploit framework was installed in ``C:\metasploit\apps\pro\msf3\``` on 2012-12-14 (which is quite old).
* There also is a postgresql server running, with log files named like ``postgresql-2016-01-27_112224.log``, but with no useful information.
* There are two user home directories on the system: ``C:\Users\ghost`` (used in April 2013 according to a log in ``PROGRA~3\Intel\Package Cache\{409CB30E-E457-4008-9B1A-ED1B9EA21140}\INSTAL~1.DAT``) and ``C:\Users\lolipop``.
* The file ``Users\ghost\Links\Desktop.lnk`` seems to suggest that ``C:\Users`` is a network mount of ``\\SYSDREAM-PC\Users``.
* There are also many Chrome-related files.
* On Windows, downloaded files get a special NTFS attribute which defines a *Zone Identifier*.
  ``volatility mftparser`` reports two such files::

    MFT entry found at offset 0x38015400
    Attribute: In Use & File
    Record Number: 185741
    Link count: 2


    $STANDARD_INFORMATION
    Creation                       Modified                       MFT Altered                    Access Date                    Type
    ------------------------------ ------------------------------ ------------------------------ ------------------------------ ----
    2016-01-27 10:09:02 UTC+0000 2016-01-27 10:09:09 UTC+0000   2016-01-27 10:09:09 UTC+0000   2016-01-27 10:09:02 UTC+0000   Archive

    $FILE_NAME
    Creation                       Modified                       MFT Altered                    Access Date                    Name/Path
    ------------------------------ ------------------------------ ------------------------------ ------------------------------ ---------
    2016-01-27 10:09:02 UTC+0000 2016-01-27 10:09:02 UTC+0000   2016-01-27 10:09:08 UTC+0000   2016-01-27 10:09:02 UTC+0000   Users\lolipop\DOWNLO~1\CONFTX~2.ZIP

    $FILE_NAME
    Creation                       Modified                       MFT Altered                    Access Date                    Name/Path
    ------------------------------ ------------------------------ ------------------------------ ------------------------------ ---------
    2016-01-27 10:09:02 UTC+0000 2016-01-27 10:09:02 UTC+0000   2016-01-27 10:09:08 UTC+0000   2016-01-27 10:09:02 UTC+0000   Users\lolipop\DOWNLO~1\conf.txt (1).zip

    $DATA
    0000000000: 50 4b 03 04 33 03 01 00 63 00 ba 60 3b 48 00 00   PK..3...c..`;H..
    0000000010: 00 00 7c 00 00 00 6c 00 00 00 08 00 0b 00 63 6f   ..|...l.......co
    0000000020: 6e 66 2e 74 78 74 01 99 07 00 02 00 41 45 01 08   nf.txt......AE..
    0000000030: 00 4c ed f3 e0 f2 9e 38 f8 ef b7 e9 cd bf e3 bf   .L.....8........
    0000000040: 53 dd e0 0b a1 f5 33 36 3a 76 e1 5b dd af 2d 1e   S.....36:v.[..-.
    0000000050: 60 aa 4f 1d 8a 53 a1 39 b0 d2 06 d7 1f 64 63 1c   `.O..S.9.....dc.
    0000000060: dd f2 91 8f 6f 98 1c da 9a d8 66 9e 9a 25 6d 93   ....o.....f..%m.
    0000000070: 2e 90 54 9e 71 b2 21 6e e8 92 fa 9c 34 4c 57 f0   ..T.q.!n....4LW.
    0000000080: 3c 9b fe 33 af 16 81 b2 ab 24 cd eb cc e2 46 09   <..3.....$....F.
    0000000090: f7 73 48 d4 12 d5 47 35 18 eb 91 f7 2f 3f d6 ec   .sH...G5..../?..
    00000000a0: e3 17 29 74 5c 80 37 f6 00 41 43 22 85 50 4b 01   ..)t\.7..AC".PK.
    00000000b0: 02 3f 03 33 03 01 00 63 00 ba 60 3b 48 00 00 00   .?.3...c..`;H...
    00000000c0: 00 7c 00 00 00 6c 00 00 00 08 00 2f 00 00 00 00   .|...l...../....
    00000000d0: 00 00 00 20 80 a4 81 00 00 00 00 63 6f 6e 66 2e   ...........conf.
    00000000e0: 74 78 74 0a 00 20 00 00 00 00 00 01 00 18 00 00   txt.............
    00000000f0: 28 7d af f2 58 d1 01 80 37 82 ac f2 58 d1 01 00   (}..X...7...X...
    0000000100: 28 7d af f2 58 d1 01 01 99 07 00 02 00 41 45 01   (}..X........AE.
    0000000110: 08 00 50 4b 05 06 00 00 00 00 01 00 01 00 65 00   ..PK..........e.
    0000000120: 00 00 ad 00 00 00 00 00                           ........

    $DATA ADS Name: Zone.Identifier
    0000000000: 5b 5a 6f 6e 65 54 72 61 6e 73 66 65 72 5d 0d 0a   [ZoneTransfer]..
    0000000010: 5a 6f 6e 65 49 64 3d 33 0d 0a                     ZoneId=3..

    ***************************************************************************
    ***************************************************************************
    MFT entry found at offset 0x3f301800
    Attribute: In Use & File
    Record Number: 189896
    Link count: 2


    $STANDARD_INFORMATION
    Creation                       Modified                       MFT Altered                    Access Date                    Type
    ------------------------------ ------------------------------ ------------------------------ ------------------------------ ----
    2016-01-27 09:59:04 UTC+0000 2016-01-27 09:59:06 UTC+0000   2016-01-27 09:59:06 UTC+0000   2016-01-27 09:59:04 UTC+0000   Archive

    $FILE_NAME
    Creation                       Modified                       MFT Altered                    Access Date                    Name/Path
    ------------------------------ ------------------------------ ------------------------------ ------------------------------ ---------
    2016-01-27 09:59:04 UTC+0000 2016-01-27 09:59:04 UTC+0000   2016-01-27 09:59:05 UTC+0000   2016-01-27 09:59:04 UTC+0000   Users\lolipop\DOWNLO~1\conf.txt.zip

    $FILE_NAME
    Creation                       Modified                       MFT Altered                    Access Date                    Name/Path
    ------------------------------ ------------------------------ ------------------------------ ------------------------------ ---------
    2016-01-27 09:59:04 UTC+0000 2016-01-27 09:59:04 UTC+0000   2016-01-27 09:59:05 UTC+0000   2016-01-27 09:59:04 UTC+0000   Users\lolipop\DOWNLO~1\CONFTX~1.ZIP

    $DATA
    0000000000: 50 4b 03 04 33 03 01 00 63 00 50 71 9e 47 00 00   PK..3...c.Pq.G..
    0000000010: 00 00 7c 00 00 00 6c 00 00 00 08 00 0b 00 63 6f   ..|...l.......co
    0000000020: 6e 66 2e 74 78 74 01 99 07 00 02 00 41 45 01 08   nf.txt......AE..
    0000000030: 00 cb b9 a1 dc 90 6a 25 5b bf c3 b1 36 8e 1c 65   ......j%[...6..e
    0000000040: 8c e1 35 55 18 7b bb ce 35 b8 ad 88 c4 6e 00 22   ..5U.{..5....n."
    0000000050: b4 48 9e 01 eb 6e 08 f5 27 a0 a7 a5 cd ed eb 8d   .H...n..'.......
    0000000060: 9e 3c cc f0 c3 20 ce ad dd 5e 2c a0 80 d7 5a 2d   .<.......^,...Z-
    0000000070: 5f 67 07 47 1c fa 46 31 34 c9 59 f5 cc 23 47 93   _g.G..F14.Y..#G.
    0000000080: 9c d7 2b d7 0a 2b e8 b2 f4 8c 83 d5 d0 87 93 b6   ..+..+..........
    0000000090: 6a c5 48 4d d6 16 73 b6 86 dd 1c ac ba 01 04 e9   j.HM..s.........
    00000000a0: 56 c8 50 d4 2b 80 ee a4 f0 0a 56 72 41 50 4b 01   V.P.+.....VrAPK.
    00000000b0: 02 3f 03 33 03 01 00 63 00 50 71 9e 47 00 00 00   .?.3...c.Pq.G...
    00000000c0: 00 7c 00 00 00 6c 00 00 00 08 00 2f 00 00 00 00   .|...l...../....
    00000000d0: 00 00 00 20 80 a4 81 00 00 00 00 63 6f 6e 66 2e   ...........conf.
    00000000e0: 74 78 74 0a 00 20 00 00 00 00 00 01 00 18 00 80   txt.............
    00000000f0: fd c0 75 03 43 d1 01 80 fd c0 75 03 43 d1 01 80   ..u.C.....u.C...
    0000000100: fd c0 75 03 43 d1 01 01 99 07 00 02 00 41 45 01   ..u.C........AE.
    0000000110: 08 00 50 4b 05 06 00 00 00 00 01 00 01 00 65 00   ..PK..........e.
    0000000120: 00 00 ad 00 00 00 00 00                           ........

    $DATA ADS Name: Zone.Identifier
    0000000000: 5b 5a 6f 6e 65 54 72 61 6e 73 66 65 72 5d 0d 0a   [ZoneTransfer]..
    0000000010: 5a 6f 6e 65 49 64 3d 33 0d 0a                     ZoneId=3..

So, there are two downloaded files, ``conf.txt.zip`` (downloaded on 2016-01-27 09:59:04 UTC) and ``conf.txt (1).zip`` (downloaded on 2016-01-27 10:09:09 UTC).
Both these ZIP files contain a file named ``conf.txt``, which is encrypted.
John The Ripper could be used to crack the password, with zip2john output::

    $ zip2john conf.txt*.zip | tee zip.hashes
    conf.txt (1).zip->conf.txt is using AES encryption, extrafield_length is 11
    conf.txt.zip->conf.txt is using AES encryption, extrafield_length is 11

    $ cat zip.hashes
    conf.txt (1).zip:$zip$*0*1*4cedf3e0f29e38f8*efb7
    conf.txt.zip:$zip$*0*1*cbb9a1dc906a255b*bfc3

    $ john zip.hashes
    Loaded 2 password hashes with 2 different salts (WinZip PBKDF2-HMAC-SHA-1 [32/64])

However John does not find anything in a reasonable time.

At that point, a hint was given to solve the challenge, https://twitter.com/hackinparis/status/695638145396772864::

    #HIPChall n°2 FIRST HINT
    Have fun, Be fair play, enjoy :)

    « A quick analysis of the corporate proxy logs revealed the top 5 domains requested by the suspect in the past 7 days:
    - accounts.google.com
    - www.amazon.fr
    - s000.tinyupload.com
    - www.adobe.com
    - www.youtube.com »
                                Sysdream's team

Using ``strings -tx | grep -C5`` to match the domains with some contextual information reveal several things.

* http://s000.tinyupload.com/ has been used to download the encrypted ZIP files::

    6f579ceb AAC:\Users\lolipop\Downloads\conf.txt (1).zipC:\Users\lolipop\Downloads\conf.txt (1).zip
    6f579d5b http://s000.tinyupload.com/index.php?file_id=05543746886013196000application/force-downloadapplication/force-download
    6f579de5 AAC:\Users\lolipop\Downloads\conf.txt.zipC:\Users\lolipop\Downloads\conf.txt.zip
    6f579e4d http://s000.tinyupload.com/index.php?file_id=15631730723919732671application/force-downloadapplication/force-download

* There are JSON dumps of LastPass structures used for a Google account, but with encrypted passwords::

    16d214d \",\"group\":\"Mail\",\"url\":\"https://accounts.google.com/ServiceLogin?service=mail&continue=https://mail.google.com/mail/&hl=fr#identifier\",\"extra\":\"\",\"fav\":\"0\",\"sharedfromaid\":\"\",\"username\":\"!
    16d2226 bX1\\u008f
    16d2234 \\u008d\\u001f
    16d2251 \\\"\\u001a
    16d2262 \\u0093t
    16d226c RU\\u0006
    16d2277 \",\"password\":\"!
    16d228c \\u0083
    16d2297 =U\\u008eZX
    16d22aa \\u000b
    16d22b3 d|\\u0098T\\n}\\u0014
    16d22ce G\\u0097\\u001aU681\",\"pwprotect\":false,\"genpw\":false,\"sn\":false,\"last_touch\":\"1451489210\",\"autologin\":false
    [...]
    \"1\":{\"otherfield\":false,\"name\":\"Passwd-hidden\",\"type\":\"password\",\"value\":\"!
    [...]
    \"tld\":\"google.com\",\"unencryptedUsername\":\"fla@ndh.com\"

Even if the password is encrypted here, it may be in unencrypted elsewhere.
Let's grep on "Passwd-hidden" input name to be sure::

    $ strings -tx memdump_0x0-0x100000000_20160127-125924.bin |grep -i Passwd-hidden |grep -i value
    12dd784c 53896395004,"uniqid":23476135},"docid":1,"sharedsite":0,"automaticallyFill":1,
    "is_launch":false,"manualfill":false,"name":"Passwd-hidden","value":"totoXXX69!","type":"password",

Bingo :) Even John is happy now::

    $ echo 'totoXXX69!' |john --stdin zip.hashes
    Loaded 2 password hashes with 2 different salts (WinZip PBKDF2-HMAC-SHA-1 [32/64])
    totoXXX69!       (conf.txt.zip)
    totoXXX69!       (conf.txt (1).zip)
    guesses: 2  time: 0:00:00:00  c/s: 10.00  trying: totoXXX69!

The ``conf.txt`` file of ``conf.txt.zip`` archive contains::

    Connexion VPN
    User : d.fla
    Password :
    NDH{33a8c7e18f2be80243bd13b697bf101c7a53f3f30165ffd35d321e8376840caa}

while the one from ``conf.txt (1).zip`` contains::

    Connexion VPN
    User : d.fla
    Password :
    HIP{33a8c7e18f2be80243bd13b697bf101c7a53f3f30165ffd35d321e8376840caa}

(``NDH`` has been replaced with ``HIP`` in the password)

To conclude the flag of the second Hack In Paris challenge is **HIP{33a8c7e18f2be80243bd13b697bf101c7a53f3f30165ffd35d321e8376840caa}**.


Appendix - dump page table entries
----------------------------------

With volatility, it is possible to dump the page tables once the base address (CR3 value on an X86 CPU) is known.
``volatility imageinfo`` gave ``DTB : 0x187000``, which is the base address.
Here is a Python script to dump the page table:

.. include:: chall2/page_table_entries.py
    :code: python

In the result, there are some interesting things for people who enjoy learning low-level operating-system-related materials.

First there is an identity mapping at ``0xfffff800 00000000``, which maps parts of the physical memory.
For example::

    fffff80003800000 (200000) -> 3800000
    fffff80003a00000 (200000) -> 3a00000 <- kdbdg = 0xf80003a4d0a0
    fffff80003c00000 (200000) -> 3c00000
    fffff80003e00000 (200000) -> 3e00000

Next there is a recursive mapping at ``0xfffff6fb7dbed000``.
It can be found because it maps to the DTB::

    fffff6fb7dbed000 (  1000) -> 187000

Moreover, this address is special regarding the page directory decomposition, where each entry is 9-bit long (an address has a 16-bit extension-bit prefix, 4 9-bit indexes and a 12-bit offset in a 4KB page, 16+4*9+12=64 bits)::

    fffff6fb7dbed000
        f68          PGD index = 0x1ed
          7b4        PUD index = 0x1ed
            3da      PMD index = 0x1ed
              1ed    PTE index = 0x1ed

This is due to the fact that on Windows, entry 0x1ed is self-referential.
This also means that addresses beginning with ``fffff6`` in the page table dump are associated to page directory structures.
For example, the leaf containing the Page Table Entry (PTE) for virtual page ``0xfffffffffffe0000`` is::

    $ python -c 'print(hex((0xfffffffffffe0000 & 0xfffffffff000) >> 9 | 0xfffff68000000000))'
    0xfffff6ffffffff00

The dump contains::

    fffff6fffffff000 (  1000) -> 1f4000
    fffffffffffe0000 (  1000) -> fee00000

As ``fffff6ffffffff00`` is offset ``f00`` of page ``fffff6fffffff000``, which is mapped to ``1f4000``, the entry for ``fffffffffffe0000`` is the 8 bytes at ``1f4f00``::

    0001f4f00: 7b01 e0fe 0000 0000

So the PTE is in ``fee0017b``, which means "physical page ``fee00000`` with flags ``17b``" (bits: 0=present, 1=writable, !2=non-userspace, 3=page write through, 4=page cache disabled, 5=accessed, 6=dirty, 8=global).
