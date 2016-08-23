#!/usr/bin/env python3
"""Decode the ROM of HIP challenge 3"""
import struct
import os.path

with open(os.path.join(os.path.dirname(__file__), 'output.c16'), 'rb') as f:
    DATA = f.read()
ROM = DATA[16:]
assert len(ROM) == 0x22ce

# Hard-code the result of the analysis
COMMENTS = {
    0x0048: 'drawing stars for code...',
    0x011c: 'print good message',
    0x0128: 'draw sprite 50x32 pxls at (50,50)',
    0x014c: 'print bad message',
    0x0178: 'Go to next line',
    0x01c4: 'R11 = col (+= 8 / char), R12 = line',
    0x01c8: 'screen width is 320 px = 40 chars',
    0x01f0: 'R2 = addr 0x0258 in code... (global var?)',

    0x028a: '0x034c = str_array[0] = welcome message',
    0x0296: 'str_array[1] = "Please, enter the password :"',
    0x02a2: 'str_array[2] = "*"',
    0x02ae: 'str_array[3] = "Bad password !"',
    0x02ba: 'str_array[4] = "You lucky bastard."',
    0x0094: 'Print 3 things and continue...',
}
LABELS = {
    # code
    0x0000: 'boot',
    0x0014: 'main__print_welcome_and_prompt',
    0x0024: 'main__input_loop',
    0x009c: 'test_konami_code_88442121_from_stack',
    0x010c: 'set_0_to_r4',
    0x0114: 'show_good_msg',
    0x013c: 'show_failure_msg',

    0x0168: 'draw_str_from_bank[r10]_and_newline',
    0x0184: 'draw_str_from_bank[r10]_and_r3+=1',
    0x019c: 'draw_string_r10',
    0x01e8: 'Play_the_music',
    0x0234: 'sleep(R10)',
    0x025a: 'play_tone_SELFMODCODE(R2)',
    0x0262: 'sleep(R10)',
    0x027a: 'load string messages',

    # data
    0x02ca: "welcome msg",
    0x030b: 'Prompt',
    0x0328: '"*"',
    0x032a: '"Bad password !"',
    0x0339: '"You lucky bastard."',
    0x034c: 'str_array[0]',
    0x034e: 'str_array[1]',
    0x0350: 'str_array[2]',
    0x0352: 'font_bitmap',
    0x0f52: 'sound_data',
    0x1c8e: 'image_win',

    0xfff0: 'I/O input'
}


def lbl(addr):
    txt = "{:#06x}".format(addr)
    if addr in LABELS:
        txt += '<' + LABELS[addr] + '>'
    else:
        txt += '<?>'
    return txt

# At 2ca: "Hack In Paris - CHIP16"... header
pc = 0
while pc < 0x2ca:
    inst = ROM[pc:pc+4]
    desc = '??'

    HHLL = struct.unpack('<H', inst[2:])[0]
    X = inst[1] & 0xf
    Y = inst[1] >> 4
    Z = inst[2] & 0xf

    # Use instructions from https://github.com/chip16/chip16/wiki/Instructions
    """
    0x - Misc/Video/Audio

    Opcode (Hex)	Mnemonic	Usage	Flags affected	Introduced
    00 00 00 00	NOP	No operation.		0.8
    01 00 00 00	CLS	Clear FG, BG = 0.		0.8
    02 00 00 00	VBLNK	Wait for VBlank. If (!vblank) PC -= 4;		0.8
    03 00 0N 00	BGC N	Set background color to index N (0 is black).		0.8
    04 00 LL HH	SPR HHLL	Set sprite width (LL) and height (HH).		0.8
    05 YX LL HH	DRW RX, RY, HHLL	Draw sprite from address HHLL at (RX, RY).	C	0.8
    06 YX 0Z 00	DRW RX, RY, RZ	Draw sprite from [RZ] at (RX, RY).	C	0.8
    07 0X LL HH	RND RX, HHLL	Store random number in RX (max. HHLL).		0.8
    08 00 00 00	FLIP 0, 0	Set hflip = false, vflip = false		0.8
    08 00 00 01	FLIP 0, 1	Set hflip = false, vflip = true		0.8
    08 00 00 02	FLIP 1, 0	Set hflip = true, vflip = false		0.8
    08 00 00 03	FLIP 1, 1	Set hflip = true, vflip = true		0.8
    09 00 00 00	SND0	Stop playing sounds.		0.8
    0A 00 LL HH	SND1 HHLL	Play 500Hz tone for HHLL ms.		0.8
    0B 00 LL HH	SND2 HHLL	Play 1000Hz tone for HHLL ms.		0.8
    0C 00 LL HH	SND3 HHLL	Play 1500Hz tone for HHLL ms.		0.8
    0D 0X LL HH	SNP RX, HHLL	Play tone from RX for HHLL ms.		1.1
    0E AD SR VT	SNG AD, VTSR	Set sound generation parameters.		1.1
    """
    if inst[0] == 1:
        desc = 'Clear Screen'
    if inst[0] == 2:
        desc = 'Wait for VBlank'
    if inst[0] == 3:
        desc = 'Set BG color to {}'.format(inst[2])
    if inst[0] == 4:
        desc = 'Set sprite to HxW {:#06x}'.format(HHLL)
    if inst[0] == 5:
        desc = 'Draw sprite from {} at (R{}, R{})'.format(lbl(HHLL), X, Y)
    if inst[0] == 6:
        desc = 'Draw sprite from R{} at (R{}, R{})'.format(Z, X, Y)
    if inst[0] == 0xd:
        desc = 'Play tone from R{} for {} ms'.format(X, HHLL)
    if inst[0] == 0xe:
        desc = 'Set sound generation parameters: AD={:#x}, VTSR={:#x}'.format(inst[1], HHLL)

    """
    1x - Jumps (Branches)

    Opcode (Hex)	Mnemonic	Usage	Flags affected	Introduced
    10 00 LL HH	JMP HHLL	Set PC to HHLL.		0.8
    11 00 LL HH	JMC HHLL	Jump to the specified address if carry flag is raised.		0.8
    12 0x LL HH	Jx HHLL	If x, then perform a JMP.		0.9
    13 YX LL HH	JME RX, RY, HHLL	Set PC to HHLL if RX == RY.		0.8
    14 00 LL HH	CALL HHLL	Store PC to [SP], increase SP by 2, set PC to HHLL.		0.8
    15 00 00 00	RET	Decrease SP by 2, set PC to [SP].		0.8
    16 0X 00 00	JMP RX	Set PC to RX.		0.8
    17 0x LL HH	Cx HHLL	If x, then perform a CALL.		0.9
    18 0X 00 00	CALL RX	Store PC to [SP], increase SP by 2, set PC to RX.		0.8
    """
    if inst[0] == 0x10:
        desc = 'jmp {}'.format(lbl(HHLL))
    if inst[:2] == b'\x14\0':
        desc = 'call {}'.format(lbl(HHLL))
    if inst == b'\x15\0\0\0':
        desc = 'return'
    if inst[0] == 0x12:
        desc = 'if cond{}, jmp {}'.format(inst[1], lbl(HHLL))
    if inst[0] == 0x17:
        desc = 'if cond{}, call {}'.format(inst[1], lbl(HHLL))

    """
    2x - Loads

    Loads from memory are always 16-bit.

    Opcode (Hex)	Mnemonic	Usage	Flags affected	Introduced
    20 0X LL HH	LDI RX, HHLL	Set RX to HHLL.		0.8
    21 00 LL HH	LDI SP, HHLL	Set SP to HHLL.		0.8
    22 0X LL HH	LDM RX, HHLL	Set RX to [HHLL].		0.8
    23 YX 00 00	LDM RX, RY	Set RX to [RY].		0.8
    24 YX 00 00	MOV RX, RY	Set RX to RY.		0.8
    """
    if inst[0] == 0x20:
        desc = 'R{} <- {:#06x}'.format(X, HHLL)
    if inst[0] == 0x22:
        desc = 'R{} <- *[{}]'.format(X, lbl(HHLL))
    if inst[0] == 0x23:
        desc = 'R{} <- *[R{}]'.format(X, Y)
    if inst[0] == 0x24:
        desc = 'R{} <- R{}'.format(X, Y)

    """
    3x - Stores

    Opcode (Hex)	Mnemonic	Usage	Flags affected	Introduced
    30 0X LL HH	STM RX, HHLL	Set [HHLL] to RX.		0.8
    31 YX 00 00	STM RX, RY	Set [RY] to RX.		0.8
    """
    if inst[0] == 0x31:
        desc = '*[R{}] <- R{}'.format(inst[1] >> 4, inst[1] & 0xf)

    """
    4x - Addition

    Opcode (Hex)	Mnemonic	Usage	Flags affected	Introduced
    40 0X LL HH	ADDI RX, HHLL	Set RX to RX+HHLL.	CZON	0.8
    41 YX 00 00	ADD RX, RY	Set RX to RX+RY.	CZON	0.8
    42 YX 0Z 00	ADD RX, RY, RZ	Set RZ to RX+RY.	CZON	0.8
    """
    if inst[0] == 0x40:
        desc = 'R{} += {:#06x}'.format(inst[1], HHLL)

    """
    5x - Subtraction

    Opcode (Hex)	Mnemonic	Usage	Flags affected	Introduced
    50 0X LL HH	SUBI RX, HHLL	Set RX to RX-HHLL.	CZON	0.8
    51 YX 00 00	SUB RX, RY	Set RX to RX-RY.	CZON	0.8
    52 YX 0Z 00	SUB RX, RY, RZ	Set RZ to RX-RY.	CZON	0.8
    53 0X LL HH	CMPI RX, HHLL	Compute RX-HHLL, discard result.	CZON	0.8
    54 YX 00 00	CMP RX, RY	Compute RX-RY, discard result.	CZON	0.8
    """
    if inst[0] == 0x50:
        desc = 'R{} -= {:#06x}'.format(inst[1], HHLL)
    if inst[0] == 0x53:
        desc = 'Cmp(R{} - {:#06x})'.format(inst[1], HHLL)

    """
    6x - Bitwise AND (&)

    Opcode (Hex)	Mnemonic	Usage	Flags affected	Introduced
    60 0X LL HH	ANDI RX, HHLL	Set RX to RX&HHLL.	ZN	0.8
    61 YX 00 00	AND RX, RY	Set RX to RX&RY.	ZN	0.8
    62 YX 0Z 00	AND RX, RY, RZ	Set RZ to RX&RY.	ZN	0.8
    63 0X LL HH	TSTI RX, HHLL	Compute RX&HHLL, discard result.	ZN	0.8
    64 YX 00 00	TST RX, RY	Compute RX&RY, discard result.	ZN	0.8
    """
    if inst[0] == 0x60:
        desc = 'R{} &= {:#06x}'.format(inst[1], HHLL)
    if inst[0] == 0x62:
        desc = 'R{} = R{} & R{}'.format(inst[2], inst[1] & 0xf, inst[1] >> 4)
    if inst[0] == 0x63:
        desc = 'Test(R{} & {:#06x})'.format(inst[1], HHLL)

    """
    7x - Bitwise OR (|)

    Opcode (Hex)	Mnemonic	Usage	Flags affected	Introduced
    70 0X LL HH	ORI RX, HHLL	Set RX to RX|HHLL.	ZN	0.8
    71 YX 00 00	OR RX, RY	Set RX to RX|RY.	ZN	0.8
    72 YX 0Z 00	OR RX, RY, RZ	Set RZ to RX|RY.	ZN	0.8
    """

    """
    8x - Bitwise XOR (^)

    Opcode (Hex)	Mnemonic	Usage	Flags affected	Introduced
    80 0X LL HH	XORI RX, HHLL	Set RX to RX^HHLL.	ZN	0.8
    81 YX 00 00	XOR RX, RY	Set RX to RX^RY.	ZN	0.8
    82 YX 0Z 00	XOR RX, RY, RZ	Set RZ to RX^RY.	ZN	0.8
    9x - Multiplication

    Opcode (Hex)	Mnemonic	Usage	Flags affected	Introduced
    90 0X LL HH	MULI RX, HHLL	Set RX to RX*HHLL	CZN	1.1
    91 YX 00 00	MUL RX, RY	Set RX to RX*RY	CZN	0.8
    92 YX 0Z 00	MUL RX, RY, RZ	Set RZ to RX*RY	CZN	0.8
    """
    if inst[0] == 0x90:
        desc = 'R{} *= {:#06x}'.format(X, HHLL)

    """
    Ax - Division

    Opcode (Hex)	Mnemonic	Usage	Flags affected	Introduced
    A0 0X LL HH	DIVI RX, HHLL	Set RX to RX/HHLL	CZN	0.8
    A1 YX 00 00	DIV RX, RY	Set RX to RX/RY	CZN	0.8
    A2 YX 0Z 00	DIV RX, RY, RZ	Set RZ to RX/RY	CZN	0.8
    A3 0X LL HH	MODI RX, HHLL	Set RX to RX MOD HHLL	ZN	1.3
    A4 YX 00 00	MOD RX, RY	Set RX to RX MOD RY	ZN	1.3
    A5 YX 0Z 00	MOD RX, RY, RZ	Set RZ to RX MOD RY	ZN	1.3
    A6 0X LL HH	REMI RX, HHLL	Set RX to RX % HHLL	ZN	1.3
    A7 YX 00 00	REM RX, RY	Set RX to RX % RY	ZN	1.3
    A8 YX 0Z 00	REM RX, RY, RZ	Set RZ to RX % RY	ZN	1.3
    """
    if inst[0] == 0xa0:
        desc = 'R{} /= {:#06x}'.format(X, HHLL)

    """
    Bx - Logical/Arithmetic Shifts

    Opcode (Hex)	Mnemonic	Usage	Flags affected	Introduced
    B0 0X 0N 00	SHL RX, N	Set RX to RX << N	ZN	0.8
    B1 0X 0N 00	SHR RX, N	Set RX to RX >> N	ZN	0.8
    B0 0X 0N 00	SAL RX, N	Set RX to RX << N	ZN	0.8
    B2 0X 0N 00	SAR RX, N	Set RX to RX >> N, copying leading bit	ZN	0.8
    B3 YX 00 00	SHL RX, RY	Set RX to RX << RY	ZN	0.8
    B4 YX 00 00	SHR RX, RY	Set RX to RX >> RY	ZN	0.8
    B3 YX 00 00	SAL RX, RY	Set RX to RX << RY	ZN	0.8
    B5 YX 00 00	SAR RX, RY	Set RX to RX >> RY, copying leading bit	ZN	0.8

    Note that a left arithmetic shift is a left logical shift, since we are not expanding the leading bit.
    Hence SAL is syntactic sugar, and maps to its corresponding SHL opcode.
    """

    """
    Cx - Push/Pop

    Opcode (Hex)	Mnemonic	Usage	Flags affected	Introduced
    C0 0X 00 00	PUSH RX	Set [SP] to RX, increase SP by 2		0.8
    C1 0X 00 00	POP RX	Decrease SP by 2, set RX to [SP]		0.8
    C2 00 00 00	PUSHALL	Store R0..RF at [SP], increase SP by 32		0.8
    C3 00 00 00	POPALL	Decrease SP by 32, load R0..RF from [SP]		0.8
    C4 00 00 00	PUSHF	Set [SP] to FLAGS, increase SP by 2		1.1
    C5 00 00 00	POPF	Decrease SP by 2, set FLAGS to [SP]		1.1
    """
    if inst[0] == 0xc0:
        desc = 'push R{}'.format(inst[1])
    if inst[0] == 0xc1:
        desc = 'pop R{}'.format(inst[1])

    """
    Dx - Palette

    Opcode (Hex)	Mnemonic	Usage	Flags affected	Introduced
    D0 00 LL HH	PAL HHLL	Load palette from [HHLL]		1.1
    D1 0X 00 00	PAL RX	Load palette from [RX]		1.1
    """

    """
    Ex - Not/Neg

    Opcode	Mnemonic	Meaning	Flags affected	Introduced
    E0 0X LL HH	NOTI RX, HHLL	Set RX to NOT HHLL	ZN	1.3
    E1 0X 00 00	NOT RX	Set RX to NOT RX	ZN	1.3
    E2 YX 00 00	NOT RX, RY	Set RX to NOT RY	ZN	1.3
    E3 0X LL HH	NEGI RX, HHLL	Set RX to NEG HHLL	ZN	1.3
    E4 0X 00 00	NEG RX	Set RX to NEG RX	ZN	1.3
    E5 YX 00 00	NEG RX, RY	Set RX to NEG RY	ZN	1.3
    """

    if pc in COMMENTS:
        desc += ' ; ' + COMMENTS[pc]

    if pc in LABELS:
        print('\n' + LABELS[pc] + ':')
    print("  {:04x}: {}    {}".format(pc, ' '.join('{:02x}'.format(x) for x in inst), desc))

    if pc in (0x258, 0x278,):
        pc += 2
    else:
        pc += 4

# Then hexdump things
while pc < len(ROM):
    if pc in LABELS:
        print(LABELS[pc] + ':')

    linelen = 1

    if 0x0352 <= pc < 0x0f52:
        # Font data
        linelen = 4
        linedata = ROM[pc:pc+linelen]
        FONT_BYTES = {
            0x11: '  ',
            0x1f: ' #',
            0xf1: '# ',
            0xff: '##',
        }
        desc = ''.join(FONT_BYTES.get(x, '?' + str(x)) for x in linedata)
        print("  {:04x}: {}  font<{}>  '{}'".format(
            pc,
            ' '.join('{:02x}'.format(x) for x in linedata),
            repr(chr(32 + (pc - 0x0352) // 32)), desc))
    elif 0x0f52 <= pc < 0x1c8e:
        # Music data
        linelen = 4
        linedata = ROM[pc:pc+linelen]
        pitch, dur = struct.unpack('<HH', linedata)
        print("  {:04x}: {}  music<{:5d} Hz, {:5d} ms>".format(
            pc,
            ' '.join('{:02x}'.format(x) for x in linedata), pitch, dur))
    elif 0x1c8e <= pc < 0x22ce:
        # Win image
        linelen = 50
        linedata = ROM[pc:pc+linelen]
        print("  {:04x}: {}".format(
            pc,
            ''.join('{:02x}'.format(x) for x in linedata)))
    else:
        # Default
        while linelen < 32 and pc + linelen < len(ROM) and (pc + linelen) not in LABELS:
            linelen += 1
        # print("  {:04x}: {}".format(pc, ' '.join('{:02x}'.format(x) for x in ROM[pc:pc+linelen])))
        print("  {:04x}: {}".format(pc, repr(ROM[pc:pc+linelen])))

    pc += linelen
