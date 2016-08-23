#!/usr/bin/env python3
"""Decode the bytecode instructions of chall.bin"""
import struct

with open('chall.bin', 'rb') as f:
    FILEDATA = f.read()

# Instructions at .rodata:402280
# Data at .rodata:41A920
# file offset 0x400000
VMCODE = FILEDATA[0x2280:0x2280 + 100000].rstrip(b'\0')
VMDATA = FILEDATA[0x1A920:0x1A920 + 43850]
assert 0x2280 + 100000 == 0x1A920


def decode_opcode_arg(pc, arg_id):
    """Decode argument arg_id for the given instruction"""
    assert arg_id in (0, 1)
    # Retrieve the specification of the operand kind
    opspec = VMCODE[pc + 1]
    if arg_id == 0:
        opspec = (opspec >> 4) & 0xf
    else:
        opspec = opspec & 0xf
    mempos = pc + 2 + 4 * arg_id
    if opspec == 1:
        dw = struct.unpack('<I', VMCODE[mempos:mempos+4])[0]
        return '{:#06x}'.format(dw)
    elif opspec == 2:
        regid = VMCODE[mempos]
        assert 0 <= regid < 10
        return 'r{}'.format(regid)
    elif opspec == 4:
        regid = VMCODE[mempos]
        assert 0 <= regid < 10
        return '*r{}'.format(regid)
    assert False


OP2_LIST = ('|', '^', '&', '+', '-', '*', '/', '%', '<<', '>>')
OP1_LIST = ('push', 'pop', 'call')
OP0_LIST = ('ret', 'read', 'write')

pc = 0
while pc < len(VMCODE):
    opcode = VMCODE[pc] & 0xf
    desc = 'opcode({:#x})'.format(opcode)

    if opcode <= 9:
        instrlen = 10
        arg0 = decode_opcode_arg(pc, 0)
        arg1 = decode_opcode_arg(pc, 1)
        desc = '{} {}= {}'.format(arg0, OP2_LIST[opcode], arg1)
    elif opcode <= 0xc:
        instrlen = 6
        arg = decode_opcode_arg(pc, 0)
        desc = '{} {}'.format(OP1_LIST[opcode - 0xa], arg)
    else:
        instrlen = 1
        desc = OP0_LIST[opcode - 0xd]

    if VMCODE[pc] & 0x10:
        desc = 'if(SF) ' + desc
    if VMCODE[pc] & 0x20:
        desc = 'if(ZF) ' + desc
    print("{:04x}: {:30} {}".format(
        pc, ' '.join('{:02x}'.format(x) for x in VMCODE[pc:pc+instrlen]), desc))
    pc += instrlen

# Decrypt data
cleardata = bytearray(len(VMDATA))
for i, x in enumerate(VMDATA):
    cleardata[i] = x ^ (i % 100)

with open('decoded_vmdata.out.txt', 'w') as f:
    f.write(cleardata.decode('ascii').replace(' ', '\n'))

# Convert to brainfuck
BFTRANS = '+-<>[].,'
BFDATA = [None] * len(cleardata)
for i, x in enumerate(cleardata):
    if x == 0x20 or x == 10:
        BFDATA[i] = 'EXIT({})\n'.format(x)
    else:
        BFDATA[i] = BFTRANS[int(cleardata[i:i+1].decode('ascii'), 16) // 2]

with open('decoded_bfdata.out.txt', 'w') as f:
    f.write(''.join(BFDATA))
