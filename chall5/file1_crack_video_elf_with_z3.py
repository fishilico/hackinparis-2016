#!/usr/bin/env python2
import z3

s = z3.Solver()

key = z3.BitVec('K', 42 * 8)

var_800 = [z3.BitVecVal(0, 64) for _ in range(256)]
for i in range(42):
    """
    .text:00000000004008A4                 mov     rax, [rbp+var_i] ; for(i = 0; key[i]; i++) {
    .text:00000000004008AB                 shr     rax, 2
    .text:00000000004008AF                 mov     rcx, rax        ;   rcx = i / 4
    .text:00000000004008B2                 mov     rax, [rbp+var_i]
    .text:00000000004008B9                 shr     rax, 2
    .text:00000000004008BD                 mov     rdx, [rbp+rax*8+var_800] ; rdx = (QWORD)var_800[i/4 * 8]
    .text:00000000004008C5                 mov     rax, rdx
    .text:00000000004008C8                 shl     rax, 2
    .text:00000000004008CC                 add     rax, rdx        ; rax = rdx * 5
    .text:00000000004008CF                 lea     rsi, ds:0[rax*4]
    .text:00000000004008D7                 add     rax, rsi        ; rax = rdx * 25
    .text:00000000004008DA                 shl     rax, 3          ; rax = rdx * 200
    .text:00000000004008DE                 lea     rsi, [rax+rdx]  ; rsi = rdx * 201
    .text:00000000004008E2                 mov     rax, [rbp+var_i]
    .text:00000000004008E9                 mov     rdx, [rbp+var_key]
    .text:00000000004008F0                 add     rax, rdx
    .text:00000000004008F3                 movzx   eax, byte ptr [rax]
    .text:00000000004008F6                 movzx   eax, al
    .text:00000000004008F9                 add     rax, rsi
    .text:00000000004008FC                 mov     [rbp+rcx*8+var_800], rax ;
                                                  ; (QWORD)var_800[i/4 * 8] = ((QWORD)var_800[i/4 * 8]) * 201 + key[i]
    .text:0000000000400904                 add     [rbp+var_i], 1  ; }
    .text:000000000040090C
    """
    key_i = z3.Extract(8 * i + 7, 8 * i, key)
    var_800[i // 4] = z3.simplify(var_800[i // 4] * 201 + z3.ZeroExt(64 - 8, key_i))

s.add(z3.Extract(key.size() - 1, 32 * 8, key) == 0)

s.add(var_800[0x00 // 8] + var_800[0x08 // 8] + var_800[0x10 // 8] + var_800[0x18 // 8] +
      var_800[0x20 // 8] + var_800[0x28 // 8] + var_800[0x30 // 8] == 0x144B7CF31)
s.add(var_800[0x00 // 8] + var_800[0x08 // 8] + var_800[0x10 // 8] + var_800[0x18 // 8] +
      var_800[0x20 // 8] + var_800[0x28 // 8] + var_800[0x30 // 8] + var_800[0x38 // 8] == 0x14502B6BB)
s.add(var_800[0x00 // 8] + var_800[0x08 // 8] + var_800[0x10 // 8] + var_800[0x18 // 8] +
      var_800[0x20 // 8] + var_800[0x28 // 8] + var_800[0x30 // 8] + var_800[0x38 // 8] +
      var_800[0x40 // 8] == 0x14502B6BB)
s.add(var_800[0x00 // 8] + var_800[0x08 // 8] + var_800[0x10 // 8] + var_800[0x18 // 8] == 0x0B7886E5F)
s.add(var_800[0x00 // 8] + var_800[0x08 // 8] + var_800[0x10 // 8] + var_800[0x18 // 8] +
      var_800[0x20 // 8] == 0x0E5CBC367)
s.add(var_800[0x00 // 8] + var_800[0x08 // 8] + var_800[0x10 // 8] + var_800[0x18 // 8] +
      var_800[0x20 // 8] + var_800[0x28 // 8] == 0x1140DDD95)
s.add(var_800[0x00 // 8] == 0x2315B844)
s.add(var_800[0x00 // 8] + var_800[0x08 // 8] == 0x515C27F0)
s.add(var_800[0x00 // 8] + var_800[0x08 // 8] + var_800[0x10 // 8] == 0x7F978390)

while s.check() == z3.sat:
    m = s.model()
    keyval = m[key].as_long()
    s.add(key != keyval)
    keybytes = b''.join([chr((keyval >> i) & 0xff) for i in range(0, key.size(), 8)])
    print(repr(keybytes.rstrip(b'\0')))
