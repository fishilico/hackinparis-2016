#!/usr/bin/env python
"""Decrypt the message in the PNG image"""

MESSAGE = """
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
""".replace(' ', '').replace('\n', '')


SUBSTITUTION_SQUARE = """
tdzph
glcbu
v??ni
frmey
sa?wo
""".replace('\n', '')


def lettup2num(lettertuple):
    """Convert a letter tuple to a number"""
    assert len(lettertuple) == 2
    assert lettertuple[0] in 'ABCDE'
    assert lettertuple[1] in 'FGHIJ'
    return (ord(lettertuple[0]) - ord('A')) + (ord(lettertuple[1]) - ord('F')) * 5


def num2lettup(num):
    """Convert a number to a lettre tuple (reciprocal of lettup2num)"""
    assert 0 <= num < 25
    return 'ABCDE'[num % 5] + 'FGHIJ'[num // 5]


# Show the substitution square function
print('   ' + ' '.join(x + '?' for x in 'ABCDE'))
for line in range(5):
    print('?{} {}'.format(
        'FGHIJ'[line],
        ' '.join('{:>2s}'.format(SUBSTITUTION_SQUARE[5 * line + j])
                 for j in range(5))))

msg_num = [lettup2num(MESSAGE[i:i + 2]) for i in range(0, len(MESSAGE), 2)]
cleartext = ''.join(SUBSTITUTION_SQUARE[n] for n in msg_num)
print(cleartext)
