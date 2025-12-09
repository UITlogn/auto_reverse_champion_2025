'''
Dấu hiện nhận biết từng section: 
0 AES               cmovns
1 RC4               setb
2 TEA               dec    %edi
3 ROL1/ROR1         rolb/rorb
4 XTEA              dec    %r8d
5 xor               xorb/notb
6 swap(ROL2)        rolw
7 bitmask           bt
8 permutation       setne
'''
import subprocess

for idx in range(6519):
    name = str(idx)
    while len(name) < 3: name = '0' + name
    name = 'reze_' + name
    
    cmd = ["objdump", "-d", "--disassemble=main", name]
    result = subprocess.run(cmd, capture_output=True, text=True)
    s = result.stdout.splitlines()
    realmain = s[10].split()[-1]
    
    cmd = ["objdump", "-d", "--disassemble="+realmain[1:-1], name]
    result = subprocess.run(cmd, capture_output=True, text=True)
    s = result.stdout.splitlines()

    pos = [(0, i) for i in range(9)]

    for i in range(10, len(s)):
        if len(s[i]) >= 32 and s[i][8] == ':':
            x = 32
            while x < len(s[i]) and s[i][x] != ' ':
                x += 1
            opera = s[i][32:x]
            # print(opera)
            if opera == 'cmovns': pos[0] = (i, 0)
            if opera == 'setb': pos[1] = (i, 1)
            if 'dec    %edi' in s[i]: pos[2] = (i, 2)
            if opera == 'rolb': pos[3] = (i, 3)
            if opera == 'rorb': pos[3] = (i, 3)
            if 'dec    %r8d' in s[i]: pos[4] = (i, 4)
            if opera == 'xorb': pos[5] = (i, 5)
            if opera == 'notb': pos[5] = (i, 5)
            if opera == 'rolw': pos[6] = (i, 6)
            if opera == 'bt': pos[7] = (i, 7)
            if opera == 'setne': pos[8] = (i, 8)

    pos.sort()
    # print(pos)

    flow = []
    for i in range(len(pos)):
        flow.append(pos[i][1])
        if pos[i][0] == 0:
            print('???')
        
    with open(name + '.flow', 'w') as f:
        for i in range(len(flow)-1, -1, -1):
            f.write(str(flow[i]) + ' ')
