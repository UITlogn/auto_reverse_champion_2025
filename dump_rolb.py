'''
Dấu hiện nhận biết từng section: 
0 AES               cmovns
1 RC4               setb
2 TEA               dec    %edi
3 ROL1              rolb
4 XTEA              dec    %r8d
5 xor               xorb
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
            if opera == 'rolb':
                res = s[i][40:46]
                while ',' in res: res = res[:-1]
                if res[:2] == '0x':
                    res = int(res[2:], 16)
                with open(name + '.rolb', 'w') as f:
                    f.write(str(res))
                break
            elif opera == 'rorb':
                res = s[i][40:46]
                while ',' in res: res = res[:-1]
                if res[:2] == '0x':
                    res = int(res[2:], 16)
                with open(name + '.rolb', 'w') as f:
                    f.write(str(8 - int(res)))
                break
                
