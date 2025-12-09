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

    res = []
    waiting_for_table = 0
    for i in range(len(s)):
        if "dec    %edi" in s[i]:
            with open(name + '.tea', 'w') as f:
                for t in [19, 9, 14, 4]:
                    tmp = s[i - t][42:50]
                    while ',' in tmp: tmp = tmp[:-1]
                    while 'x' in tmp: tmp = tmp[1:]
                    f.write(tmp + ' ')
        
    
        
