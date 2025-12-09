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

for idx in range(537, 6519):
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

    res = ''
    for i in range(len(s)):
        if "(%rip),%xmm" in s[i]:
            x = s[i].split()
            for j in range(len(x)):
                if x[j] == '#':
                    start1 = x[j + 1]
                    end1 = int(start1, 16) + 16
                    cmd = ["objdump", "-s", "--start-address=0x"+start1, "--stop-address="+hex(end1), name]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    k = result.stdout.splitlines()
                    val = k[-1][:-16].split()
                    for t in range(1, len(val)):
                        res += val[t]
                    break 
    # print(res)
    with open(name + '.keyaes', 'w') as f:
        f.write(res[:32])
    
    with open(name + '.ivaes', 'w') as f:
        f.write(res[32: 64])
    
    with open(name + '.target', 'w') as f:
        f.write(res[64:])
        
