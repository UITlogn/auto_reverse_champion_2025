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
    for i in range(len(s) - 1, -1, -1):
        if "bt" in s[i] and s[i].find("bt") == 32:
            if waiting_for_table == 0:
                waiting_for_table = 1
        if waiting_for_table == 1 and "#" in s[i]:
            waiting_for_table = -1
            x = s[i].split()
            for j in range(len(x)):
                if x[j] == '#':
                    start1 = x[j + 1]
                    end1 = int(start1, 16) + 128
                    cmd = ["objdump", "-s", "--start-address=0x"+start1, "--stop-address="+hex(end1), name]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    k = result.stdout.splitlines()
                    val = k[-1].split()
                    with open(name + '.bittest', 'w') as f:
                        for i in range(4, len(k)):
                            tmp = k[i].split()
                            for j in range(1, 5):
                                f.write(tmp[j])
                            
                    break
        
    
        
