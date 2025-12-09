from Crypto.Cipher import AES
import struct
from Crypto.Cipher import ARC4
import subprocess

def aes_ctr_rust(key: bytes, nonce: bytes, data: bytes, counter_endian: str = "big") -> bytes:
    aes = AES.new(key, AES.MODE_ECB)
    counter = bytearray(nonce)
    out = bytearray()
    pos = 0
    n = len(data)
    while pos < n:
        keystream = aes.encrypt(bytes(counter))
        chunk = data[pos:pos+16]
        for i, b in enumerate(chunk):
            out.append(b ^ keystream[i])
        pos += 16

        if counter_endian == "little":
            for i in range(16):
                counter[i] = (counter[i] + 1) & 0xFF
                if counter[i] != 0:
                    break
        else:
            for i in range(15, -1, -1):
                counter[i] = (counter[i] + 1) & 0xFF
                if counter[i] != 0:
                    break

    return bytes(out)

def decrypt_Aes(iv, key, ciphertext):
    p = aes_ctr_rust(key, iv, ciphertext, counter_endian="big")
    return p

# iv = bytes.fromhex("9269D20F44D9232C2BEEBBA87AC47BB7")[::-1]
# key = bytes.fromhex("EC36452F5D9319DC653374E963334B76")[::-1]
# ciphertext = bytes.fromhex("15568527A1FF60928701696C407A402B")[::-1] + bytes.fromhex("344DF3AD05929D449815B52910A125EF")[::-1]

# print(" ".join(f"{x:02X}" for x in ciphertext))

# print(" ".join(f"{x:02X}" for x in Aes(iv, key, ciphertext)))


# C1 69 D8 C3 CF 9B 6A 47 03 3C A7 A6 CB 0E ED E5 9B 1C A5 CD 00 95 FB 67 22 36 9B 84 98 D1 9A F8



def decrypt_rc4(cipher: bytearray, key: bytes):
    c = ARC4.new(key)
    p = c.decrypt(cipher)
    return p

# key = bytes.fromhex("E7 E5 99 70 F0 14 2E 4D A0 A9 18 3F EF CE 37 95")
# c = bytes.fromhex("6C 8C 5A EF 7A AC 59 BA 49 A6 F4 81 D6 67 0B E7 C6 51 B4 E8 5E 4B A9 B7 8C DB 43 0C 62 F7 38 64")
# p = rc4_custom_decrypt(c, key)
# print(" ".join(f"{x:02X}" for x in p))











MASK32 = 0xFFFFFFFF

def _u32(x: int) -> int:
    return x & MASK32

def decrypt_block(ct8: bytes, C) -> bytes:
    assert len(ct8) == 8
    v30 = int.from_bytes(ct8[0:4], 'little')
    v31 = int.from_bytes(ct8[4:8], 'little')
    START = 0x9E3779B9
    DELTA = 0x61C88647

    v32 = _u32(START - (_u32(DELTA * 32)))

    for _ in range(32):
        v32 = _u32(v32 + DELTA)

        g = _u32(( (16 * v30 + C[1]) ^ _u32(v32 + v30) ^ _u32((v30 >> 5) + C[3]) ))
        v31 = _u32(v31 - g)

        f = _u32(( (16 * v31 + C[0]) ^ _u32(v31 + v32) ^ _u32((v31 >> 5) + C[2]) ))
        v30 = _u32(v30 - f)

    return v30.to_bytes(4, 'little') + v31.to_bytes(4, 'little')

def decrypt_TEA(ciphertext: bytes, C) -> bytes:
    """Giải 32-byte ciphertext (4 block x 8 bytes) và trả về 32-byte plaintext."""
    assert len(ciphertext) == 32
    out = bytearray()
    for off in (0, 8, 16, 24):
        block = ciphertext[off:off+8]
        out.extend(decrypt_block(block, C))
    return bytes(out)

# ct_hex = "06 D0 DB B1 D8 14 F6 23 A8 EE C2 B7 25 E4 2D C6 5C 36 4B 4B 9F 39 C1 8C 61 1D E0 CE 26 C9 91 EE"
# ct = bytes.fromhex(ct_hex)
# pt = decrypt_all(ct)
# in hex cặp phân tách bằng space
# print(" ".join(f"{b:02X}" for b in pt))








def ror1(x, r):
    return ((x >> r) | ((x << (8 - r)) & 0xFF)) & 0xFF

def decrypt_ROL1(buf, step):
    res = bytearray()
    for k in range(32):
        res.append(ror1(buf[k], step))
    return res

# c = bytes.fromhex('49 C9 5A B3 79 16 03 60 39 98 D1 C2 77 E4 62 02 B0 12 6D CF 0C 0D FB A1 4F 9D 4B 08 49 93 0D E6')
# p = reverseROL1(c)
# print(" ".join(f"{b:02X}" for b in p))







MASK32 = 0xFFFFFFFF
DELTA = 0x61C88647  # 1640531527


def rol32(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK32

def u32(x):
    return x & MASK32

def decrypt_block_pair(v0: int, v1: int, T):
    v24 = u32((-32 * DELTA) & MASK32)
    v0 = u32(v0)
    v1 = u32(v1)

    for _ in range(32):
        offset = (v24 >> 9) & 0xC
        idx2 = offset // 4
        t2 = T[idx2]

        part_v0 = ( (16 * v0) ^ (v0 >> 5) ) & MASK32
        expr1 = u32((v0 + part_v0) & MASK32)
        expr2 = u32(( (v24 + t2) & MASK32 ))
        v1 = u32((v1 - (expr1 ^ expr2)) & MASK32)

        byte_v24 = v24 & 0xFF
        idx1 = ( (byte_v24 + 71) & 3 )
        t1 = T[idx1]

        part_v1 = ( (16 * v1) ^ (v1 >> 5) ) & MASK32
        expr3 = u32((v1 + part_v1) & MASK32)
        expr4 = u32((t1 + v24 + DELTA) & MASK32)
        v0 = u32((v0 - (expr3 ^ expr4)) & MASK32)

        v24 = u32((v24 + DELTA) & MASK32)

    return v0, v1

def decrypt_XTEA(cipher32: bytes, T) -> bytes:
    assert len(cipher32) == 32
    out = bytearray(32)
    for i in range(4):
        off = i * 8
        v0 = int.from_bytes(cipher32[off:off+4], 'little')
        v1 = int.from_bytes(cipher32[off+4:off+8], 'little')
        p0, p1 = decrypt_block_pair(v0, v1, T)
        out[off:off+4] = p0.to_bytes(4, 'little')
        out[off+4:off+8] = p1.to_bytes(4, 'little')
    return bytes(out)

# c = bytes.fromhex('29 39 4B 76 2F C2 60 0C 27 13 3A 58 EE 9C 4C 40 16 42 AD F9 81 A1 7F 34 E9 B3 69 01 29 72 A1 DC')
# p = decrypt_XTEA(c)
# print(" ".join(f"{b:02X}" for b in p))





def decrypt_xor(x, val):
    res = bytearray()
    for k in range(32):
        res.append(x[k] ^ val)
    return res
# c = bytes.fromhex('D5 D0 82 82 CB 88 C6 87 10 D0 8A C4 04 2F CE 62 55 F8 20 A5 1A 88 F2 14 3E F2 E2 53 5B 54 D0 2B')
# p = decrypt_xor(c, 0xDD)
# print(" ".join(f"{b:02X}" for b in p))





def decrypt_swapROL2(x):
    res = bytearray()
    for k in range(0, 32, 2):
        res.append(x[k + 1])
        res.append(x[k])
    return res
# c = bytes.fromhex('08 0D 5F 5F 16 55 1B 5A CD 0D 57 19 D9 F2 13 BF 88 25 FD 78 C7 55 2F C9 E3 2F 3F 8E 86 89 0D F6')
# p = decrypt_swapROL2(c)
# print(" ".join(f"{b:02X}" for b in p))
    
    







# import struct
# arr1_hex = '01 00 00 00 02 00 00 00 05 00 00 00 0D 00 00 00 13 00 00 00 24 00 00 00 4E 00 00 00 AD 00 00 00 08 01 00 00 A8 02 00 00 2D 04 00 00 B3 0D 00 00 A4 1D 00 00 31 2A 00 00 0B 5D 00 00 CF A9 00 00 C6 DB 01 00 CE 4E 03 00 2A F7 05 00 C2 75 0F 00 59 0D 1A 00 37 0A 3E 00 06 E2 61 00 D7 34 BB 00 EB B9 A0 01 90 FD 66 03 32 A0 FB 04 58 B4 BB 08 A4 DE E3 14 B4 E0 EF 25 63 4A 4C 57 21 03 EE 81'
# arr1_raw = bytes.fromhex(arr1_hex)
# ARR1 = [struct.unpack('<I', arr1_raw[i:i+4])[0] for i in range(0, len(arr1_raw), 4)]
def decrypt_bitmask(ARR1, output):
    M = [[(ARR1[row] >> col) & 1 for col in range(32)] for row in range(32)]
    b = [o for o in output]

    for col in range(32):
        pivot = None
        for row in range(col, 32):
            if M[row][col]:
                pivot = row
                break
        if pivot is None:
            raise Exception("Ma trận không khả nghịch — arr1 không full-rank!")

        M[col], M[pivot] = M[pivot], M[col]
        b[col], b[pivot] = b[pivot], b[col]

        for row in range(32):
            if row != col and M[row][col]:
                for k in range(col, 32):
                    M[row][k] ^= M[col][k]
                b[row] ^= b[col]

    return bytes(b)
                
# c = bytes.fromhex('0D 08 5F 5F 55 16 5A 1B 0D CD 19 57 F2 D9 BF 13 25 88 78 FD 55 C7 C9 2F 2F E3 8E 3F 89 86 F6 0D')
# p = decrypt_bitmask(c)
# print(" ".join(f"{b:02X}" for b in p))
                
                
                
# permu_hex = '0B 00 00 00 00 00 00 00 18 00 00 00 00 00 00 00 0F 00 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 0E 00 00 00 00 00 00 00 11 00 00 00 00 00 00 00 1B 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 12 00 00 00 00 00 00 00 0C 00 00 00 00 00 00 00 1E 00 00 00 00 00 00 00 15 00 00 00 00 00 00 00 17 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 1A 00 00 00 00 00 00 00 14 00 00 00 00 00 00 00 0D 00 00 00 00 00 00 00 19 00 00 00 00 00 00 00 05 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 1D 00 00 00 00 00 00 00 09 00 00 00 00 00 00 00 16 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00 03 00 00 00 00 00 00 00 1F 00 00 00 00 00 00 00 07 00 00 00 00 00 00 00 13 00 00 00 00 00 00 00 1C 00 00 00 00 00 00 00'
# permu_raw = bytes.fromhex(permu_hex)
# PERMUTATION = [struct.unpack('<Q', permu_raw[i:i+8])[0] for i in range(0, len(permu_raw), 8)]     
def decrypt_permutation(permutation, encrypted):
    assert len(permutation) == 32
    assert len(encrypted) == 32

    perm_inv = [0] * 32
    for i in range(32):
        p = permutation[i]
        if p >= 32:
            raise Exception("Invalid permutation element")
        perm_inv[p] = i

    raw = [0] * 32
    for raw_idx in range(32):
        enc_idx = perm_inv[raw_idx]
        raw[raw_idx] = encrypted[enc_idx]

    return bytes(raw)

# encrypted = bytes.fromhex('0D 08 52 00 50 44 00 00 0D 89 02 49 A2 00 5E 00 4E 00 00 48 06 0A 00 82 00 03 1A 47 7D 0A 05 00')
# inp = decrypt_permutation(PERMUTATION, encrypted)

# print(inp)


flag = b''

def Solve(idx, tryswap_target):
    name = str(idx)
    while len(name) < 3: name = '0' + name
    name = 'reze_' + name
    
    print(name)
    # ciphertext = bytes.fromhex("15568527A1FF60928701696C407A402B")[::-1] + bytes.fromhex("344DF3AD05929D449815B52910A125EF")[::-1]
    # iv = bytes.fromhex("9269D20F44D9232C2BEEBBA87AC47BB7")[::-1]
    # key = bytes.fromhex("EC36452F5D9319DC653374E963334B76")[::-1]
    # keyrc4 = bytes.fromhex("E7 E5 99 70 F0 14 2E 4D A0 A9 18 3F EF CE 37 95")
    
    ciphertext = bytes.fromhex(open(name+'.target').read())
    iv = bytes.fromhex(open(name+'.ivaes').read())
    key = bytes.fromhex(open(name+'.keyaes').read())
    keyrc4 = bytes.fromhex(open(name+'.keyrc4').read())
    flow = list(map(int, open(name+'.flow').read().split()))
    arr1_raw = bytes.fromhex(open(name+'.bittest').read())
    permu_raw = bytes.fromhex(open(name+'.permu').read())
    XOR_VAL = int(open(name+'.xorb').read(), 16)
    ROL1_VAL = int(open(name+'.rolb').read())
    arrXTEA = bytes.fromhex(open(name+'.xtea').read())
    arrTEA = open(name+'.tea').read().split()
    C = [int(i, 16) for i in arrTEA]
    T = [struct.unpack('<I', arrXTEA[i:i+4])[0] for i in range(0, len(arrXTEA), 4)]
    
    
    if (tryswap_target):
        ciphertext = ciphertext[16:] + ciphertext[:16]
        
    
    ARR1 = [struct.unpack('<I', arr1_raw[i:i+4])[0] for i in range(0, len(arr1_raw), 4)]
    PERMUTATION = [struct.unpack('<Q', permu_raw[i:i+8])[0] for i in range(0, len(permu_raw), 8)]   
    x = ciphertext
    for i in range(9):
        if flow[i] == 0:
            x = decrypt_Aes(iv, key, x)
        elif flow[i] == 1:
            x = decrypt_rc4(x, keyrc4)
        elif flow[i] == 2:    
            x = decrypt_TEA(x, C)
        elif flow[i] == 3:    
            x = decrypt_ROL1(x, ROL1_VAL)
        elif flow[i] == 4:    
            x = decrypt_XTEA(x, T)
        elif flow[i] == 5:    
            x = decrypt_xor(x, XOR_VAL)
        elif flow[i] == 6:    
            x = decrypt_swapROL2(x)
        elif flow[i] == 7:    
            x = decrypt_bitmask(ARR1, x)
        elif flow[i] == 8:    
            x = decrypt_permutation(PERMUTATION, x)
    
        # print(" ".join(f"{b:02X}" for b in x[:16]))
        # print(" ".join(f"{b:02X}" for b in x[16:]))


    result = subprocess.run(
        ["./" + name],
        input=x,              
        capture_output=True
    )
    
    if b"Correct" not in result.stdout:
        if tryswap_target == 0:
            tmp = Solve(idx, 1)
            if tmp == 0:
                print("Wrong")
                exit(0)
        else:
            print("Wrong")
            exit(0)
    
    # with open(name + '.res', 'w') as f:
    #     f.write(x.hex())
    global flag
    flag += x
        
    print('OK')
    return 1


for i in range(6519):
    Solve(i, 0)

with open('flag', 'wb') as f:
    f.write(flag)