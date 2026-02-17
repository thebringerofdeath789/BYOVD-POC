
import os
import struct

def rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

KEYS = [
    0x70E0DD63, 0x1eac9953, 0xd4c20412, 0xF62E6CE0,
    0x10030F0F, 0x30303030, 0x0F0F0F0F, 0x12345678, 0x00000000,
    0x4031632d, 0x2e06c278, 0x2a975764, 0x98129204, 0x19284203,
    0x0783C1E0, 0x0E81C1E0
]

# Add more keys to brute force if needed?
# KDU often uses year/date based keys or patterns.
# Let's brute force valid "PA30" keys for the first 4 bytes using Byte logic.

FILE_PATH = r"c:\Users\admin\Downloads\KDU\Source\Tanikaze\drv\gdrv.bin"

def check_file(path):
    if not os.path.exists(path):
        print(f"File not found: {path}")
        return

    with open(path, 'rb') as f:
        data = f.read(16) # Read first 16 bytes

    print(f"File: {path}")
    print(f"Header: {data[:4].hex()}")

    target_pa30 = b'\x50\x41\x33\x30' # PA30
    
    # Try all KEYS
    for start_key in KEYS:
        test_decrypt(data, start_key, "KEYS")

    # Brute force if needed (limited)
    # We can inverse the operation for the first 4 bytes to FIND the key!
    # Byte0 ^ (k & 0xFF) = 'P' (0x50)
    # Byte1 ^ (rotl(k,1) & 0xFF) = 'A' (0x41)
    # ...
    
    # Let's try to solve K.
    # We have 4 equations for 32 bits of K.
    # actually we only know (k&0xff), (rotl(k,1)&0xff)...
    # This might filter down candidates.
    solve_key(data, target_pa30)

def test_decrypt(data, key, source):
    k = key
    decrypted = bytearray()
    for i in range(len(data)):
        b = data[i]
        b ^= (k & 0xFF)
        decrypted.append(b)
        k = rotl32(k, 1)
    
    sig = decrypted[:4]
    if sig == b'PA30' or sig[:2] == b'Mz' or sig[:2] == b'MZ':
        print(f"KEY FOUND: 0x{key:08X} -> {sig}")
    # else:
    #     print(f"Key 0x{key:08X} -> {sig}")

def solve_key(data, target):
    # We want data[0] ^ (k & 0xFF) = target[0]  => k & 0xFF = data[0] ^ target[0]
    # We want data[1] ^ (rotl(k,1) & 0xFF) = target[1]
    
    # k0 = data[0] ^ target[0]
    # k1_shifted = data[1] ^ target[1]
    # ...
    
    # Since rotl(k, 1) shifts everything left by 1, bit 0 comes from bit 31.
    # This dependency chain allows us to check consistency.
    pass

def brute_force_solver(data):
    # Solver is hard, let's just reverse engineer the first few bytes
    b0 = data[0] ^ 0x50 # 'P'
    b1 = data[1] ^ 0x41 # 'A'
    b2 = data[2] ^ 0x33 # '3'
    b3 = data[3] ^ 0x30 # '0'
    
    # K must satisfy:
    # (K >> 0) & 0xFF == b0
    # (rotl(K,1) >> 0) & 0xFF == b1
    # ...
    
    # We can perform a limited brute force or constraint propagation.
    # Let's brute force just the keys we have + variations, 
    # OR assume the file might use the DWORD algo (which we already confirmed works for first 4 bytes).
    pass

check_file(FILE_PATH)
