import struct

def rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def decrypt(data, key):
    # Convert bytes to mutable bytearray
    buf = bytearray(data)
    
    # Process 32-bit blocks
    num_blocks = len(buf) // 4
    for i in range(num_blocks):
        # Read 4 bytes as Little Endian ULONG
        val = struct.unpack_from('<I', buf, i*4)[0]
        
        # XOR
        val ^= key
        
        # Write back
        struct.pack_into('<I', buf, i*4, val)
        
        # Rotate Key
        key = rotl32(key, 1)
        
    # Remaining bytes (if any) processed by byte logic in C++, but usually aligned?
    # The C++ code had a second loop for remaining bytes using static_cast<UCHAR>(Key).
    # Let's ignore that for header check.
    
    return buf

def main():
    try:
        with open(r'C:\Users\admin\Documents\decrypted_0.bin', 'rb') as f:
            raw_data = f.read()
    except FileNotFoundError:
        print("File not found")
        return

    # Hypothesis Key
    key = 0x0783C1E0
    print(f"Testing Key: 0x{key:08X}")
    
    decrypted = decrypt(raw_data, key)
    
    # Check Header
    header = decrypted[:4]
    print(f"Decrypted Header (Hex): {header.hex()}")
    print(f"Decrypted Header (ASCII): {header}")
    
    if header == b'PA30':
        print("MATCH! Found MS Delta Signature.")
    elif header == b'MZ\x90\x00':
        print("MATCH! Found PE Signature.")
    else:
        print("No Match.")

if __name__ == '__main__':
    main()
