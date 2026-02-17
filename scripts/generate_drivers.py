import os

def file_to_hex_array(file_path, array_name):
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        hex_array = ', '.join([f'0x{b:02X}' for b in content])
        
        return f"""    extern const unsigned char {array_name}[] = {{ {hex_array} }};
    extern const unsigned long {array_name.replace('data', 'size')} = sizeof({array_name});
"""
    except FileNotFoundError:
        print(f"Warning: File not found: {file_path}. Generating dummy data.")
        return f"""    extern const unsigned char {array_name}[] = {{ 0x90, 0x90, 0x90, 0xC3 }};
    extern const unsigned long {array_name.replace('data', 'size')} = 4;
"""

def generate_cpp(output_path, mappings):
    content = """#include <windows.h>

// Auto-generated file containing embedded driver binaries.
// Sourced from KernelMode/drv/

extern "C" {
"""
    
    for file_path, array_name in mappings.items():
        print(f"Processing {file_path} -> {array_name}")
        content += "\n" + file_to_hex_array(file_path, array_name)

    content += "}\n"

    with open(output_path, 'w') as f:
        f.write(content)
    print(f"Generated {output_path}")

base_dir = r"c:\Users\admin\Documents\Visual Studio 2022\Projects\BYOVD-POC\KernelMode"
drv_dir = os.path.join(base_dir, "drv")

mappings = {
    os.path.join(drv_dir, "gdrv.sys"): "gdrv_bin_data",
    os.path.join(drv_dir, "RTCore64.bin"): "rtcore_bin_data",
    os.path.join(drv_dir, "DbUtil2_3.bin"): "dbutil_bin_data"
}

output_file = os.path.join(base_dir, "EmbeddedDrivers.cpp")
generate_cpp(output_file, mappings)
