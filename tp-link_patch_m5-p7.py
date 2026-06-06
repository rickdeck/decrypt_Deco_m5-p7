#!/usr/bin/env python3
import argparse
from pathlib import Path

# The replacement products to make the M5 firmware work on Deco P7
NEW_PRODUCTS = [
    b"{product_name:P7,product_ver:1.0.0,special_id:55530000}",
    b"{product_name:P7,product_ver:1.0.0,special_id:45550000}",
    b"{product_name:P7,product_ver:1.0.0,special_id:43410000}",
    b"{product_name:P7,product_ver:1.0.0,special_id:4A500000}",
    b"{product_name:P7,product_ver:1.0.0,special_id:41550000}",
    b"{product_name:P7,product_ver:1.0.0,special_id:4B520000}"
]

def patch_firmware(bin_path: Path, out_path: Path) -> bool:
    print(f"Reading unencrypted binary: {bin_path.name}...")
    try:
        data = bytearray(bin_path.read_bytes())
    except Exception as e:
        print(f"Error reading file: {e}")
        return False

    # Check for SupportList: at expected offset 0x201C (8220)
    expected_offset = 0x201C
    marker = b"SupportList:\n"
    
    offset = data.find(marker)
    if offset == -1:
        print("Error: 'SupportList:\\n' marker not found in binary.")
        return False
        
    if offset != expected_offset:
        print(f"Note: 'SupportList:' found at offset 0x{offset:X} instead of expected 0x{expected_offset:X}.")
    else:
        print(f"Found 'SupportList:' at expected offset 0x{offset:X}.")

    # Identify the start of the first bracket
    start_bracket = data.find(b"{", offset)
    if start_bracket == -1 or start_bracket > offset + 100:
        print("Error: Could not find product lists following 'SupportList:'.")
        return False

    # Find support-list partition size in fwup-ptn index at offset 0x1014
    ptn_index_offset = 0x1014
    ptn_index_end = data.find(b"\x00", ptn_index_offset)
    if ptn_index_end == -1:
        ptn_index_end = ptn_index_offset + 2048
    ptn_index_data = data[ptn_index_offset:ptn_index_end]

    import re
    match = re.search(r"fwup-ptn\s+support-list\s+base\s+0x([0-9A-Fa-f]+)\s+size\s+0x([0-9A-Fa-f]+)", ptn_index_data.decode("ascii", errors="ignore"))
    if not match:
        print("Error: Could not find 'support-list' partition details in ptn index.")
        return False
    
    support_list_base = int(match.group(1), 16)
    support_list_size = int(match.group(2), 16)
    support_list_end = 0x1014 + support_list_base + support_list_size
    print(f"Parsed support-list partition: base=0x{support_list_base:X}, size=0x{support_list_size:X} (ends at 0x{support_list_end:X})")

    # Parse first 6 lines
    current = start_bracket
    lines_found = []
    
    for i in range(6):
        next_nl = data.find(b"\n", current)
        if next_nl == -1 or next_nl >= support_list_end:
            print(f"Error: Unexpected EOF while parsing product line {i + 1}.")
            return False
        lines_found.append(data[current:next_nl])
        current = next_nl + 1

    # Print original products
    print("\nOriginal first 6 products:")
    for i, line in enumerate(lines_found):
        print(f"  {i+1}: {line.decode('ascii', errors='replace')}")

    # Build the replacement string
    replacement = b"\n".join(NEW_PRODUCTS) + b"\n"

    original_file_size = len(data)
    original_len = support_list_end - start_bracket
    replacement_len = len(replacement)

    if replacement_len > original_len:
        print(f"\nError: Replacement size ({replacement_len}) exceeds support list partition space ({original_len}).")
        return False
    
    # Overwrite the rest of the partition space with newlines to reduce entry count under U-Boot's 32 limit
    padding_len = original_len - replacement_len
    print(f"Overwriting remaining {padding_len} bytes of support-list partition with newlines (to stay under U-Boot's 32-entry limit).")
    replacement = replacement + b"\n" * padding_len

    # Perform the replacement in bytearray without shifting
    data[start_bracket:support_list_end] = replacement

    # Verify size didn't change
    if len(data) != original_file_size:
        print(f"Error: Binary size changed from {original_file_size} to {len(data)} bytes!")
        return False
    else:
        print(f"Confirmed: Patched binary size is identical to original ({original_file_size} bytes).")

    # Print new products
    print("\nPatched first 6 products:")
    for i, new_line in enumerate(NEW_PRODUCTS):
        print(f"  {i+1}: {new_line.decode('ascii')}")

    # Save patched file
    try:
        # If outputting to the same input file, let's create a backup first
        if out_path.resolve() == bin_path.resolve():
            bak_path = bin_path.with_suffix(bin_path.suffix + ".bak")
            print(f"\nCreating backup of original binary at: {bak_path.name}")
            bak_path.write_bytes(bin_path.read_bytes())

        out_path.write_bytes(data)
        print(f"\nSuccessfully wrote patched binary to: {out_path.name}")
        return True
    except Exception as e:
        print(f"Error saving patched binary: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Patch the SupportList section of an unencrypted Deco M5 recovery binary to support Deco P7."
    )
    parser.add_argument(
        "binary",
        help="Path to the unencrypted Deco M5 firmware binary"
    )
    parser.add_argument(
        "-o", "--output",
        default="M5v1_tp_recovery.bin",
        help="Path to save the patched output (default: M5v1_tp_recovery.bin)"
    )
    args = parser.parse_args()

    bin_path = Path(args.binary)
    if not bin_path.is_file():
        print(f"Error: Input file '{bin_path}' does not exist.")
        return 1

    out_path = Path(args.output)
    
    success = patch_firmware(bin_path, out_path)
    return 0 if success else 1

if __name__ == "__main__":
    import sys
    sys.exit(main())
