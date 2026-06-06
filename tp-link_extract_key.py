#!/usr/bin/env python3
import argparse
import lzma
from pathlib import Path

def extract_key(bin_path: Path) -> str:
    print(f"Reading {bin_path.name}...")
    try:
        content = bin_path.read_bytes()
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

    # Scan for XZ streams (magic header: \xfd7zXZ\x00)
    xz_magic = b"\xfd7zXZ\x00"
    offset = 0
    xz_offsets = []
    while True:
        idx = content.find(xz_magic, offset)
        if idx == -1:
            break
        xz_offsets.append(idx)
        offset = idx + 1

    print(f"Found {len(xz_offsets)} compressed blocks. Scanning...")

    for i, idx in enumerate(xz_offsets):
        try:
            # Use LZMADecompressor to decompress until end of stream, ignoring trailing bytes
            decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
            decomp = decompressor.decompress(content[idx:])
            
            # Look for the public key Base64 marker
            match_idx = decomp.find(b"BgIAAAwk")
            if match_idx != -1:
                # Find the end of the base64 character block
                end = match_idx
                while end < len(decomp) and 32 <= decomp[end] <= 126:
                    end += 1
                key_str = decomp[match_idx:end].decode("ascii")
                print(f"Successfully extracted key from compressed block {i} at offset 0x{idx:X}!")
                return key_str
        except Exception:
            pass

    # Fallback: Search in raw plaintext binary data
    print("Key not found in compressed streams. Checking raw binary data...")
    match_idx = content.find(b"BgIAAAwk")
    if match_idx != -1:
        end = match_idx
        while end < len(content) and 32 <= content[end] <= 126:
            end += 1
        key_str = content[match_idx:end].decode("ascii")
        print(f"Successfully found key in plaintext at offset 0x{match_idx:X}!")
        return key_str

    return None

def main():
    parser = argparse.ArgumentParser(
        description="Extract RSA-2048 public key from an unencrypted TP-Link Deco firmware binary."
    )
    parser.add_argument(
        "binary",
        help="Path to the unencrypted Deco M5 firmware .bin file"
    )
    parser.add_argument(
        "-o", "--output",
        default="recovery_key.txt",
        help="Path to save the extracted key (default: recovery_key.txt)"
    )
    args = parser.parse_args()

    bin_path = Path(args.binary)
    if not bin_path.is_file():
        print(f"Error: File '{bin_path}' does not exist or is not a file.")
        return 1

    key = extract_key(bin_path)
    if key:
        out_path = Path(args.output)
        try:
            out_path.write_text(key, encoding="utf-8")
            print(f"Saved key to: {out_path.resolve()}")
            return 0
        except Exception as e:
            print(f"Error saving key to file: {e}")
            return 1
    else:
        print("Error: Could not find the recovery key in the binary.")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())
