#!/usr/bin/env python3
import argparse
import base64
import struct
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC

def parse_publickeyblob(key_bytes: bytes) -> tuple[int, int]:
    """Parse Windows PUBLICKEYBLOB format to extract modulus (n) and exponent (e)."""
    # KeyBlob header (8 bytes) + RSAPUBKEY header (12 bytes)
    if len(key_bytes) < 20:
        raise ValueError("Key data too short to be a valid PUBLICKEYBLOB")
    
    bType, bVersion, reserved, aiKeyAlg = struct.unpack("<BBHI", key_bytes[:8])
    magic, bitlen, pubexp = struct.unpack("<4sII", key_bytes[8:20])
    
    if magic != b"RSA1":
        raise ValueError(f"Unsupported key magic: {magic!r} (expected b'RSA1')")
        
    modulus_len = bitlen // 8
    if len(key_bytes) < 20 + modulus_len:
        raise ValueError("Key data too short for the specified bit length")
        
    modulus_bytes = key_bytes[20:20+modulus_len]
    n = int.from_bytes(modulus_bytes, "little")
    e = pubexp
    return n, e

def mgf1_sha256(seed: bytes, mask_len: int) -> bytes:
    """Mask Generation Function 1 (MGF1) using SHA-256."""
    out = bytearray()
    counter = 0
    while len(out) < mask_len:
        c = counter.to_bytes(4, "big")
        out.extend(hashlib.sha256(seed + c).digest())
        counter += 1
    return bytes(out[:mask_len])

def decrypt_firmware(fw_path: Path, key_path: Path, out_path: Path) -> bool:
    print(f"Loading key file: {key_path.name}...")
    try:
        key_content = key_path.read_text(encoding="utf-8").strip()
        # Clean any whitespace or newlines from base64
        key_content = "".join(key_content.split())
        key_bytes = base64.b64decode(key_content)
        n, e = parse_publickeyblob(key_bytes)
        print(f"Successfully loaded RSA key: modulus={n.bit_length()} bits, exponent={e}")
    except Exception as ex:
        print(f"Error parsing key file: {ex}")
        print("Note: The key file must contain a Base64-encoded Windows PUBLICKEYBLOB (RSA1).")
        return False

    print(f"Loading encrypted firmware: {fw_path.name}...")
    try:
        buf = bytearray(fw_path.read_bytes())
    except Exception as ex:
        print(f"Error reading firmware: {ex}")
        return False

    # Check for fw-type magic
    FW_TYPE_OFFSET = 0x14
    FW_TYPE_MAGIC = b"fw-type:"
    if len(buf) < FW_TYPE_OFFSET + len(FW_TYPE_MAGIC) or buf[FW_TYPE_OFFSET:FW_TYPE_OFFSET+len(FW_TYPE_MAGIC)] != FW_TYPE_MAGIC:
        print("Warning: 'fw-type:' magic not found at offset 0x14. Decryption might fail.")

    # Container offsets
    FW_DATA_POS = 0x14
    SIG_POS = 0x130
    SIG_LEN = 0x100

    if len(buf) < SIG_POS + SIG_LEN:
        print("Error: Firmware file is too small to contain signature.")
        return False

    # Extract signature and zero it out in the hash computation buffer
    signature = bytes(buf[SIG_POS : SIG_POS + SIG_LEN])
    buf_for_hash = bytearray(buf)
    for i in range(SIG_LEN):
        buf_for_hash[SIG_POS + i] = 0

    data_to_verify = bytes(buf_for_hash[FW_DATA_POS:])

    # RSA-PSS signature verification & salt recovery
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        print(f"Error: Signature length ({len(signature)}) does not match key length ({k}).")
        return False

    # Signature is stored in little-endian in the firmware
    sig_int = int.from_bytes(signature, "little", signed=False)
    
    try:
        em_int = pow(sig_int, e, n)
        em = em_int.to_bytes(k, "big")
    except Exception as ex:
        print(f"Error during RSA modular exponentiation: {ex}")
        return False

    if em[-1] != 0xBC:
        print(f"Error: PSS trailer byte mismatch (expected 0xBC, got 0x{em[-1]:X}). Wrong key?")
        return False

    hlen = 32
    masked_db = em[: k - hlen - 1]
    H = em[k - hlen - 1 : k - 1]

    # Reconstruct DB mask using MGF1
    db_mask = mgf1_sha256(H, len(masked_db))
    DB = bytearray(x ^ y for x, y in zip(masked_db, db_mask))

    # Clear leftmost bits per EMSA-PSS
    em_bits = n.bit_length() - 1
    unused = 8 * k - em_bits
    if unused:
        DB[0] &= 0xFF >> unused

    # Find DB separator 0x01
    try:
        idx = DB.index(0x01)
    except ValueError:
        print("Error: PSS DB separator 0x01 not found. Signature verification failed.")
        return False

    salt = bytes(DB[idx + 1 :])
    
    # Verify the signature hash
    mhash = hashlib.sha256(data_to_verify).digest()
    Hp = hashlib.sha256(b"\x00" * 8 + mhash + salt).digest()
    if Hp != H:
        print("Error: PSS hash mismatch. Signature verification failed (wrong key or corrupted firmware).")
        return False

    print("Firmware signature verified successfully!")

    # AES Decryption key and IV derivation from recovered PSS salt
    key = salt[:16]
    iv = salt[16:32]
    print(f"Decryption AES Key: {key.hex()}")
    print(f"Decryption AES IV:  {iv.hex()}")

    # Decrypt starting at absolute offset 0x130 (SIG_POS)
    abs_off = SIG_POS
    dec_len = ((len(buf) - abs_off) // 16) * 16

    try:
        cipher = Cipher(AES(key), CBC(iv))
        decryptor = cipher.decryptor()
        ct = bytes(buf[abs_off : abs_off + dec_len])
        pt = decryptor.update(ct) + decryptor.finalize()
        
        # Replace ciphertext with plaintext
        buf[abs_off : abs_off + dec_len] = pt
    except Exception as ex:
        print(f"Error during AES decryption: {ex}")
        return False

    # Save output
    try:
        out_path.write_bytes(buf)
        print(f"Decrypted firmware written to: {out_path.name}")
    except Exception as ex:
        print(f"Error writing output file: {ex}")
        return False

    # Verify decryption success
    marker = b"fwup-ptn"
    pos = buf.find(marker)
    if pos != -1:
        print(f"Verification Success: Found decrypted partition marker '{marker.decode()}' at offset 0x{pos:X}!")
        return True
    else:
        print("Verification Failed: Decrypted partition marker 'fwup-ptn' was not found.")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Decrypt TP-Link 'fw-type:Cloud' AES-128-CBC/RSA-PSS firmware update files."
    )
    parser.add_argument(
        "firmware",
        help="Path to the encrypted Deco M5 firmware .bin file"
    )
    parser.add_argument(
        "-k", "--key",
        default="recovery_key.txt",
        help="Path to the public key file (default: recovery_key.txt)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Path to save the decrypted output file (default: <firmware>.dec)"
    )
    args = parser.parse_args()

    fw_path = Path(args.firmware)
    if not fw_path.is_file():
        print(f"Error: Firmware file '{fw_path}' does not exist.")
        return 1

    key_path = Path(args.key)
    if not key_path.is_file():
        print(f"Error: Key file '{key_path}' does not exist.")
        return 1

    if args.output:
        out_path = Path(args.output)
    else:
        out_path = fw_path.with_suffix(fw_path.suffix + ".dec")

    success = decrypt_firmware(fw_path, key_path, out_path)
    return 0 if success else 1

if __name__ == "__main__":
    import sys
    sys.exit(main())
