# TP-Link Deco M5 to Deco P7 Firmware Patch Toolkit

This directory contains a standalone set of Python 3 utilities designed to decrypt newer TP-Link Deco M5 firmware updates (v1.9.4 and potentially newer) and patch unencrypted Deco M5 recovery firmware to allow installation on the Deco P7.

By updating the compatibility checks inside the Deco M5 recovery binary, the validation on upload is passed when flashing onto a Deco P7 in *recovery mode*, allowing to upgrade Deco P7 to newer, more stable firmware.

---

## Technical Background: Why Unpatched Firmware Fails

When attempting to flash an unpatched newer (or decrypted) Deco M5 firmware onto a Deco P7, the device will download the binary via TFTP/FTP in an infinite loop but refuses to flash it. This is caused by two distinct validation checks in the bootloader (U-Boot):

1. **Model Compatibility Check**: The bootloader checks the firmware's `SupportList` to see if the device model matches. By default, Deco M5 firmware contains M5 signatures, which fail on Deco P7 hardware.
2. **Tokenizer Buffer Overflow (32-Entry Limit)**: Newer Deco M5 firmware releases (such as v1.9.4) have an expanded `SupportList` containing 58 entries. U-Boot has a hardcoded parsing limit of 32 entries. Exceeding this limit causes an overflow in the parser, which silently fails the validation check and aborts the upgrade, resulting in the infinite fetch loop.

The patching script resolves both issues by:
* Injecting Deco P7 regional signatures into the first 6 entries.
* Replacing all subsequent entries in the partition with newlines (`\n`). Because U-Boot's tokenizer skips empty tokens, it sees only 6 valid entries (well below the 32-entry limit) and successfully completes the upgrade.

---

## Toolkit Overview

The folder contains the following scripts:

1. **`install_dependencies.py`**: A helper script to verify and install all required external libraries (`cryptography` and `ubi-reader`).
2. **`tp-link_extract_key.py`**: Extracts the RSA-2048 public key from an unencrypted Deco M5 firmware image.
3. **`tp-link_decrypt_binary.py`**: Uses the recovered RSA public key to decrypt and verify encrypted Deco M5 firmware.
4. **`tp-link_patch_m5-p7.py`**: Modifies the `SupportList:` product configuration block of an unencrypted Deco M5 recovery binary to insert Deco P7 signatures.

---

## Step-by-Step Guide

### 1. Install Dependencies
Before running the tools, ensure Python3 is installed on your system. Run the installer script to download the required package dependencies:

```bash
python install_dependencies.py
```

---

### 2. Extract RSA Decryption Key
From v1.9.4 onwards, the firmware updates of TP-Link Deco M5 are encrypted using AES-128-CBC. The decryption key is derived from an RSA-2048 signature stored inside the binary. 
Luckily, we can extract this public key from an older (unencrypted) Deco M5 firmware and use it to decrypt the firmware file.
To keep this repository clean, you will need to extract the key yourself. The process will create a keyfile that can then be used to decrypt an encrypted firmware-file.

Procedure to recover the key:
1. Download an older, unencrypted Deco M5 firmware release. For example, download the official **Deco M5 v1.9.1** firmware:
   * **Download Link:** [M5_1.9.1 Build 20250909.zip](https://static.tp-link.com/upload/firmware/2025/202509/20250928/M5_1.9.1%20Build%2020250909.zip)
2. Extract the ZIP file to locate the `.bin` firmware file (e.g. `M5 1.0_en_1.9.1 Build 20250909 Rel. 37570_..._up.bin`).
3. Run the key extraction script pointing to that unencrypted binary:

```bash
python tp-link_extract_key.py "path/to/M5_1.9.1_unencrypted.bin"
```

* **Output:** Saves the Base64-encoded key string into a local file named `recovery_key.txt`.

---

### 3. Decrypt Encrypted Firmware
If you wish to inspect or analyze an encrypted target firmware update (e.g. Deco M5 v1.9.4):
1. Obtain the encrypted target firmware `.bin` file.
2. Run the decryption script, which will verify the RSA-PSS signature using `recovery_key.txt` (default) and output the decrypted partition container:

```bash
python tp-link_decrypt_binary.py "path/to/encrypted_target_firmware.bin"
```

* **Output:** Creates a decrypted binary at `path/to/encrypted_target_firmware.bin.dec`.
* **Verification:** The script automatically validates the signature and verifies that the decrypted file structure starts with the partition marker `fwup-ptn`.

---

### 4. Patch Recovery Firmware for Deco P7
The final step is to modify an unencrypted (or decrypted) Deco M5 recovery binary so that it is accepted by the Deco P7 hardware bootloader.
1. Run the patch script, pointing it to either the native unencrypted v1.9.1 binary or a decrypted v1.9.4 binary:

```bash
# Option A: Patching native unencrypted v1.9.1 firmware
python tp-link_patch_m5-p7.py "path/to/M5_1.9.1_unencrypted.bin" -o "M5v1_tp_recovery.bin"

# Option B: Patching decrypted v1.9.4 firmware
python tp-link_patch_m5-p7.py "path/to/M5_1.9.4_decrypted.bin.dec" -o "M5v1_tp_recovery.bin"
```

* **Under the Hood Process**:
  * **In-place Patching**: Replaces the first 6 supported device definitions in-place with the following P7 signatures across all major regions:
    * `{product_name:P7,product_ver:1.0.0,special_id:55530000}` (US)
    * `{product_name:P7,product_ver:1.0.0,special_id:45550000}` (EU)
    * `{product_name:P7,product_ver:1.0.0,special_id:43410000}` (CA)
    * `{product_name:P7,product_ver:1.0.0,special_id:4A500000}` (JP)
    * `{product_name:P7,product_ver:1.0.0,special_id:41550000}` (AU)
    * `{product_name:P7,product_ver:1.0.0,special_id:4B520000}` (KR)
  * **Zero Offset Shifting**: Overwrites target bytes in-place without resizing the file. This keeps the exact file size matching the original, preventing offsets in the `fwup-ptn` index from shifting out of alignment.
  * **U-Boot 32-Entry Limit Bypass**: Overwrites all remaining entries (entries 7-58 in v1.9.4) with newlines `\n`. U-Boot's tokenizer skips consecutive newlines, reducing the parsed entry count to 6 and preventing a hardcoded 32-entry tokenizer limit overflow in U-Boot.
* **Output**: Generates a patched firmware container file named `M5v1_tp_recovery.bin` ready for TFTP recovery or Web UI upgrade on a Deco P7.

---

### 5. Upgrade Deco P7 in recovery mode (TFTP)
Follow description on https://www.tp-link.com/en/support/faq/2958/ to put the device in recovery mode and upgrade the firmware.

In a nutshell:
1. Set IP-address of your PC LAN port to IP `192.168.0.66`, subnet mask `255.255.255.0`
2. Put 'M5v1_tp_recovery.bin' in TFTP folder, start TFTP
3. Connect a LAN-cable from PC to Deco device. Disconnect Power from Deco, press reset pin and keep it pressed while connecting USB-C power cord
4. Release button when TFTP indicates that a file is being transferred.
5. Wait for Deco to complete upgrade and restart

