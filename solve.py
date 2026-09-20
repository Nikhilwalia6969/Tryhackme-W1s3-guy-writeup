#!/usr/bin/env python3
"""Recover W1seGuy's repeating XOR key in an authorized TryHackMe lab."""

import argparse
import re
import socket
import string

PROMPT = b"What is the encryption key? "


def recover_key(ciphertext: bytes) -> bytes:
    if len(ciphertext) < 5:
        raise ValueError("Ciphertext is too short.")
    if len(ciphertext) % 5 != 0:
        raise ValueError("The closing brace does not reveal key byte 4 for this length.")
    key = bytes(ciphertext[i] ^ b"THM{"[i] for i in range(4))
    key += bytes([ciphertext[-1] ^ ord("}")])
    if any(c not in (string.ascii_letters + string.digits).encode() for c in key):
        raise ValueError("Recovered key contradicts the source's alphanumeric alphabet.")
    return key


def xor_decode(ciphertext: bytes, key: bytes) -> bytes:
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(ciphertext))


def recv_until(sock: socket.socket, marker: bytes) -> bytes:
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Server closed before sending the complete prompt.")
        data.extend(chunk)
        if len(data) > 65536:
            raise ValueError("Unexpectedly large server banner.")
    return bytes(data)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="TryHackMe target IP")
    parser.add_argument("--port", type=int, default=1337)
    args = parser.parse_args()
    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        banner = recv_until(sock, PROMPT)
        match = re.search(rb"flag 1:[ \t]*([0-9a-fA-F]+)[ \t]*\r?\n", banner)
        if not match:
            raise ValueError("Could not locate the hexadecimal ciphertext.")
        ciphertext = bytes.fromhex(match.group(1).decode("ascii"))
        key = recover_key(ciphertext)
        flag1 = xor_decode(ciphertext, key).decode("ascii")
        if not all(32 <= ord(c) <= 126 for c in flag1):
            raise ValueError("Decrypted text is not a printable ASCII flag.")
        print(f"[+] Recovered key: {key.decode('ascii')}")
        print(f"[+] Flag 1: {flag1}")
        sock.sendall(key + b"\n")
        response = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > 65536:
                raise ValueError("Unexpectedly large server response.")
        if not response:
            raise ConnectionError("Server closed without returning a result.")
        print(response.decode("utf-8").strip())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, ConnectionError) as exc:
        raise SystemExit(f"[-] {exc}") from exc
