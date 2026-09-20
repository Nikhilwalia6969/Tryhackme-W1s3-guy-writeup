# W1seGuy — TryHackMe Writeup

**Category:** Cryptography · **Difficulty:** Easy · **Service:** TCP/1337

> “Your friend told me you were wise, but I don't believe them. Can you prove me wrong?”

W1seGuy demonstrates how predictable plaintext exposes a short, repeating XOR key. By reviewing the supplied Python source and using the flag's opening and closing characters as known plaintext, we can recover the five-character key, decrypt flag 1, and submit the key to request flag 2.

**Skills demonstrated:** source-code review, known-plaintext attacks, byte manipulation, and Python socket automation.

## 1. Connect to the service

Start the lab machine, wait for it to boot, and connect from the TryHackMe AttackBox or a machine with access through the lab VPN:

```bash
nc -nv <TARGET_IP> 1337
```

Here, Netcat acts as the client. The `-l` option would start a local listener, which is unnecessary because the challenge server is already listening.

The supplied example session contains this banner:

```text
This XOR encoded text has flag 1: 070d0518356224240d31163d3c223127712b0826122b3a50243f09310b102131315330213d071138
What is the encryption key?
```

Keep this connection open. The server generates a fresh key for each connection, so the recovered key must be submitted in the session that produced its ciphertext.

## 2. Review the source

The relevant encryption logic is:

```python
def setup(server, key):
    flag = 'THM{thisisafakeflag}'
    xored = ""
    for i in range(len(flag)):
        xored += chr(ord(flag[i]) ^ ord(key[i % len(key)]))
    return xored.encode().hex()
```

The server generates its key with:

```python
res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
key = str(res)
```

Each key has five alphanumeric characters. There are `62⁵ = 916,132,832` possible keys, but searching that space is unnecessary.

The source also loads a separate flag from disk:

```python
flag = open('flag.txt', 'r').read().strip()
```

The `flag` inside `setup()` is a local variable; it does not overwrite this global value. After sending the encrypted local flag, the server compares our answer with the session key. A correct answer returns the global flag from `flag.txt`.

### Source placeholder versus observed ciphertext

The supplied source contains the 20-character placeholder `THM{thisisafakeflag}`. The example ciphertext decodes to 40 bytes and, as verified below, encrypts a different flag. We therefore use the expected `THM{...}` format rather than assuming the placeholder is the deployed plaintext.

Both the example plaintext and the key are ASCII. Their XOR values stay below 128, so the source's UTF-8 encoding preserves one byte per XOR result for this example.

## 3. Identify the weakness

Repeating-key XOR applies this operation at each position:

```text
C[i] = P[i] XOR K[i mod 5]
```

XOR is reversible, so a known plaintext byte reveals the corresponding key byte:

```text
K[i mod 5] = C[i] XOR P[i]
```

The expected prefix `THM{` reveals key positions 0–3. To recover position 4, we use the expected closing brace `}`.

**The position matters:** the example contains 40 bytes, making its last index 39. Because `39 % 5 == 4`, the closing brace reveals the remaining key byte. This shortcut works when the ciphertext length is divisible by five; it does not recover all five positions for every possible flag length.

## 4. Recover the key and flag 1

For the supplied ciphertext, the five known characters give:

| Ciphertext index | Ciphertext byte | Known plaintext | Key position | Recovered character |
| --- | --- | --- | --- | --- |
| 0 | `0x07` | `T` (`0x54`) | 0 | `S` |
| 1 | `0x0d` | `H` (`0x48`) | 1 | `E` |
| 2 | `0x05` | `M` (`0x4d`) | 2 | `H` |
| 3 | `0x18` | `{` (`0x7b`) | 3 | `c` |
| 39 | `0x38` | `}` (`0x7d`) | 4 | `E` |

The recovered key is **`SEHcE`**. We can reproduce the calculation locally:

```python
ciphertext = bytes.fromhex(
    "070d0518356224240d31163d3c223127712b0826122b3a50243f09310b102131315330213d071138"
)
assert len(ciphertext) % 5 == 0
key = bytes(ciphertext[i] ^ b"THM{"[i] for i in range(4))
key += bytes([ciphertext[-1] ^ ord("}")])
plaintext = bytes(c ^ key[i % 5] for i, c in enumerate(ciphertext))
print(key.decode())
print(plaintext.decode())
```

Output:

```text
SEHcE
THM{p1alntExtAtt4ckcAnr3alLyhUrty0urxOr}
```

The flag's message describes the vulnerability: predictable plaintext can expose a repeating XOR key.

## 5. Request flag 2

Enter the recovered key at the prompt in the **same connection**. For the example above, the answer is `SEHcE`; a new connection will normally require a different key.

The successful response has this form:

```text
Congrats! That is the correct key! Here is flag 2: THM{...}
```

The second flag is read from the server's `flag.txt`. Its exact value is not included in this writeup, and the source alone does not establish whether it changes between lab instances.

## 6. Automate the attack

The accompanying [solve.py](solve.py) connects to the service, extracts the ciphertext, recovers the key, prints flag 1, and submits the key to request flag 2. It uses only Python's standard library.

```bash
python3 solve.py <TARGET_IP>
```

For a different port:

```bash
python3 solve.py <TARGET_IP> --port 1337
```

The solver handles several details that matter in a real TCP client:

- It reads until the complete prompt arrives. TCP is a byte stream: separate server sends can arrive together, and one send can arrive across several reads.
- It extracts only the hexadecimal field, even if the prompt arrives in the same chunk.
- It checks that the final brace maps to key position 4 and that the recovered key matches the source's alphanumeric alphabet.
- It submits the key on the existing connection and reads the response until the server closes it.

The solver deliberately stops if the length assumption fails. In that case, the prefix still reveals four key characters, but another plaintext clue or analysis of the remaining 62 candidates is needed.

### Validation

The example ciphertext was decoded locally and reproduced both `SEHcE` and the first flag shown above. The solver was also checked against a local mock service with combined and fragmented banner delivery. These checks verify the example and client behavior; they do not constitute a live retrieval of flag 2.

## 7. Results

| Value | Result |
| --- | --- |
| Example session key | `SEHcE` |
| Flag 1 | `THM{p1alntExtAtt4ckcAnr3alLyhUrty0urxOr}` |
| Flag 2 | Returned by the live service after the correct session key is submitted; not recorded here |

## 8. Lessons learned

- **A large nominal keyspace does not prevent a structural attack.** Five known plaintext characters recover the entire key when they cover all five key positions.
- **Predictable formats supply useful clues.** A recognizable prefix and suffix can be enough, even when the complete plaintext is unknown.
- **Fresh keys do not fix an insecure construction.** This attack uses one ciphertext from one session; it does not depend on reusing the key across connections.
- **XOR is an operation, not the root problem by itself.** The weakness here is a short repeating key exposed by known plaintext. XOR is also used inside secure cryptographic constructions.
- **TCP clients must handle stream boundaries correctly.** Assuming that one `recv()` matches one server message can break an otherwise correct solver.

For a real application, replace this custom construction with a vetted authenticated-encryption implementation, with secure key generation and correct nonce management. Changing the random-number generator alone would not prevent this known-plaintext attack.

---

*Challenge and source logic: TryHackMe, W1seGuy. Analysis is scoped to the authorized training lab.*
