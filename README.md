
# Applied Cryptography

A collection of Python implementations exploring core cryptographic primitives — built from scratch to demonstrate understanding of the underlying mathematics and security properties, not just library usage.

---

## Project Overview

This project covers three distinct areas of applied cryptography:

| Module | File | Description |
|---|---|---|
| Hash Function & Collision Attack | `collision_resistant_hash_function.py` | Custom polynomial hash + SHA-256 comparison + collision attack |
| Custom AES Mode | `Custom_AES_Mode.py` | CBC-style encryption implemented over AES-ECB |
| HMAC | `HMAC.py` | RFC 2104-compliant HMAC-SHA256 from scratch |

---

## Modules

### 1. Hash Function & Collision Resistance (`collision_resistant_hash_function.py`)

#### `ds_hash(message: str) -> int`

A custom polynomial rolling hash function. Each character contributes to the hash via:

```
hash = (hash × 71) + ord(char)
```

The result is masked to 31 bits (`& 0x7FFFFFFF`), producing a non-negative integer output. This design is intentionally simple, making it a useful target for demonstrating collision vulnerabilities.

#### `sha256_hash(message: str) -> str`

A wrapper around Python's `hashlib.sha256`, included for direct comparison with the custom hash. Returns a 256-bit hexadecimal digest — significantly larger output space than `ds_hash`, and cryptographically secure against collision attacks.

#### `myAttack() -> bool`

A brute-force collision search against `ds_hash`. The function:
- Iterates over messages composed from a 62-character alphanumeric alphabet
- Hashes each message using `ds_hash`
- Stores hash→message mappings in a dictionary
- Returns `False` (collision found / not collision-resistant) if any two messages produce the same hash, `True` otherwise

This attack exploits the limited 31-bit output space of `ds_hash` (~2.1 billion possible values). By the birthday paradox, collisions become highly probable after roughly √(2^31) ≈ 46,341 hash evaluations — far fewer than the total message space. This starkly contrasts with SHA-256's 2^256 output space, which makes brute-force collision attacks computationally infeasible.

**Key insight:** The attack demonstrates why output size, avalanche effect, and non-linearity are all critical properties of a cryptographically secure hash function — properties `ds_hash` lacks.

---

### 2. Custom AES Mode (`Custom_AES_Mode.py`)

#### `CustomAESMode(key: bytes, iv: bytes, plaintext: str) -> str`

Implements a **CBC (Cipher Block Chaining)**-style encryption mode, built on top of AES in ECB mode from Python's `cryptography` library.

**How it works:**

1. **Padding** — The plaintext is padded using PKCS#7 to ensure its length is a multiple of 16 bytes (the AES block size).
2. **Block splitting** — The padded plaintext is divided into 16-byte blocks.
3. **CBC chaining** — Before encrypting each block, it is XOR'd with the previous ciphertext block. For the first block, the IV is used in place of a prior ciphertext block.
4. **AES-ECB encryption** — Each XOR'd block is encrypted using AES in ECB mode. Because the XOR step introduces dependency between blocks, the effective mode is CBC — using ECB as the underlying block cipher primitive.
5. **Output** — The accumulated ciphertext is returned as a hexadecimal string.

**Why this matters:** This illustrates how CBC mode achieves semantic security (identical plaintext blocks produce different ciphertext blocks) from a deterministic primitive (ECB), purely through chaining. It also demonstrates why the IV must be random and unpredictable — a fixed or predictable IV weakens the scheme.

```
Plaintext Block 1  →  XOR(IV)         →  AES-ECB  →  Ciphertext Block 1
Plaintext Block 2  →  XOR(CT Block 1) →  AES-ECB  →  Ciphertext Block 2
...
```

---

### 3. HMAC-SHA256 (`HMAC.py`)

#### `CustomHMAC(key: bytes, text: str) -> str`

A faithful implementation of **HMAC** (Hash-based Message Authentication Code) as specified in **RFC 2104**, using SHA-256 as the underlying hash function.

**Construction (step by step):**

| Step | Operation |
|---|---|
| Key normalisation | If `len(key) > 64`: hash key with SHA-256. If `len(key) < 64`: right-pad with zero bytes to 64 bytes. |
| ipad XOR | `k_ipad = key XOR (0x36 × 64)` |
| Inner hash input | `step3 = k_ipad ‖ message` |
| Inner hash | `step4 = SHA256(step3)` |
| opad XOR | `k_opad = key XOR (0x5C × 64)` |
| Outer hash input | `step6 = k_opad ‖ step4` |
| Final HMAC | `HMAC = SHA256(step6)` |

The constants `0x36` (ipad) and `0x5C` (opad) are defined in RFC 2104 and create two distinct cryptographic contexts for the inner and outer hashes — this two-pass structure is what gives HMAC its security properties, including resistance to length-extension attacks.

#### Verification

The module includes `HMAC_from_Cryptography()`, which uses Python's `cryptography.hazmat.primitives.hmac` library as a reference implementation. The `__main__` block runs both functions on the same key and message, asserting their outputs match — confirming the custom implementation is correct.

---

## Dependencies

```bash
pip install cryptography
```

The `hashlib` and `itertools` modules are part of Python's standard library and require no installation.

**Python version:** 3.7+

---

## Running the Modules

```bash
# Hash function & collision attack
python collision_resistant_hash_function.py

# Custom AES CBC-over-ECB mode
python Custom_AES_Mode.py

# HMAC-SHA256 (includes self-verification against cryptography library)
python HMAC.py
```

---

## Key Concepts Demonstrated

- **Polynomial rolling hash** and its structural weaknesses
- **Birthday paradox** and its application to collision attacks
- **AES block cipher modes** — ECB vs CBC, and the role of the IV
- **PKCS#7 padding** for block cipher alignment
- **RFC 2104 HMAC** construction and the ipad/opad design rationale
- **Length-extension attack resistance** through HMAC's two-pass structure
- **Testing cryptographic implementations** against reference library outputs
