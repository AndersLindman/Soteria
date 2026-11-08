# Soteria: HHK Rabin KEM

An experimental, educational implementation of a **Rabin Key Encapsulation Mechanism (KEM)** using the **Hofheinz–Hövelmanns–Kiltz (HHK) / Fujisaki-Okamoto transform**, built entirely in a single HTML file with vanilla JavaScript and the Web Crypto API.

## ⚠️ Security Warnings

> **THIS IS EXPERIMENTAL AND NOT PRODUCTION-READY.**

- **Do not use this for real-world security.** This code has not been audited, formally verified, or reviewed by professional cryptographers.
- **Side-channel leakage:** JavaScript `BigInt` arithmetic is **not constant-time**. Operations such as modular exponentiation, multiplication, and comparison may leak timing information that could expose private key material to a local attacker.
- **No formal proof:** While the padding structure follows sound cryptographic principles (HKDF-based commitment, implicit rejection, re-encryption check), this specific instantiation has not been reduced to a standard hardness assumption in a peer-reviewed setting.
- **Browser-only:** This implementation relies on browser-specific behavior and is intended purely for educational exploration.

## What This Is

This project demonstrates a **Rabin-based KEM** that:

1. **Encapsulates** a 256-bit random seed into a 4096-bit ciphertext using deterministic Rabin squaring: `c = M² mod N`.
2. **Pads** the seed using HKDF-SHA-256 to fill the full modulus width, preventing algebraic attacks on sparse messages.
3. **Decapsulates** by computing four square roots via the Chinese Remainder Theorem, validating the padding commitment, and applying the HHK/Fujisaki-Okamoto re-encryption check.
4. **Implicitly rejects** invalid ciphertexts by deriving a pseudorandom fallback key, preventing chosen-ciphertext (CCA) oracle attacks.

## How It Works

### Key Generation

The implementation uses a "cheat code" for speed: it calls the browser's native `crypto.subtle.generateKey` to generate a 4096-bit RSA keypair in optimized C++/Rust code, then extracts the prime factors `p` and `q` from the JWK export. This reduces key generation from several seconds (pure JS) to **under 1 second**.

Because the browser does not guarantee **Blum primes** (`p ≡ 3 mod 4`), the decapsulation step uses the **Tonelli-Shanks algorithm** to compute modular square roots for any prime, rather than relying on the Blum-prime shortcut.

### Padding

The message is encoded as:

M = 0x00 || seed (32 bytes) || HKDF-SHA-256(seed, salt, info) (remaining bytes)


- The leading `0x00` byte guarantees `M < N` without modular reduction.
- The HKDF output fills the entire remaining space, preventing trailing-zero algebraic attacks.
- Decapsulation verifies the HKDF commitment to confirm the correct square root.

### HHK / Fujisaki-Okamoto Transform

The KEM applies the deterministic PKE variant of the HHK transform:

1. **Encapsulation:** Generate random seed → encode → square → derive session key via HKDF.
2. **Decapsulation:** Compute four roots → validate padding → verify re-encryption → derive session key or implicit-rejection key.

This provides **IND-CCA security** in the Random Oracle Model, assuming the underlying Rabin function is one-way.

## Running

1. Open the index.html file locally in a modern web browser (e.g., Chrome, Firefox, Safari, Edge) or via `https://` or `localhost`. The Web Crypto API requires a secure context.
2. Click **Run Honest Exchange** to see a successful encapsulation/decapsulation.
3. Click **Run Tampered CCA Exchange** to see implicit rejection in action.

## Technical Details

| Component | Value |
|---|---|
| Modulus size | 4096 bits (2048-bit primes) |
| Seed size | 256 bits |
| Padding | HKDF-SHA-256, full-width |
| Square root algorithm | Tonelli-Shanks (general prime) |
| CRT reconstruction | Optimized Garner's formula |
| Session key derivation | HKDF-SHA-256 with transcript binding |
| Implicit rejection | HKDF-derived fallback key from secret `σ` |

## Limitations

- **JavaScript BigInt is not constant-time.** Timing, cache, and branch-prediction side channels may leak private key information.
- **No multi-party or protocol integration.** This is a standalone demo.
- **No post-quantum security.** Rabin's security rests on integer factorization, which is broken by Shor's algorithm on a sufficiently large quantum computer.
- **Browser dependency.** Behavior may vary across engines.

## License

This work is released into the public domain under the **CC0 1.0 Universal (CC0 1.0) Public Domain Dedication**.

You can copy, modify, distribute, and use this code for any purpose, including commercial use, without asking permission.

See [https://creativecommons.org/publicdomain/zero/1.0/](https://creativecommons.org/publicdomain/zero/1.0/) for details.

## References

- Hofheinz, D., Hövelmanns, K., Kiltz, E. — *A Modular Analysis of the Fujisaki-Okamoto Transformation* (TCC 2017)
- Fujisaki, E., Okamoto, T. — *Secure Integration of Asymmetric and Symmetric Encryption Schemes* (Journal of Cryptology, 2013)
- Tonelli-Shanks algorithm — [Wikipedia](https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm)
- Web Crypto API — [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
