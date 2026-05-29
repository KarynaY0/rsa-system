# RSA Encryption System — Level B

A complete RSA encryption and decryption desktop application implemented **without any cryptography library**.  
All math is implemented from scratch using `java.math.BigInteger`.

## Features

| Step | Description |
|------|-------------|
| ① Key Generation | Enter two prime numbers p, q → computes n, φ, e, d |
| ② Encrypt | Type plaintext → encrypts each Unicode character via RSA → display & save `.rsaenc` |
| ③ Decrypt | Load `.rsaenc` file → decrypt with private key → recover original text |
| ④ Math Attack | Given only public key (n, e) + ciphertext → factors n → recovers private key → decrypts |
