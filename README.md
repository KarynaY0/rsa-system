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

## How to Run

```bash
java -jar rsa-system.jar
```

Requires **Java 17+**.

## RSA Algorithm (implemented manually)

### 1. Key Generation

```
n   = p × q
φ   = (p−1)(q−1)            # Euler's totient
e   = smallest integer > 1 with gcd(e, φ) = 1
d   = e⁻¹ mod φ             # modular inverse via Extended Euclidean

Public key  = (n, e)
Private key = (n, d)
```

### 2. Euclidean Algorithm (GCD)

```
gcd(a, b):
  while b ≠ 0:
    (a, b) ← (b, a mod b)
  return a
```

### 3. Extended Euclidean Algorithm

Finds `x, y` such that `a·x + b·y = gcd(a, b)`.  
Used to compute the modular inverse `d = e⁻¹ mod φ`.

### 4. Encryption

For each character with Unicode codepoint `m`:
```
c = m^e mod n
```

### 5. Decryption

For each ciphertext block `c`:
```
m = c^d mod n   →   convert to Unicode character
```

### 6. Mathematical Attack (Tab ④)

Given `(n, e)` and ciphertext:
1. Factor `n` by trial division → recover `p`, `q`
2. Recompute `φ = (p−1)(q−1)`
3. Recover `d = e⁻¹ mod φ`
4. Decrypt

## File Format

Encrypted messages are stored as `.rsaenc` files (Java Properties format):

```
cipher=1234 5678 9012 ...   # space-separated BigInteger values
pub.n=3233
pub.e=17
message=original label
```

## Project Structure

```
src/main/java/rsa/
├── Main.java               # Entry point
├── core/
│   └── RSACore.java        # All RSA math (GCD, extended GCD, encrypt, decrypt, attack)
├── storage/
│   └── RSAStorage.java     # File save/load (.rsaenc format)
└── ui/
    └── MainWindow.java     # Swing desktop UI
```

## Example Values (for demo)

- p = 61, q = 53
- n = 3233, φ = 3120
- e = 17, d = 2753
- Encrypts all ASCII characters and Unicode up to codepoint 3232

For larger character sets (emoji, CJK), use larger primes where n > max codepoint.
