package rsa.core;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * RSA implementation WITHOUT any cryptography library.
 * All math is done manually using BigInteger for arbitrary precision.
 */
public class RSACore {

    // ─────────────────────────────────────────────────
    //  1. PRIME VALIDATION
    // ─────────────────────────────────────────────────

    /** Simple trial-division primality check (suitable for educational purposes). */
    public static boolean isPrime(long n) {
        if (n < 2) return false;
        if (n == 2) return true;
        if (n % 2 == 0) return false;
        for (long i = 3; i * i <= n; i += 2) {
            if (n % i == 0) return false;
        }
        return true;
    }

    // ─────────────────────────────────────────────────
    //  2. EUCLIDEAN ALGORITHM
    // ─────────────────────────────────────────────────

    /**
     * Standard Euclidean algorithm.
     * Returns GCD(a, b).
     */
    public static BigInteger gcd(BigInteger a, BigInteger b) {
        while (!b.equals(BigInteger.ZERO)) {
            BigInteger temp = b;
            b = a.mod(b);
            a = temp;
        }
        return a;
    }

    // ─────────────────────────────────────────────────
    //  3. EXTENDED EUCLIDEAN ALGORITHM
    // ─────────────────────────────────────────────────

    /**
     * Extended Euclidean algorithm.
     * Returns [gcd, x, y] such that a*x + b*y = gcd(a, b).
     * Used to find the modular inverse (private key d).
     */
    public static BigInteger[] extendedGcd(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            return new BigInteger[]{a, BigInteger.ONE, BigInteger.ZERO};
        }
        BigInteger[] r = extendedGcd(b, a.mod(b));
        BigInteger gcd = r[0];
        BigInteger x   = r[2];
        BigInteger y   = r[1].subtract(a.divide(b).multiply(r[2]));
        return new BigInteger[]{gcd, x, y};
    }

    /**
     * Modular inverse of e mod phi, found via extended Euclidean algorithm.
     * d = e^(-1) mod phi(n)
     */
    public static BigInteger modInverse(BigInteger e, BigInteger phi) {
        BigInteger[] result = extendedGcd(e, phi);
        if (!result[0].equals(BigInteger.ONE)) {
            throw new ArithmeticException("Modular inverse does not exist — GCD != 1");
        }
        return result[1].mod(phi).add(phi).mod(phi); // ensure positive
    }

    // ─────────────────────────────────────────────────
    //  4. RSA PARAMETER CALCULATION
    // ─────────────────────────────────────────────────

    public static class RSAParams {
        public final BigInteger p, q, n, phi, e, d;

        public RSAParams(BigInteger p, BigInteger q, BigInteger n,
                         BigInteger phi, BigInteger e, BigInteger d) {
            this.p = p; this.q = q; this.n = n;
            this.phi = phi; this.e = e; this.d = d;
        }

        public PublicKey publicKey()  { return new PublicKey(n, e); }
        public PrivateKey privateKey(){ return new PrivateKey(n, d); }
    }

    public record PublicKey(BigInteger n, BigInteger e) {
        @Override public String toString() { return "n=" + n + "\ne=" + e; }
    }

    public record PrivateKey(BigInteger n, BigInteger d) {
        @Override public String toString() { return "n=" + n + "\nd=" + d; }
    }

    /**
     * Generates all RSA parameters from two prime numbers p and q.
     *
     * Steps:
     *   n   = p * q
     *   phi = (p-1) * (q-1)      [Euler's totient]
     *   e   = smallest integer > 1 s.t. gcd(e, phi) == 1
     *   d   = e^(-1) mod phi     [via extended Euclidean]
     */
    public static RSAParams generateParams(long pLong, long qLong) {
        if (!isPrime(pLong)) throw new IllegalArgumentException("p = " + pLong + " is not prime.");
        if (!isPrime(qLong)) throw new IllegalArgumentException("q = " + qLong + " is not prime.");
        if (pLong == qLong)  throw new IllegalArgumentException("p and q must be different primes.");

        BigInteger p   = BigInteger.valueOf(pLong);
        BigInteger q   = BigInteger.valueOf(qLong);
        BigInteger n   = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Choose e: typically start from 65537, fall back to small values
        BigInteger e = findPublicExponent(phi);
        BigInteger d = modInverse(e, phi);

        return new RSAParams(p, q, n, phi, e, d);
    }

    /** Find smallest e > 1 such that gcd(e, phi) == 1. */
    private static BigInteger findPublicExponent(BigInteger phi) {
        // Try 65537 first (standard), then fall through smaller candidates
        BigInteger[] candidates = {
            BigInteger.valueOf(65537),
            BigInteger.valueOf(17),
            BigInteger.valueOf(5),
            BigInteger.valueOf(3)
        };
        for (BigInteger candidate : candidates) {
            if (candidate.compareTo(phi) < 0 && gcd(candidate, phi).equals(BigInteger.ONE)) {
                return candidate;
            }
        }
        // Brute-force fallback
        BigInteger e = BigInteger.valueOf(2);
        while (e.compareTo(phi) < 0) {
            if (gcd(e, phi).equals(BigInteger.ONE)) return e;
            e = e.add(BigInteger.ONE);
        }
        throw new ArithmeticException("Could not find valid public exponent e.");
    }

    // ─────────────────────────────────────────────────
    //  5. ENCRYPTION
    // ─────────────────────────────────────────────────

    /**
     * Encrypts a string character by character.
     * Each char is converted to its Unicode codepoint,
     * then: cipherChar = (codepoint ^ e) mod n
     *
     * Returns a list of BigInteger ciphertexts (one per character).
     */
    public static List<BigInteger> encrypt(String plaintext, PublicKey pub) {
        List<BigInteger> cipher = new ArrayList<>();
        for (int cp : plaintext.codePoints().toArray()) {
            BigInteger m = BigInteger.valueOf(cp);
            if (m.compareTo(pub.n()) >= 0) {
                throw new IllegalArgumentException(
                    "Character codepoint " + cp + " >= n=" + pub.n() +
                    ". Use larger primes to support this character.");
            }
            cipher.add(m.modPow(pub.e(), pub.n()));
        }
        return cipher;
    }

    /** Serializes the cipher list to a space-separated string for storage. */
    public static String cipherToString(List<BigInteger> cipher) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < cipher.size(); i++) {
            if (i > 0) sb.append(' ');
            sb.append(cipher.get(i));
        }
        return sb.toString();
    }

    /** Deserializes a stored cipher string back to a list of BigIntegers. */
    public static List<BigInteger> stringToCipher(String s) {
        List<BigInteger> list = new ArrayList<>();
        for (String tok : s.trim().split("\\s+")) {
            list.add(new BigInteger(tok));
        }
        return list;
    }

    // ─────────────────────────────────────────────────
    //  6. DECRYPTION (with key)
    // ─────────────────────────────────────────────────

    /**
     * Decrypts using the known private key.
     * plainChar = (cipherChar ^ d) mod n
     */
    public static String decrypt(List<BigInteger> cipher, PrivateKey priv) {
        StringBuilder sb = new StringBuilder();
        for (BigInteger c : cipher) {
            BigInteger m = c.modPow(priv.d(), priv.n());
            sb.appendCodePoint(m.intValueExact());
        }
        return sb.toString();
    }

    // ─────────────────────────────────────────────────
    //  7. MATHEMATICAL ATTACK: factor n to recover p, q
    // ─────────────────────────────────────────────────

    /**
     * Factors n by trial division to find p and q.
     * Then recomputes phi, d (private key), and decrypts.
     *
     * This demonstrates why small primes are insecure —
     * large n values would take infeasible time here.
     */
    public static long[] factorN(BigInteger n) {
        // Trial division — practical only for small n (educational use)
        for (long i = 2; i * i <= n.longValueExact(); i++) {
            if (n.mod(BigInteger.valueOf(i)).equals(BigInteger.ZERO)) {
                long p = i;
                long q = n.divide(BigInteger.valueOf(i)).longValueExact();
                return new long[]{p, q};
            }
        }
        throw new ArithmeticException("Could not factor n=" + n + " (too large for trial division).");
    }

    /**
     * Full attack-based decryption:
     * 1. Factor n → p, q
     * 2. Compute phi = (p-1)(q-1)
     * 3. Recover d = e^(-1) mod phi
     * 4. Decrypt
     */
    public static AttackResult decryptViaAttack(List<BigInteger> cipher, BigInteger n, BigInteger e) {
        long[] pq = factorN(n);
        BigInteger p   = BigInteger.valueOf(pq[0]);
        BigInteger q   = BigInteger.valueOf(pq[1]);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger d   = modInverse(e, phi);
        PrivateKey priv = new PrivateKey(n, d);
        String plaintext = decrypt(cipher, priv);
        return new AttackResult(pq[0], pq[1], phi, d, plaintext);
    }

    public record AttackResult(long p, long q, BigInteger phi, BigInteger d, String plaintext) {}
}
