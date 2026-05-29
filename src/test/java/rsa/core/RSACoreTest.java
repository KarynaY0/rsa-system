package rsa.core;

import org.junit.jupiter.api.*;
import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RSACoreTest {

    @Test void primeCheck()  {
        assertTrue(RSACore.isPrime(61));
        assertTrue(RSACore.isPrime(53));
        assertFalse(RSACore.isPrime(1));
        assertFalse(RSACore.isPrime(4));
        assertFalse(RSACore.isPrime(9));
    }

    @Test void gcd() {
        assertEquals(BigInteger.valueOf(4), RSACore.gcd(BigInteger.valueOf(8), BigInteger.valueOf(12)));
        assertEquals(BigInteger.ONE,        RSACore.gcd(BigInteger.valueOf(17), BigInteger.valueOf(61)));
    }

    @Test void modInverse() {
        // 17 * d ≡ 1 (mod 3120)
        BigInteger d = RSACore.modInverse(BigInteger.valueOf(17), BigInteger.valueOf(3120));
        assertEquals(BigInteger.ONE, d.multiply(BigInteger.valueOf(17)).mod(BigInteger.valueOf(3120)));
    }

    @Test void encryptDecryptRoundTrip() {
        RSACore.RSAParams p = RSACore.generateParams(61, 53);
        String msg = "Hello";
        List<BigInteger> cipher = RSACore.encrypt(msg, p.publicKey());
        String plain = RSACore.decrypt(cipher, p.privateKey());
        assertEquals(msg, plain);
    }

    @Test void attackRecoversPlaintext() {
        RSACore.RSAParams p = RSACore.generateParams(61, 53);
        List<BigInteger> cipher = RSACore.encrypt("RSA", p.publicKey());
        RSACore.AttackResult ar = RSACore.decryptViaAttack(cipher, p.n, p.e);
        assertEquals("RSA", ar.plaintext());
    }

    @Test void invalidPrimeThrows() {
        assertThrows(IllegalArgumentException.class, () -> RSACore.generateParams(4, 53));
    }

    @Test void equalPrimesThrow() {
        assertThrows(IllegalArgumentException.class, () -> RSACore.generateParams(61, 61));
    }
}
