package rsa.storage;

import rsa.core.RSACore;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.List;
import java.util.Properties;

/**
 * Handles file-system persistence of encrypted messages and public keys.
 *
 * File format (*.rsaenc):
 *   A Java properties file with keys:
 *     cipher  = space-separated BigInteger values
 *     pub.n   = modulus
 *     pub.e   = public exponent
 *     message = optional label
 */
public class RSAStorage {

    public static final String EXT = ".rsaenc";

    // ── Save ──────────────────────────────────────────

    public static void save(File file,
                            List<BigInteger> cipher,
                            RSACore.PublicKey pub,
                            String label) throws IOException {
        Properties props = new Properties();
        props.setProperty("cipher",  RSACore.cipherToString(cipher));
        props.setProperty("pub.n",   pub.n().toString());
        props.setProperty("pub.e",   pub.e().toString());
        props.setProperty("message", label == null ? "" : label);

        try (Writer w = new FileWriter(file)) {
            props.store(w, "RSA Encrypted Message");
        }
    }

    // ── Load ──────────────────────────────────────────

    public record LoadResult(List<BigInteger> cipher,
                             RSACore.PublicKey pub,
                             String label) {}

    public static LoadResult load(File file) throws IOException {
        Properties props = new Properties();
        try (Reader r = new FileReader(file)) {
            props.load(r);
        }

        String cipherStr = props.getProperty("cipher");
        String nStr      = props.getProperty("pub.n");
        String eStr      = props.getProperty("pub.e");
        String label     = props.getProperty("message", "");

        if (cipherStr == null || nStr == null || eStr == null) {
            throw new IOException("File is missing required RSA fields.");
        }

        List<BigInteger> cipher = RSACore.stringToCipher(cipherStr);
        RSACore.PublicKey pub   = new RSACore.PublicKey(new BigInteger(nStr), new BigInteger(eStr));

        return new LoadResult(cipher, pub, label);
    }
}
