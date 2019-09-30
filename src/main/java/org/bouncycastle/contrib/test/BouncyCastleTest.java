package org.bouncycastle.contrib.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;

public class BouncyCastleTest {

    public static void main(final String[] args) throws GeneralSecurityException {
        final Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        final Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", provider);
        System.out.println("cipher.getAlgorithm() = " + cipher.getAlgorithm());
        final byte[] bytesZeroes = new byte[]{
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
        };
        final SecretKey key = new SecretKeySpec(bytesZeroes, 0, bytesZeroes.length, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        System.out.println("cipher.getAlgorithm() = " + cipher.getAlgorithm());
    }
}
