package com.example.rsaproject;

import org.springframework.stereotype.Service;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


@Service
public class RSAUtils {


    private static final String RSA_ALGORITHM = "RSA";

    public KeyPair produce() {
        KeyPairGenerator keyGen;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public PrivateKey PrivateKeyProduce(byte[] encodedByteArrayForPrivateKey) {
        try {
            PrivateKey privateKey = KeyFactory.getInstance(RSA_ALGORITHM)
                    .generatePrivate(new PKCS8EncodedKeySpec(encodedByteArrayForPrivateKey));

            return privateKey;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public PublicKey PublicKeyProduce(byte[] encodedByteArrayForPublicKey) {
        try {
            PublicKey publicKey = KeyFactory.getInstance(RSA_ALGORITHM)
                    .generatePublic(new X509EncodedKeySpec(encodedByteArrayForPublicKey));

            return publicKey;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}