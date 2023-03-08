package com.example.rsaproject;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;


import javax.crypto.Cipher;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.HashMap;


@Service
@RequiredArgsConstructor
public class RSAService {
    String transformation="RSA";


    static FileOutputStream privateKeyFile;
    static FileOutputStream publicKeyFile;

    public byte[] encrypt(PublicKey spec, byte[] plainText) {

        try {
            Cipher cipher = Cipher.getInstance(transformation);
            if (transformation.contains("ECB"))
                cipher.init(Cipher.ENCRYPT_MODE, spec);
            else {
                cipher.init(Cipher.ENCRYPT_MODE, spec);
            }
            return cipher.doFinal(plainText);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return null;
    }

    public byte[] decrypt(PrivateKey spec, byte[] encryptedText) {

        try {
            Cipher cipher = Cipher.getInstance(transformation);
            if (transformation.contains("ECB"))
                cipher.init(Cipher.DECRYPT_MODE, spec);
            else {
                cipher.init(Cipher.DECRYPT_MODE, spec);
            }
            return cipher.doFinal(encryptedText);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return null;
    }

    public void insertIntoFile() throws IOException {

        KeyPair keyPair = new RSAUtils().produce();

        privateKeyFile = new FileOutputStream("RsaPrivate" + ".key");
        privateKeyFile.write(keyPair.getPrivate().getEncoded());
        privateKeyFile.close();

        publicKeyFile = new FileOutputStream("RsaPublic" + ".pub");
        publicKeyFile.write(keyPair.getPublic().getEncoded());
        publicKeyFile.close();
    }

    public HashMap<String, HashMap<String, String>> encryptService(RSARequest rsaRequest) throws IOException {

        Path privateKeyFile1 = Paths.get("./RsaPrivate.key");
        Path publicKeyFile1 = Paths.get("./RsaPublic.pub");

        PrivateKey privateKey
                = new RSAUtils().PrivateKeyProduce(
                Files.readAllBytes(privateKeyFile1)
        );

        PublicKey publicKey
                = new RSAUtils().PublicKeyProduce(
                Files.readAllBytes(publicKeyFile1)
        );

        String password = rsaRequest.getPassword();

        byte[] enc = encrypt(publicKey, password.getBytes());

        byte[] bytes = decrypt(privateKey, enc);
        String plainAfter = new String(bytes);

        HashMap<String, HashMap<String, String>> map = new HashMap<>();

        map.put("RSA", new HashMap() {{
            put("1.encrypt", enc);
        }});

        map.get("RSA").put("2.decrypt", plainAfter);

        return map;
    }
}
