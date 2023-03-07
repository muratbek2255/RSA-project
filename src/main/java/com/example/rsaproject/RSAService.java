package com.example.rsaproject;

import com.example.rsaproject.io.ByteArrayReader;
import com.example.rsaproject.io.ByteArrayWriter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.HashMap;


@Service
@RequiredArgsConstructor
public class RSAService {
    String transformation="RSA";


    static Path privateKeyFile;
    static Path publicKeyFile;

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

    public void insertIntoFile() {

        KeyPair keyPair = new RSAUtils().produce();

        privateKeyFile = Paths.get("./RsaPrivate.key");
        publicKeyFile = Paths.get("./RsaPublic.key");

        ByteArrayWriter writer = new ByteArrayWriter(privateKeyFile);
        writer.write(keyPair.getPrivate().getEncoded());

        ByteArrayWriter writer2 = new ByteArrayWriter(publicKeyFile);
        writer.write(keyPair.getPublic().getEncoded());
    }

    public HashMap<String, HashMap<String, String>> encryptService(RSARequest rsaRequest){

        privateKeyFile = Paths.get("./RsaPrivate.key");
        publicKeyFile = Paths.get("./RsaPublic.key");

        PrivateKey privateKey
                = new RSAUtils().PrivateKeyProduce(
                new ByteArrayReader(privateKeyFile).read()
        );

        PublicKey publicKey
                = new RSAUtils().PublicKeyProduce(
                new ByteArrayReader(publicKeyFile).read()
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
