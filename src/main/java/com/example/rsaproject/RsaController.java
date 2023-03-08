package com.example.rsaproject;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

@RestController
public class RsaController {

    private final RSAService rsaService;

    @Autowired
    public RsaController(RSAService rsaService) {
        this.rsaService = rsaService;
    }

    @GetMapping("/file")
    public void insertIntoFile() throws IOException {
        rsaService.insertIntoFile();
    }

    @PostMapping("/encrypt-decrypt")
    public ResponseEntity<HashMap<String, HashMap<String, String>>> encryptPassword(@RequestBody RSARequest rsaRequest)
            throws NoSuchAlgorithmException, IOException {
        return ResponseEntity.status(201).body(rsaService.encryptService(rsaRequest));
    }
}
