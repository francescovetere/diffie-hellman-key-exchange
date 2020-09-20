package it.unipr.netsec.project2020;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class KeyGenerator {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, SignatureException, IOException {
        Utils.saveKeyPair();
        PublicKey publicKey = Utils.loadPublicKey();
        PrivateKey privateKey = Utils.loadPrivateKey();

        String text = "test";
        byte[] signed = Utils.sign(privateKey, text.getBytes());
        if(!Utils.verify(publicKey, text.getBytes(), signed))
            throw new IllegalStateException("KEYS NOT VALID. RE-GENERATE THEM.");
        else
            System.out.println("Keys valid");

    }

}
