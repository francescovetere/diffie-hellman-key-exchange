package it.unipr.netsec.project2020;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;

public class ClientNetSec {

    public static void main(String[] args) {
        try
        {
            /* KEY INITIALIZATION */
            PublicKey publicKey = Utils.getNetSecUniprIt7021PublicKey();

            /* STARTING */
            String clientName = "My fair client";
            System.out.println("ClientNetSec Started...");
            Socket socket = new Socket("netsec.unipr.it",7021);
            System.out.println("Socket created...");
            BufferedInputStream inputStream = new BufferedInputStream(socket.getInputStream());
            BufferedOutputStream outputStream = new BufferedOutputStream(socket.getOutputStream());

            BigInteger g = BigInteger.valueOf(2);
            BigInteger p = new BigInteger("f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c7c5b2d8ef6f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743a31d186cde33212cb52aff3ce1b1294018118d7c84a70a72d686c40319c807297aca950cd9969fabd00a509b0246d3083d66a45d419f9c7cbd894b221926baaba25ec355e92f78c7", 16);
            BigInteger x_c = new BigInteger(1024, new SecureRandom());
            BigInteger y_c = g.modPow(x_c, p);

            /* SENDING Y_C */
            Utils.sendField(outputStream, y_c.toByteArray());

            System.out.println("\nWaiting for response...");

            /* RECEIVING Y_S */
            byte[] y_s_bytes = Utils.receiveField(inputStream);
            BigInteger y_s = new BigInteger(1, y_s_bytes);

            /* COMPUTING DH KEY */
            BigInteger key = y_s.modPow(x_c,p);


            /* RECEIVING AND VERIFYING SIGNATURE */
            byte[] signature_bytes = Utils.receiveField(inputStream);

            System.out.println("Sign: " + Utils.bytesToHexString(signature_bytes));
            byte[] concatenated_y_c_y_s = Utils.concatenateBytes(y_c.toByteArray(), y_s_bytes);
            boolean verified = Utils.verify(publicKey, concatenated_y_c_y_s, signature_bytes);
            System.out.println("Sign verification result: " + verified);
            if(!verified)
                throw new IllegalStateException("SIGNATURE NOT VERIFIED!");

            /* RECEIVING CRYPTED SERVER NAME */
            byte[] auth_s = Utils.receiveField(inputStream);
            byte[] auth_s_decrypted = Utils.decrypt(key, auth_s);
            String serverName = new String(auth_s_decrypted);
            System.out.println("Server name: " + serverName);


            /* SENDING CLIENT NAME */
            byte[] auth_c = Utils.encrypt(key, clientName.getBytes());
            Utils.sendField(outputStream, auth_c);
            socket.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
}

