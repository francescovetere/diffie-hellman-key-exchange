package it.unipr.netsec.project2020;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.SecureRandom;

public class Server {

    public static void main(String[] args) {
        try
        {
            System.out.println("Server Started...");
            ServerSocket serverSocket = new ServerSocket(7021);
            String serverName = "My fair server";
            System.out.println("Socket created...");

            BigInteger g = BigInteger.valueOf(2);
            BigInteger p = new BigInteger("f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c7c5b2d8ef6f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743a31d186cde33212cb52aff3ce1b1294018118d7c84a70a72d686c40319c807297aca950cd9969fabd00a509b0246d3083d66a45d419f9c7cbd894b221926baaba25ec355e92f78c7", 16);

            /* KEY INITIALIZATION */
            PrivateKey privateKey = Utils.loadPrivateKey();

            while (true){
                Socket socket = serverSocket.accept();
                BufferedInputStream inputStream = new BufferedInputStream(socket.getInputStream());
                BufferedOutputStream outputStream = new BufferedOutputStream(socket.getOutputStream());

                BigInteger x_s = new BigInteger(1024, new SecureRandom());
                BigInteger y_s = g.modPow(x_s, p);
                System.out.println("Y_s: " + y_s);


                /* GET Y_C */
                byte[] y_cBytes = Utils.receiveField(inputStream);
                BigInteger y_c = new BigInteger(1, y_cBytes);
                System.out.println("Y_c: " + y_c.toString(16));

                /* GEN DH KEY */
                BigInteger key = y_c.modPow(x_s,p);
                System.out.println("DH Key: " + key.toString(16));

                /* SIGNING */
                byte[] concatenated_y_c_y_s = Utils.concatenateBytes(y_cBytes, y_s.toByteArray());
                byte[] sign = Utils.sign(privateKey, concatenated_y_c_y_s);
                System.out.println("Sign: " + Utils.bytesToHexString(sign));

                /* AUTH TOKEN GENERATION */
                byte[] auth_s = Utils.encrypt(key, serverName.getBytes());

                Utils.sendField(outputStream, y_s.toByteArray());
                Utils.sendField(outputStream, sign);
                Utils.sendField(outputStream, auth_s);


                byte[] auth_c = Utils.receiveField(inputStream);
                byte[] auth_c_decrypted = Utils.decrypt(key, auth_c);
                String clientName = new String(auth_c_decrypted);
                System.out.println("ClientNetSec name: " + clientName);

            }

        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
}

