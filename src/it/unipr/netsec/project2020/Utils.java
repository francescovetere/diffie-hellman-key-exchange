package it.unipr.netsec.project2020;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Utils {

    /** Converts a byte array into a hexadecimal string.
     * @param buf the byte array
     * @return the hexadecimal string */
    public static String bytesToHexString(byte[] buf) {
        StringBuffer sb = new StringBuffer();
        for (int i=0; i<buf.length; i++) sb.append(Integer.toHexString((buf[i]>>4)&0x0f)).append(Integer.toHexString(buf[i]&0x0f));
        return sb.toString();
    }

    /** Converts an hexadecimal string into a byte array.
     * @param str the string with hexadecimal symbols
     * @return the byte array */
    public static byte[] hexStringToBytes(String str) {
        byte[] buf = new byte[str.length()/2];
        for (int i=0; i<buf.length; i++) buf[i]=(byte)Integer.parseInt(str.substring(i*2,i*2+2),16);
        return buf;
    }
    
    /** Concatenates two byte arrays.
     * @param aBytes first array
     * @param bBytes second array
     * @return concatenated array */
    public static byte[] concatenateBytes(byte[] aBytes, byte[] bBytes){
        ByteBuffer byteBuffer = ByteBuffer.allocate(aBytes.length + bBytes.length);
        byteBuffer.put(aBytes);
        byteBuffer.put(bBytes);
        byte[] concatenated = byteBuffer.array();
        return concatenated;
    }

    /* COMMUNICATION UTILS */

    /** Writes data to a given output stream.
     * @param outputStream stream on which data will be written 
     * @param field byte array containing the binary representation of the message's field to be sent
     */
    public static void sendField(OutputStream outputStream, byte[] field) throws IOException {
        BigInteger length = BigInteger.valueOf(field.length);
        if(length.toByteArray().length < 2)
            outputStream.write(0);
        else if(length.toByteArray().length > 2)
            throw new UnsupportedOperationException("TOO LONG");
        outputStream.write(length.toByteArray());
        outputStream.write(field);
        outputStream.flush();
    }
    
    /** Reads data from a given input stream.
     * @param inputStream stream from which data will be read
     * @return field byte array containing the binary representation of the received message's field
     */
    public static byte[] receiveField(InputStream inputStream) throws IOException {
        byte[] lengthBytes = new byte[2];
        inputStream.readNBytes(lengthBytes, 0, 2);
        BigInteger length = new BigInteger(1, lengthBytes);
        byte[] field = new byte[length.intValue()];
        inputStream.readNBytes(field, 0, length.intValue());
        return field;
    }


    /* SIGNING UTILS */

    private static final String SIGNING_ALGORITHM = "SHA1withRSA";
    public static final String PUBLIC_KEY_FILE = "public-key.bin";
    public static final String PRIVATE_KEY_FILE = "private-key.bin";
    
    /** Performs a substring operation in order to obtain the name of the signature/encryption algorithm (RSA in this case).
     * @return the name of the signature/encryption algorithm
     */
    private static String getSignatureEncryptionAlgorithm() {
        return SIGNING_ALGORITHM.substring(SIGNING_ALGORITHM.length() - 3);
    }

    /** Creates and returns the public key for the remote server netsec.unipr.it (a known, fixed public value).
     * @return remote server's public key
     */
    public static PublicKey getNetSecUniprIt7021PublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        if(!getSignatureEncryptionAlgorithm().equals("RSA"))
            throw new IllegalStateException("ONLY RSA KEY IS KNOWN FOR THIS SERVER");

        BigInteger e = new BigInteger("65537", 10);
        BigInteger n = new BigInteger("b196e1a7c79a4d66750539bb93f822e088bcd8a6f162fc8503983eb95d682b7ee3093b5bb746b1446550c1e9149b460fc3e461109e102d0312c3b1b4b5da4619dda8a77741475d9ead85001c5c4329f39a2b5a65375571e5f30793415aa5bebaba8b683f547b343e59293462bf185647b97a8d7b943dd2fb8e68815f14826afb", 16);
        KeyFactory factory = KeyFactory.getInstance(getSignatureEncryptionAlgorithm());
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(n,e);
        PublicKey publicKey = factory.generatePublic(rsaPublicKeySpec);
        return publicKey;
    }

    /** Generates a public-private key pair, then writes each key into a specific binary file.
     */
    public static void saveKeyPair() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(getSignatureEncryptionAlgorithm());
        KeyPair keyPair = generator.generateKeyPair();
        FileOutputStream publicKeyFile = new FileOutputStream(Utils.PUBLIC_KEY_FILE);
        publicKeyFile.write(keyPair.getPublic().getEncoded());
        publicKeyFile.flush();
        publicKeyFile.close();

        FileOutputStream privateKeyFile = new FileOutputStream(Utils.PRIVATE_KEY_FILE);
        privateKeyFile.write(keyPair.getPrivate().getEncoded());
        privateKeyFile.flush();
        privateKeyFile.close();
    }

    /** Reads the public key from the corresponding file, then returns its value.
     * @return public key's value
     */
    public static PublicKey loadPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        FileInputStream fileInputStream = new FileInputStream(PUBLIC_KEY_FILE);
        byte[] file = fileInputStream.readAllBytes();
        fileInputStream.close();
        PublicKey publicKey = KeyFactory.getInstance(getSignatureEncryptionAlgorithm())
                .generatePublic(new X509EncodedKeySpec(file));
        return publicKey;
    }

    /** Reads the private key from the corresponding file, then returns its value.
     * @return private key's value
     */
    public static PrivateKey loadPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        FileInputStream fileInputStream = new FileInputStream(PRIVATE_KEY_FILE);
        byte[] file = fileInputStream.readAllBytes();
        fileInputStream.close();
        PrivateKey privateKey = KeyFactory.getInstance(getSignatureEncryptionAlgorithm())
                .generatePrivate(new PKCS8EncodedKeySpec(file));
        return privateKey;
    }
    
    /** Signs a message with a given private key, using a specific algorithm. Then, returns the sign.
     * @param privateKey the key used for signing
     * @param field byte array containing the binary representation of the message to be signed
     * @return message's sign
     */
    public static byte[] sign(PrivateKey privateKey, byte[] field) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(SIGNING_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(field);
        byte[] sign = signature.sign();
        return sign;
    }

    
    /** Verifies a message with a given public key, using a specific algorithm. Then, returns the boolean verification's outcome.
     * @param publicKey the key used for verification
     * @param message byte array containing the binary representation of the message to be verified
     * @param sign message's sign
     * @return boolean verification's outcome
     */
    public static boolean verify(PublicKey publicKey, byte[] message, byte[] sign) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        Signature signature = Signature.getInstance(SIGNING_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(message);
        boolean verified = signature.verify(sign);
        return verified;
    }


    /* ENCRYPTION UTILS */

    private static final byte[] IV = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
    
    
    /** Encrypts a message with a key derived from Diffie-Hellman's shared secret, using a specific algorithm. Then, returns the encryption.
     * @param dhKey key derived from Diffie-Hellman's shared secret
     * @param message byte array containing the binary representation of the message to be encrypted
     * @return message's encryption
     */
    public static byte[] encrypt(BigInteger dhKey, byte[] message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] dh_key = keyFromDHKey(dhKey);
        SecretKeySpec secretKeySpec = new SecretKeySpec(dh_key, ENCRYPTION_ALGORITHM.substring(0, 3));
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(IV));
        byte[] encrypted = cipher.doFinal(message);
        return encrypted;
    }
    
    /** Decrypts a message with a key derived from Diffie-Hellman's shared secret, using a specific algorithm. Then, returns the decryption.
     * @param dhKey key derived from Diffie-Hellman's shared secret
     * @param encrypted byte array containing the binary representation of the encrypted message to be decrypted
     * @return decrypted message
     */
    public static byte[] decrypt(BigInteger dhKey, byte[] encrypted) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] dh_key = keyFromDHKey(dhKey);
        SecretKeySpec secretKeySpec = new SecretKeySpec(dh_key, ENCRYPTION_ALGORITHM.substring(0, 3));
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(IV));
        byte[] message = cipher.doFinal(encrypted);
        return message;
    }

    /** Derives the key used for encryption/decryption, starting from Diffie-Hellman's shared secret (just takes its rightmost 16 bytes)
     * @param dhKey Diffie-Hellman's shared secret
     * @return derived key
     */
    private static byte[] keyFromDHKey(BigInteger dhKey){
        byte[] keyBytes = dhKey.toByteArray();
        byte[] dh_key = new byte[16];
        for(int i = 0; i < 16; ++i)
            dh_key[i] = keyBytes[keyBytes.length - 16 + i];
        return dh_key;
    }
}
