import java.net.*;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.math.*;

public class ClientDelegate extends Thread {
    private Socket socket;
    private DataOutputStream output;
    private DataInputStream input;
    private String address;
    private int port;
    private SecretKeySpec secretKeySpec;
    private IvParameterSpec ivParameterSpec;
    private SecretKeySpec hashKeySpec;

    public ClientDelegate(String address, int port) {
        this.address = address;
        this.port = port;
    }

    public void run() {
        try {
            socket = new Socket(address, port);
            output = new DataOutputStream(socket.getOutputStream());
            input = new DataInputStream(socket.getInputStream());

            // Generate R
            SecureRandom random = new SecureRandom();
            long challenge = random.nextLong();
            // Send R
            output.writeUTF("SECURE INIT " + challenge);

            // R'
            String serverResponse = input.readUTF();
            // Get Servers Public Key
            PublicKey publicKey = getServerPublicKey();
            // Validate signature
            if (verifySignature(serverResponse, challenge, publicKey)) {
                output.writeUTF("OK");

                // Receive and process Diffie-Hellman parameters and signature
                String G = input.readUTF();
                BigInteger Gb = new BigInteger(G);
                String P = input.readUTF();
                BigInteger Pb = new BigInteger(P);
                String Gx = input.readUTF();
                BigInteger Gbx = new BigInteger(Gx);
                String iv = input.readUTF();

                // Receive signature
                String signature = input.readUTF();

                // Validate signature
                if (verifyMasterKey(signature, Gb, Pb, Gbx, publicKey)) {
                    output.writeUTF("OK");
                    
                    // Generate Y
                    SecureRandom randomY = new SecureRandom();
                    BigInteger y = new BigInteger(1024, randomY);
                    // Generate Gy
                    BigInteger Gy = Gb.modPow(y, Pb);

                    // Generate master key
                    BigInteger masterKey = Gbx.modPow(y, Pb);

                    // Send Gy
                    output.writeUTF(Gy.toString());

                    // Generate keys
                    ArrayList<byte[]> keys = generateKeys(masterKey);

                    // Generate simetric key
                    Cipher cipher = generateSimetricKey(keys.get(0), iv);
                    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

                    // Generate hash
                    Mac mac = generateHash(keys.get(1));
                    mac.init(hashKeySpec);

                    String initPartTwo = input.readUTF();

                    if (initPartTwo.equals("CONTINUAR")) {
                        
                        byte[] serverUser = "admin".getBytes();
                        byte[] serverPassword = "admin".getBytes();

                        byte[] cipherUserBytes = cipher.doFinal(serverUser);
                        String cipherUser = Base64.getEncoder().encodeToString(cipherUserBytes);

                        output.writeUTF(cipherUser);

                        byte[] cipherPasswordBytes = cipher.doFinal(serverPassword);
                        String cipherPassword = Base64.getEncoder().encodeToString(cipherPasswordBytes);

                        output.writeUTF(cipherPassword);

                        String credentialsValidation = input.readUTF();

                        if (credentialsValidation.equals("OK")) {
                            int randomNumber = random.nextInt();
                            String randomNumberString = String.valueOf(randomNumber);

                            byte[] cypherRandomNumberBytes = cipher.doFinal(randomNumberString.getBytes());
                            String cypherRandomNumber = Base64.getEncoder().encodeToString(cypherRandomNumberBytes);

                            output.writeUTF(cypherRandomNumber);

                            String response = input.readUTF();

                            byte[] responseBytes = Base64.getDecoder().decode(response);

                            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

                            byte[] decryptedResponseBytes = cipher.doFinal(responseBytes);
                            String decryptedResponse = new String(decryptedResponseBytes);

                            int responseNumber = Integer.parseInt(decryptedResponse);

                            String responseHmac = input.readUTF();

                            byte[] hmacBytes = Base64.getDecoder().decode(responseHmac);
                            byte[] hmacResultNumber = mac.doFinal(decryptedResponse.getBytes());

                            if (responseNumber == randomNumber - 1 && Arrays.equals(hmacBytes, hmacResultNumber)) {
                                System.out.println("Connection established successfully.");
                            } else {
                                System.out.println("F");
                                output.writeUTF("ERROR");
                                closeConnection();
                            }
                        } else {
                            output.writeUTF("ERROR");
                            closeConnection();
                        }
                    } else {
                        output.writeUTF("ERROR");
                        closeConnection();
                    }
                } else {
                    output.writeUTF("ERROR");
                    closeConnection();
                }


            } else {
                output.writeUTF("ERROR");
                closeConnection();
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Error in ClientDelegate: " + e.getMessage());
        }
    }

    /**
     * Verifies the signature of a challenge using the provided public key.
     * 
     * @param signedData The Base64 encoded signature to be verified.
     * @param challenge The challenge that was signed.
     * @param publicKey The public key used to verify the signature.
     * @return true if the signature is verified successfully, false otherwise.
     * @throws NoSuchAlgorithmException If the signature algorithm is not available.
     * @throws InvalidKeyException If the public key is invalid for verification.
     * @throws SignatureException If an error occurs during the verification process.
     */
    private boolean verifySignature(String signedData, long challenge, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(BigInteger.valueOf(challenge).toByteArray());
        byte[] signatureBytes = Base64.getDecoder().decode(signedData);
        return signature.verify(signatureBytes);
    }

    /**
     * Verifies the signature of concatenated BigIntegers (G, P, and Gx) using the provided public key.
     * 
     * @param signedData The Base64 encoded signature to be verified.
     * @param G The generator BigInteger that was signed.
     * @param P The prime BigInteger that was signed.
     * @param Gx The key BigInteger that was signed.
     * @param publicKey The public key used to verify the signature.
     * @return true if the signature is verified successfully, false otherwise.
     * @throws NoSuchAlgorithmException If the signature algorithm is not available.
     * @throws InvalidKeyException If the public key is invalid for verification.
     * @throws SignatureException If an error occurs during the verification process.
     * @throws IOException If an I/O error occurs while writing to the ByteArrayOutputStream.
     */
    private boolean verifyMasterKey(String signedData, BigInteger G, BigInteger P, BigInteger Gx, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(G.toByteArray());
        outputStream.write(P.toByteArray());
        outputStream.write(Gx.toByteArray());
        signature.update(outputStream.toByteArray());
        byte[] signatureBytes = Base64.getDecoder().decode(signedData);
        return signature.verify(signatureBytes);
    }

    /**
     * Retrieves the public key of the server from a file and constructs a PublicKey object.
     * 
     * @return The PublicKey object representing the server's public key.
     * @throws IOException If an I/O error occurs while reading the public key file.
     * @throws NoSuchAlgorithmException If the specified cryptographic algorithm is not available.
     * @throws InvalidKeySpecException If the provided key specification is invalid.
     */
    private PublicKey getServerPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        FileReader fileReader = new FileReader("publicKey.txt");
        BufferedReader bufferedReader = new BufferedReader(fileReader);
        String mod = bufferedReader.readLine();
        String exp = bufferedReader.readLine();
        bufferedReader.close();
        BigInteger module = new BigInteger(mod);
        BigInteger exponent = new BigInteger(exp);
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(module, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * Generates encryption and HMAC keys from the provided master key using SHA-512.
     * 
     * @param masterKey The master key to derive the encryption and HMAC keys from.
     * @return An ArrayList containing the encryption key (at index 0) and the HMAC key (at index 1) as byte arrays.
     * @throws NoSuchAlgorithmException If the specified cryptographic algorithm is not available.
     */
    private ArrayList<byte[]> generateKeys(BigInteger masterKey) throws NoSuchAlgorithmException {
        byte[] bytes = masterKey.toByteArray();
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        byte[] digest = md.digest(bytes);
        byte[] keyForEncryption = new byte[32];
        byte[] keyForHmac = new byte[32];
        System.arraycopy(digest, 0, keyForEncryption, 0, 32);
        System.arraycopy(digest, 32, keyForHmac, 0, 32);
        ArrayList<byte[]> keys = new ArrayList<>();
        keys.add(keyForEncryption);
        keys.add(keyForHmac);
        return keys;
    }

    /**
     * Generates a Cipher object for symmetric encryption using AES in CBC mode with PKCS5 padding.
     * 
     * @param keyForEncryption The encryption key.
     * @param iv The Initialization Vector.
     * @return A Cipher object initialized for encryption using AES in CBC mode with PKCS5 padding.
     * @throws NoSuchAlgorithmException If the specified cryptographic algorithm is not available.
     * @throws NoSuchPaddingException If the specified padding scheme is not available.
     */
    private Cipher generateSimetricKey(byte[] keyForEncryption, String iv) throws NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] ivb = Base64.getDecoder().decode(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyForEncryption, "AES");
        this.secretKeySpec = secretKeySpec;
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivb);
        this.ivParameterSpec = ivParameterSpec;
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        return cipher;
    }

    /**
     * Generates a MAC (Message Authentication Code) object for HMAC using SHA-256.
     * 
     * @param keyForHmac The HMAC key.
     * @return A MAC object initialized for HMAC using SHA-256.
     * @throws NoSuchAlgorithmException If the specified cryptographic algorithm is not available.
     */
    private Mac generateHash(byte[] keyForHmac) throws NoSuchAlgorithmException {
        SecretKeySpec secretKey = new SecretKeySpec(keyForHmac, "HmacSHA256");
        this.hashKeySpec = secretKey;
        Mac mac = Mac.getInstance("HmacSHA256");
        return mac;
    }

    /**
     * Closes the socket connection, input stream, and output stream associated with this connection.
     * 
     * This method attempts to close the socket, input stream, and output stream. If any of them are not null,
     * they are closed. Any IOException that occurs during the closing process is caught and printed to the console.
     */
    private void closeConnection() {
        try {
            if (socket != null) socket.close();
            if (input != null) input.close();
            if (output != null) output.close();
        } catch (IOException e) {
            System.out.println("Error closing the connection: " + e.getMessage());
        }
    }
}