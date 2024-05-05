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
    private int id;

    public ClientDelegate(String address, int port, int i) {
        this.address = address;
        this.port = port;
        this.id = i;
    }

    public void run() {
        try {
            socket = new Socket(address, port);
            output = new DataOutputStream(socket.getOutputStream());
            input = new DataInputStream(socket.getInputStream());

            // =================================== Generate R ======================================= //
            SecureRandom random = new SecureRandom();
            long challenge = random.nextLong();
            // =================================== Send R ======================================= //
            output.writeUTF("SECURE INIT " + challenge);

            // =================================== R' ======================================= //
            String serverResponse = input.readUTF();
            // =================================== Get Servers Public Key ======================================= //
            PublicKey publicKey = getServerPublicKey();
            // =================================== Validate signature ======================================= //
            long startTimeSignaturteValidation = System.nanoTime();
            Boolean signatureValidation = verifySignature(serverResponse, challenge, publicKey);
            long endTimeSignaturteValidation = System.nanoTime();
            long durationSignaturteValidation = endTimeSignaturteValidation - startTimeSignaturteValidation;
            if (signatureValidation) {
                output.writeUTF("OK");

                // =================================== Receive and process Diffie-Hellman parameters and signature ======================================= //
                String G = input.readUTF();
                BigInteger Gb = new BigInteger(G);
                String P = input.readUTF();
                BigInteger Pb = new BigInteger(P);
                String Gx = input.readUTF();
                BigInteger Gbx = new BigInteger(Gx);
                String iv = input.readUTF();

                // =================================== Receive signature ======================================= //
                String signature = input.readUTF();

                // =================================== Validate signature (OK|ERROR)  ======================================= //
                if (verifyMasterKey(signature, Gb, Pb, Gbx, publicKey)) {
                    output.writeUTF("OK");
                    
                    // =================================== Generate Y  ======================================= //
                    SecureRandom randomY = new SecureRandom();
                    BigInteger y = new BigInteger(1024, randomY);
                    // =================================== Generate Gy = Gb^y mod Pb  ======================================= //
                    long startTimeGenerateGy = System.nanoTime();
                    BigInteger Gy = Gb.modPow(y, Pb);
                    long endTimeGenerateGy = System.nanoTime();
                    long durationGenerateGy = endTimeGenerateGy - startTimeGenerateGy;

                    // =================================== Generate master key  ======================================= //
                    BigInteger masterKey = Gbx.modPow(y, Pb);

                    // =================================== Send Gy  ======================================= //
                    output.writeUTF(Gy.toString());

                    // =================================== Generate keys ======================================= //
                    ArrayList<byte[]> keys = generateKeys(masterKey);

                    // =================================== Generate simetric key ======================================= //
                    Cipher cipher = generateSimetricKey(keys.get(0), iv);
                    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

                    // =================================== Generate hash ======================================= //
                    Mac mac = generateHash(keys.get(1));
                    mac.init(hashKeySpec);

                    // =================================== SECOND PART ======================================= //
                    String initPartTwo = input.readUTF();

                    if (initPartTwo.equals("CONTINUAR")) {
                        
                        // =================================== Server Credentials Bytes ======================================= //
                        byte[] serverUser = "admin".getBytes();
                        byte[] serverPassword = "admin".getBytes();

                        // =================================== Cypher Server user ======================================= //
                        byte[] cipherUserBytes = cipher.doFinal(serverUser);
                        String cipherUser = Base64.getEncoder().encodeToString(cipherUserBytes);

                        // =================================== Send Cypher Server User ======================================= //
                        output.writeUTF(cipherUser);

                         // =================================== Cypher Server password ======================================= //
                        byte[] cipherPasswordBytes = cipher.doFinal(serverPassword);
                        String cipherPassword = Base64.getEncoder().encodeToString(cipherPasswordBytes);

                        // =================================== Send Cypher Server User ======================================= //
                        output.writeUTF(cipherPassword);

                        // =================================== Read Server Credentials Validation (OK|ERROR) ======================================= //
                        String credentialsValidation = input.readUTF();
                        if (credentialsValidation.equals("OK")) {

                            // =================================== Consultation ======================================= //
                            int randomNumber = random.nextInt();
                            String randomNumberString = String.valueOf(randomNumber);
                            
                            // =================================== Cypher Consultation ======================================= //
                            long startTimeCypher = System.nanoTime();
                            byte[] cypherRandomNumberBytes = cipher.doFinal(randomNumberString.getBytes());
                            long endTimeCypher = System.nanoTime();
                            long durationCypher = endTimeCypher - startTimeCypher;
                            String cypherRandomNumber = Base64.getEncoder().encodeToString(cypherRandomNumberBytes);

                            // =================================== Send Cypher Consultation ======================================= //
                            output.writeUTF(cypherRandomNumber);

                            // =================================== Hash Consultation ======================================= //
                            long startTimeAuth = System.nanoTime();
                            byte[] hmacBytesSend = mac.doFinal(Integer.toString(randomNumber).getBytes());
                            long endTimeAuth = System.nanoTime();
                            long durationAuth = endTimeAuth - startTimeAuth;
                            String hmacSend = Base64.getEncoder().encodeToString(hmacBytesSend);

                            // =================================== Send Hash Consultation ======================================= //
                            output.writeUTF(hmacSend);

                            // =================================== Read Consultation Response ======================================= //
                            String response = input.readUTF();

                            // =================================== Decypher Consultation Response ======================================= //
                            byte[] responseBytes = Base64.getDecoder().decode(response);
                            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
                            byte[] decryptedResponseBytes = cipher.doFinal(responseBytes);
                            String decryptedResponse = new String(decryptedResponseBytes);
                            int responseNumber = Integer.parseInt(decryptedResponse);

                            // =================================== Read HMAC Consultation Response ======================================= //
                            String responseHmac = input.readUTF();

                            // =================================== Get HMAC Consultation Response ======================================= //
                            byte[] hmacBytes = Base64.getDecoder().decode(responseHmac);
                            byte[] hmacResultNumber = mac.doFinal(decryptedResponse.getBytes());

                            // =================================== Validate HMAC Consultation ======================================= //
                            if (responseNumber == randomNumber - 1 && Arrays.equals(hmacBytes, hmacResultNumber)) {
                                System.out.println("Client " + id + "| Consultation number: " + randomNumber + " - Server Response number: " + responseNumber + "| Verification Time: " + durationSignaturteValidation + "ns | Gy Generation Time: " + durationGenerateGy + "ns | Cypher Time: " + durationCypher + "ns | Auth Time: " + durationAuth + "ns");
                                print(durationSignaturteValidation, durationGenerateGy, durationCypher, durationAuth);
                                output.writeUTF("OK");
                            } else {
                                System.out.println("Client " + id + " - Consultation not successful");
                                output.writeUTF("ERROR");
                                closeConnection();
                            }
                        } else {
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

    private void print(long durationSignaturteValidation, long durationGenerateGy, long durationCypher, long durationAuth) {   
        File file = new File("client_64.csv");
        try {
            FileWriter fr = new FileWriter(file, true);
            fr.write(durationSignaturteValidation + "," + durationGenerateGy + "," + durationCypher + "," + durationAuth + "\n");
            fr.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}