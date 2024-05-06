import java.net.*;
import java.io.*;
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.*;
import java.math.*;

public class ServerDelegate extends Thread {
    private Socket socket;
    private DataOutputStream output;
    private DataInputStream input;
    private KeyPair keyPair;
    private BigInteger p;
    private BigInteger g;
    private SecretKeySpec secretKeySpec;
    private IvParameterSpec ivParameterSpec;
    private SecretKeySpec hashKeySpec;
    private int id;
    
    public ServerDelegate(Socket socket, KeyPair keyPair, BigInteger p, BigInteger g, int i) {
        this.socket = socket;
        this.keyPair = keyPair;
        this.p = p;
        this.g = g;
        this.id = i;
    }

    public void run() {
        try {
            input = new DataInputStream(socket.getInputStream());
            output = new DataOutputStream(socket.getOutputStream());

            // =================================== Init ======================================= //
            String clientMessage = input.readUTF();

            // =================================== Read R ======================================= //
            if (clientMessage.startsWith("SECURE INIT")) {
                long challenge = Long.parseLong(clientMessage.split(" ")[2]);

                // =================================== Sign R' ======================================= //
                long startTimeSignaturteGeneration = System.nanoTime();
                String R = signChallenge(challenge);
                long endTimeSignaturteGeneration = System.nanoTime();
                long durationSignaturteGeneration = endTimeSignaturteGeneration - startTimeSignaturteGeneration;

                // =================================== Send R' ======================================= //
                output.writeUTF(R);

                // =================================== Clients verification (OK|ERROR) ======================================= //
                String clientResponse = input.readUTF();
                if (clientResponse.equals("OK")) {

                    // =================================== Generate Diffie-Hellman parameters ======================================= //
                    BigInteger G = g;
                    BigInteger P = p;

                    // =================================== Generate X ======================================= //
                    SecureRandom random = new SecureRandom();
                    BigInteger x = new BigInteger(1024, random);

                    // =================================== Generate GX ======================================= //
                    BigInteger Gx = g.modPow(x, p);

                    // =================================== Send G, P, Gx ======================================= //
                    output.writeUTF(G.toString());
                    output.writeUTF(P.toString());
                    output.writeUTF(Gx.toString());
 
                    // =================================== Generate IV ======================================= //
                    String iv = generateIV();

                    // =================================== Send IV ======================================= //
                    output.writeUTF(iv);

                    // =================================== Sign G, P, Gx ======================================= //
                    String signature = signData(G, P, Gx);

                    // =================================== Send Signature ======================================= //
                    output.writeUTF(signature);

                    // =================================== Clients verification (OK|ERROR) ======================================= //
                    String clientVerification = input.readUTF();
                    if (clientVerification.equals("OK")) {

                        // =================================== Read GY ======================================= //
                        String Gy = input.readUTF();
                        BigInteger Gby = new BigInteger(Gy);

                        // =================================== Generate keys ======================================= //
                        BigInteger masterKey = Gby.modPow(x, P);
                        ArrayList<byte[]> keys = generateKeys(masterKey);

                        // =================================== Generate Simetric key ======================================= //
                        Cipher cipher = generateSimetricKey(keys.get(0), iv);
                        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

                        // =================================== Generate Hash HMAC ======================================= //
                        Mac mac = generateHash(keys.get(1));
                        mac.init(hashKeySpec);

                        // =================================== PART TWO ======================================= //
                        output.writeUTF("CONTINUAR");

                        // =================================== Get Server Credentials ======================================= //
                        ArrayList<String> credentials = getServerCredentials();
                        String serverUser = credentials.get(0);
                        String serverPassword = credentials.get(1);

                        // =================================== Read Credentials ======================================= //
                        String user = input.readUTF();
                        String password = input.readUTF();
                        byte[] userBytes = Base64.getDecoder().decode(user);
                        byte[] passwordBytes = Base64.getDecoder().decode(password);

                        // =================================== Decypher Credentials ======================================= //
                        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
                        byte[] decryptedUserBytes = cipher.doFinal(userBytes);
                        String decryptedUser = new String(decryptedUserBytes);
                        byte[] decryptedPasswordBytes = cipher.doFinal(passwordBytes);
                        String decryptedPassword = new String(decryptedPasswordBytes);

                        // =================================== Clients verification (OK|ERROR) ======================================= //
                        if (decryptedUser.equals(serverUser) && decryptedPassword.equals(serverPassword)) {
                            output.writeUTF("OK");

                            // =================================== Read Consultation Response ======================================= //
                            String consultation = input.readUTF();
                            byte[] consultationBytes = Base64.getDecoder().decode(consultation);
                            
                            // =================================== Decypher Consultation Response ======================================= //
                            long startTimeDecypher = System.nanoTime();
                            byte[] decryptedConsultationBytes = cipher.doFinal(consultationBytes);
                            long endTimeDecypher = System.nanoTime();
                            long durationDecypher = endTimeDecypher - startTimeDecypher;
                            String decryptedConsultation = new String(decryptedConsultationBytes);

                            // =================================== Read HMAC Consultation Response ======================================= //
                            String responseHmac = input.readUTF();

                            // =================================== Get HMAC Consultation Response ======================================= //
                            byte[] hmacBytesResponse = Base64.getDecoder().decode(responseHmac);
                            byte[] hmacResultNumberResponse = mac.doFinal(decryptedConsultation.getBytes());

                            // =================================== Validate HMAC Consultation Response ======================================= //
                            long startTimeAuth = System.nanoTime();
                            Boolean isHmacValid = Arrays.equals(hmacBytesResponse, hmacResultNumberResponse);
                            long endTimeAuth = System.nanoTime();
                            long durationAuth = endTimeAuth - startTimeAuth;
                            if (!isHmacValid){
                                System.out.println("Server " + id + " - Error in client verification (wrong hash)");
                                input.close();
                                output.close();
                                socket.close();
                            }

                            // =================================== Consultation Response ======================================= //
                            int consultationResult = Integer.parseInt(decryptedConsultation);
                            int result = consultationResult - 1;
                            String resultString = Integer.toString(result);

                            // =================================== Cypher Consultation Response ======================================= //
                            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
                            byte[] cypherResultBytes = cipher.doFinal(resultString.getBytes());
                            String cypherResultNumber = Base64.getEncoder().encodeToString(cypherResultBytes);

                            // =================================== Send Cypher Consultation Response  ======================================= //
                            output.writeUTF(cypherResultNumber);

                            // =================================== Hash Consultation Response ======================================= //
                            byte[] hmacBytes = mac.doFinal(resultString.getBytes());
                            String hmacResultNumber = Base64.getEncoder().encodeToString(hmacBytes);

                            // =================================== Send Hash Consultation Response  ======================================= //
                            output.writeUTF(hmacResultNumber);

                            // =================================== Clients verification (OK|ERROR) ======================================= //
                            String finalVerification = input.readUTF();
                            if (finalVerification.equals("OK")) {
                                System.out.println("Server " + id + " - Consultation number: " + consultationResult +  " | " + "Sign generation time: " + durationSignaturteGeneration + " ns" + " | " + "Decypher time: " + durationDecypher + " ns" + " | " + "HMAC validation time: " + durationAuth + " ns");
                                input.close();
                                output.close();
                                socket.close();
                            } else {
                                System.out.println("Server " + id + " - Error in client verification (wrong simetric key or hash)");
                                System.out.println("Server " + id + " - Consultation not successful");
                            }
                        } else {
                            System.out.println("Server " + id + " - Error in client verification (wrong server credentials)");
                            output.writeUTF("ERROR");
                        }

                    } else {
                        System.out.println("Server " + id + " - Error in client verification (wrong signature)");
                        input.close();
                        output.close();
                        socket.close();
                    }
                } else {
                    System.out.println("Server " + id + " - Error in client verification (wrong signature)");
                    input.close();
                    output.close();
                    socket.close();
                }
            }
        } catch (Exception e) {
            System.out.println("Error in ServerDelegate: " + e.getMessage());
        }
    }

    /**
     * Signs a challenge using the RSA digital signature algorithm with SHA-256.
     * 
     * @param challenge The challenge to sign.
     * @return A Base64 encoded string representing the signed data.
     * @throws NoSuchAlgorithmException If the signature algorithm is not available.
     * @throws InvalidKeyException If the private key is invalid for signing.
     * @throws SignatureException If an error occurs during the signing process.
     */
    private String signChallenge(long challenge) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(BigInteger.valueOf(challenge).toByteArray());
        byte[] signedData = signature.sign();
        return Base64.getEncoder().encodeToString(signedData);
    }


    /**
     * Signs the provided data consisting of three BigIntegers (G, P, and Gx) concatenated together using the RSA digital signature algorithm with SHA-256.
     * 
     * @param G The generator BigInteger to sign.
     * @param P The prime BigInteger to sign.
     * @param Gx The key BigInteger to sign.
     * @return A Base64 encoded string representing the signed data.
     * @throws NoSuchAlgorithmException If the signature algorithm is not available.
     * @throws InvalidKeyException If the private key is invalid for signing.
     * @throws SignatureException If an error occurs during the signing process.
     * @throws IOException If an I/O error occurs while writing to the ByteArrayOutputStream.
     */
    private String signData(BigInteger G, BigInteger P, BigInteger Gx) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(G.toByteArray());
        outputStream.write(P.toByteArray());
        outputStream.write(Gx.toByteArray());
        signature.update(outputStream.toByteArray());
        byte[] signedData = signature.sign();
        return Base64.getEncoder().encodeToString(signedData);
    }

    /**
     * Generates a random Initialization Vector (IV) for symmetric encryption.
     * 
     * @return A Base64 encoded string representing the randomly generated IV.
     */
    private String generateIV() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
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
     * Retrieves the server credentials from a file.
     * 
     * @return An ArrayList containing the username (at index 0) and password (at index 1).
     * @throws IOException If an I/O error occurs while reading the credentials file.
     */
    private ArrayList<String> getServerCredentials() throws IOException {
        FileReader fileReader = new FileReader("credentials.txt");
        BufferedReader bufferedReader = new BufferedReader(fileReader);
        String user = bufferedReader.readLine();
        String password = bufferedReader.readLine();
        bufferedReader.close();
        ArrayList<String> credentials = new ArrayList<>();
        credentials.add(user);
        credentials.add(password);
        return credentials;
    }
}