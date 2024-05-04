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

    public ServerDelegate(Socket socket, KeyPair keyPair, BigInteger p, BigInteger g) {
        this.socket = socket;
        this.keyPair = keyPair;
        this.p = p;
        this.g = g;
    }

    public void run() {
        try {
            input = new DataInputStream(socket.getInputStream());
            output = new DataOutputStream(socket.getOutputStream());

            // Init
            String clientMessage = input.readUTF();
            // Receiva R
            if (clientMessage.startsWith("SECURE INIT")) {
                long challenge = Long.parseLong(clientMessage.split(" ")[2]);
                // Sign R'
                String R = signChallenge(challenge);
                // Send R'
                output.writeUTF(R);

                // Clients verification
                String clientResponse = input.readUTF();
                // Verified
                if (clientResponse.equals("OK")) {
                    // Generate Diffie-Hellman parameters
                    BigInteger G = g;
                    BigInteger P = p;
                    // Generate X
                    SecureRandom random = new SecureRandom();
                    BigInteger x = new BigInteger(1024, random);
                    // Generate Gx
                    BigInteger Gx = g.modPow(x, p);

                    // Send G, P, Gx
                    output.writeUTF(G.toString());
                    output.writeUTF(P.toString());
                    output.writeUTF(Gx.toString());

                    // Generate IV
                    String iv = generateIV();
                    // Send IV
                    output.writeUTF(iv);

                    // Sign G, P, Gx
                    String signature = signData(G, P, Gx);
                    // Send signature
                    output.writeUTF(signature);

                    // Receive and process Diffie-Hellman parameters and signature
                    String clientVerification = input.readUTF();
                    // Verified
                    if (clientVerification.equals("OK")) {
                        // Receive Gy
                        String Gy = input.readUTF();
                        BigInteger Gby = new BigInteger(Gy);

                        // Generate master key
                        BigInteger masterKey = Gby.modPow(x, P);
                        // Generate keys
                        ArrayList<byte[]> keys = generateKeys(masterKey);

                        // Generate simetric key
                        Cipher cipher = generateSimetricKey(keys.get(0), iv);
                        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

                        // Generate hash
                        Mac mac = generateHash(keys.get(1));
                        mac.init(hashKeySpec);

                        output.writeUTF("CONTINUAR");

                        ArrayList<String> credentials = getServerCredentials();

                        String serverUser = credentials.get(0);
                        String serverPassword = credentials.get(1);

                        String user = input.readUTF();
                        String password = input.readUTF();

                        byte[] userBytes = Base64.getDecoder().decode(user);
                        byte[] passwordBytes = Base64.getDecoder().decode(password);

                        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

                        byte[] decryptedUserBytes = cipher.doFinal(userBytes);
                        String decryptedUser = new String(decryptedUserBytes);

                        byte[] decryptedPasswordBytes = cipher.doFinal(passwordBytes);
                        String decryptedPassword = new String(decryptedPasswordBytes);

                        if (decryptedUser.equals(serverUser) && decryptedPassword.equals(serverPassword)) {
                            output.writeUTF("OK");

                            String consultation = input.readUTF();
        
                            byte[] consultationBytes = Base64.getDecoder().decode(consultation);
                            
                            byte[] decryptedConsultationBytes = cipher.doFinal(consultationBytes);
                            String decryptedConsultation = new String(decryptedConsultationBytes);

                            int consultationResult = Integer.parseInt(decryptedConsultation);
                            int result = consultationResult - 1;
                            String resultString = Integer.toString(result);

                            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
                            
                            byte[] cypherResultBytes = cipher.doFinal(resultString.getBytes());
                            String cypherResultNumber = Base64.getEncoder().encodeToString(cypherResultBytes);

                            output.writeUTF(cypherResultNumber);

                            byte[] hmacBytes = mac.doFinal(resultString.getBytes());
                            String hmacResultNumber = Base64.getEncoder().encodeToString(hmacBytes);

                            output.writeUTF(hmacResultNumber);
                        } else {
                            output.writeUTF("ERROR");
                        }

                    } else {
                        System.out.println("Client not verified");
                        input.close();
                        output.close();
                        socket.close();
                    }

                // Not Verified
                } else {
                    System.out.println("Error: client response not OK");
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