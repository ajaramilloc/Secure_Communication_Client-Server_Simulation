import java.net.*;
import java.io.*;
import java.util.*;
import java.security.*;
import java.math.*;

public class ServerDelegate extends Thread {
    private Socket socket;
    private DataOutputStream output;
    private DataInputStream input;
    private KeyPair keyPair;

    public ServerDelegate(Socket socket, int port, KeyPair keyPair) {
        this.socket = socket;
        this.keyPair = keyPair;
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
                    SecureRandom random = new SecureRandom();
                    BigInteger G = BigInteger.probablePrime(512, random);
                    BigInteger P = BigInteger.probablePrime(512, random);
                    BigInteger x = new BigInteger(512, random);
                    BigInteger Gx = G.modPow(x, P);

                    output.writeUTF(G.toString());
                    output.writeUTF(P.toString());
                    output.writeUTF(Gx.toString());

                    byte[] iv = generateIV();
                    output.write(iv);

                    byte[] signature = signData(G, P, Gx);
                    output.write(signature);

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

    private String signChallenge(long challenge) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(BigInteger.valueOf(challenge).toByteArray());
        byte[] signedData = signature.sign();
        return Base64.getEncoder().encodeToString(signedData);
    }

    private byte[] signData(BigInteger G, BigInteger P, BigInteger Gx) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(G.toByteArray());
        outputStream.write(P.toByteArray());
        outputStream.write(Gx.toByteArray());
        signature.update(outputStream.toByteArray());
        return signature.sign();
    }

    private byte[] generateIV() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return iv;
    }
}