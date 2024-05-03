import java.net.*;
import java.util.*;
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
                System.out.println("OK");

                // Receive and process Diffie-Hellman parameters and signature
                String G = input.readUTF();
                System.out.println("G: " + G);
                String P = input.readUTF();
                System.out.println("P: " + P);
                String Gx = input.readUTF();
                System.out.println("Gx: " + Gx);
            } else {
                output.writeUTF("ERROR");
                System.out.println("ERROR");
                closeConnection();
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            System.out.println("Error in ClientDelegate: " + e.getMessage());
        }
    }

    private boolean verifySignature(String signedData, long challenge, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(BigInteger.valueOf(challenge).toByteArray());

        byte[] signatureBytes = Base64.getDecoder().decode(signedData);
        return signature.verify(signatureBytes);
    }

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