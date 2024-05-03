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
                BigInteger Gb = new BigInteger(G);
                String P = input.readUTF();
                BigInteger Pb = new BigInteger(P);
                String Gx = input.readUTF();
                BigInteger Gbx = new BigInteger(Gx);
                String iv = input.readUTF();

                String signature = input.readUTF();

                if (verifyMasterKey(signature, Gb, Pb, Gbx, publicKey)) {
                    output.writeUTF("OK");
                    System.out.println("Master key verified");
                } else {
                    output.writeUTF("ERROR");
                    System.out.println("Master key not verified");
                }


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