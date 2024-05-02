import java.net.*;
import java.io.*;
import java.security.*;
import java.util.Random;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.math.BigInteger;

public class Server {
    private static final int BASE_PORT = 5000;
    private ServerSocket serverSocket;

    public Server() throws IOException {
        serverSocket = new ServerSocket(12345);
    }

    public void startServer() {
        int delegateCount = 0;
        try {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                int delegatePort = BASE_PORT + delegateCount + 1;
                new ServerDelegate(clientSocket, delegatePort).start();
                delegateCount++;
            }
        }catch (IOException e) {
            System.out.println("Error accepting client connection: " + e.getMessage());
        }
    }

    private class ServerDelegate extends Thread {
        private Socket socket;
        private int port;
        private DataOutputStream output;
        private DataInputStream input;

        public ServerDelegate(Socket socket, int port) {
            this.socket = socket;
            this.port = port;
        }

        public void run() {
            try {
                input = new DataInputStream(socket.getInputStream());
                output = new DataOutputStream(socket.getOutputStream());

                String clientMessage = input.readUTF();
                if (clientMessage.startsWith("SECURE INIT")) {
                    long challenge = Long.parseLong(clientMessage.split(" ")[2]);
                    BigInteger R = signChallenge(challenge);
                    output.writeUTF(R.toString());

                    String clientResponse = input.readUTF();
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
                    } else {
                        input.close();
                        output.close();
                        socket.close();
                    }
                }
            } catch (Exception e) {
                System.out.println("Error in ServerDelegate: " + e.getMessage());
            }
        }

        private BigInteger signChallenge(long challenge) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
            Signature signature = Signature.getInstance("SHA256withRSA");
            KeyPair keyPair = generateKeyPair();
            signature.initSign(keyPair.getPrivate());
            signature.update(BigInteger.valueOf(challenge).toByteArray());
            byte[] signedData = signature.sign();
            return new BigInteger(signedData);
        }

        private byte[] signData(BigInteger G, BigInteger P, BigInteger Gx) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
            Signature signature = Signature.getInstance("SHA256withRSA");
            KeyPair keyPair = generateKeyPair();
            signature.initSign(keyPair.getPrivate());
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(G.toByteArray());
            outputStream.write(P.toByteArray());
            outputStream.write(Gx.toByteArray());
            signature.update(outputStream.toByteArray());
            return signature.sign();
        }

        private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        }

        private byte[] generateIV() {
            SecureRandom random = new SecureRandom();
            byte[] iv = new byte[16];
            random.nextBytes(iv);
            return iv;
        }
    }

    public static void main(String[] args) {
        try {
            Server server = new Server();
            System.out.println("Server started on port " + BASE_PORT);
            server.startServer();
        } catch (IOException e) {
            System.out.println("Failed to start server: " + e.getMessage());
        }
    }
}