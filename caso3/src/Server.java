import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;

public class Server {
    private static final int BASE_PORT = 5000;
    private ServerSocket serverSocket;
    public static PublicKey serverPublicKey;
    public static KeyPair serverPairKey;

    public Server() throws IOException {
        serverSocket = new ServerSocket(BASE_PORT);
    }

    public void startServer() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        KeyPair pair = RSAKeyPairGenerator();
        PublicKey publicKey = pair.getPublic();

        serverPublicKey = publicKey;
        serverPairKey = pair;

        String[] x = serverPublicKey.toString().split("\n");
        String mod = x[2].split(":")[1].strip();
        String exp = x[3].split(":")[1].strip();

        FileWriter fileWriter = new FileWriter("publicKey.txt");
        BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
        bufferedWriter.write(mod + "\n");
        bufferedWriter.write(exp + "\n");
        bufferedWriter.close();

        int delegateCount = 0;
        try {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                int delegatePort = BASE_PORT + delegateCount + 1;
                new ServerDelegate(clientSocket, delegatePort, serverPairKey).start();
                delegateCount++;
            }
        }catch (IOException e) {
            System.out.println("Error accepting client connection: " + e.getMessage());
        }
    }

    private static KeyPair RSAKeyPairGenerator() {
        try {
            // Inicializar el generador de pares de claves para RSA
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);

            // Generar el par de claves
            KeyPair pair = keyGen.generateKeyPair();
            return pair;

        } catch (NoSuchAlgorithmException e) {
            System.out.println("RSA Key Pair Generator Algorithm not found: " + e.getMessage());

            return null;
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            Server server = new Server();
            server.startServer();
        } catch (IOException e) {
            System.out.println("Failed to start server: " + e.getMessage());
        }
    }
}