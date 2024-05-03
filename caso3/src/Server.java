import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.math.*;

public class Server extends Thread {
    private static final int BASE_PORT = 5000;
    private ServerSocket serverSocket;
    public static PublicKey serverPublicKey;
    public static KeyPair serverPairKey;
    private static BigInteger p;
    private static BigInteger g;

    public Server() throws IOException {
        serverSocket = new ServerSocket(BASE_PORT);
    }

    @Override
    public void run() {
        try {
            startServer();
        } catch (Exception e) {
            System.out.println("Failed to start server: " + e.getMessage());
        }
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

        String hex = "CD19554B8C909F80FF7F2C51EF6F0CC289FD37B27F42F001B1AB05929849DB4C" +
                     "1CF35881E2C728E1701451CAE6514A4D835F34AD226A2EDEDC8C9EC11EFA6E97" +
                     "2984D67553F123D643CC8F603A8DD265F41158E73B858E62AB40D06744F209E2" +
                     "6871FC3977DF03E08229C131C1333DC8F8F599804D55821AC63333FEC882035F";
        p = new BigInteger(hex, 16);
        g = new BigInteger("2", 16);

        int delegateCount = 0;
        try {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                int delegatePort = BASE_PORT + delegateCount + 1;
                new ServerDelegate(clientSocket, delegatePort, serverPairKey, p, g).start();
                delegateCount++;
            }
        } catch (IOException e) {
            System.out.println("Error accepting client connection: " + e.getMessage());
        }
    }

    private static KeyPair RSAKeyPairGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    public static void main(String[] args) {
        try {
            Server server = new Server();
            server.start();
        } catch (IOException e) {
            System.out.println("Server initialization failed: " + e.getMessage());
        }
    }
}