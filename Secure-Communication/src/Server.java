import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.math.*;

public class Server extends Thread {
    private static final int BASE_PORT = 5000;
    private ServerSocket serverSocket;
    public static PublicKey serverPublicKey;
    private static KeyPair serverPairKey;
    private static BigInteger p;
    private static BigInteger g;

    public Server() throws IOException {
        serverSocket = new ServerSocket(BASE_PORT, 1000000000);
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

        FileReader fileReader = new FileReader("pairKeysSet.txt");
        BufferedReader bufferedReader = new BufferedReader(fileReader);
        String p_hex = bufferedReader.readLine();
        String g_hex = bufferedReader.readLine();
        bufferedReader.close();

        p = new BigInteger(p_hex, 16);
        g = new BigInteger(g_hex, 16);

        int i = 0;
        try {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                new ServerDelegate(clientSocket, serverPairKey, p, g, i).start();
                i++;
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
}