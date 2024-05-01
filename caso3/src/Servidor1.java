import java.io.*;
import java.net.*;
import java.security.*;
import java.util.concurrent.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

public class Servidor1 {
    private ServerSocket serverSocket;
    private ExecutorService pool;

    // Credenciales de acceso al servidor
    private static final String login = "admin";
    private static final String password = "admin";

    // Par claves asimétricas RSA
    private static PublicKey publicServerKey;
    private static  PrivateKey privateServerKey;
    

    public Servidor1(int port, int poolSize) {
        try {
            serverSocket = new ServerSocket(port);
            pool = Executors.newFixedThreadPool(poolSize);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void start() {
        System.out.println("Server started on port " + serverSocket.getLocalPort());

        // Generar un par de claves RSA
        KeyPair pair = RSAKeyPairGenerator();
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();

        publicServerKey = publicKey;
        privateServerKey = privateKey;
        try {
            while (true) {
                // Crear Delegado para manejar la conexión con el cliente
                Socket clientSocket = serverSocket.accept();
                ClientHandler clientHandler = new ClientHandler(clientSocket);
                pool.execute(clientHandler);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        int port = 12345; // Port to listen on
        Servidor1 server = new Servidor1(port, 10);
        server.start();
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
}

class ClientHandler implements Runnable {
    private Socket clientSocket;

    public ClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    @Override
    public void run() {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                System.out.println("Received from client: " + inputLine);
                out.println("Echo: " + inputLine);
            }

            // Generar un vector de inicialización (IV) aleatorio
            byte[] iv = new byte[16]; // AES utiliza bloques de 16 bytes
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
