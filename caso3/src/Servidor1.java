import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.util.concurrent.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
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

    public void start() throws InvalidAlgorithmParameterException {
        System.out.println("Server started on port " + serverSocket.getLocalPort());

        // Generar un par de claves RSA
        KeyPair pair = RSAKeyPairGenerator();
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();

        publicServerKey = publicKey;
        privateServerKey = privateKey;

        DH();
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

    public static void main(String[] args) throws InvalidAlgorithmParameterException {
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

    private static void DH() throws InvalidAlgorithmParameterException{
        try {
            
            // Inicializar los parámetros de Diffie-Hellman (estos valores son solo un ejemplo)
            // Primo p
            String hexPrime = "00a16edf36080bf8293a14699324d5fbfe83ae4bfb4913276cbe686a103d0adc261e20b589a6f5ab95f97a720549a18a10eac782fc53097fa21dc3b9315a6e836cdcb94595a8f50dcaf33a9dc40e3ad6db91822384e63ea3b0daaa12ab4e61a31312ea0882de6eb88d4dfa28943376b9fe3ecc8e3e2db7e2ed89f4069df76be877";
            BigInteger p = new BigInteger(hexPrime, 16);
            // Generador g
            BigInteger g = new BigInteger("2", 16); // Reemplaza "valor_de_g" con el valor real
            DHParameterSpec dhSpec = new DHParameterSpec(p, g);

            // Generar par de claves Diffie-Hellman
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(dhSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Supongamos que ambos usuarios tienen la misma llave maestra ahora, ej. la parte pública de otra entidad
            BigInteger masterKey = ((DHPublicKey) keyPair.getPublic()).getY(); // Simulación de llave maestra

            // Calcular SHA-512 de la llave maestra
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(masterKey.toByteArray());

            // Dividir el digest en llaves de cifrado y HMAC
            byte[] encryptionKey = Arrays.copyOfRange(digest, 0, 32); // Primeros 256 bits
            byte[] hmacKey = Arrays.copyOfRange(digest, 32, 64); // Últimos 256 bits

            // Imprimir las llaves en hexadecimal
            System.out.println("Llave para cifrado (hex): " + bytesToHex(encryptionKey));
            System.out.println("Llave para HMAC (hex): " + bytesToHex(hmacKey));

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error durante la generación de claves o digest");
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
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
                out.println(inputLine);

                // Generar un vector de inicialización (IV) aleatorio
                byte[] iv = new byte[16]; // AES utiliza bloques de 16 bytes
                SecureRandom random = new SecureRandom();
                random.nextBytes(iv);
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            }

            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
