import java.io.*;
import java.net.*;
import java.math.BigInteger;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

public class Servidor {
    
    // Credenciales de acceso al servidor
    private static final String login = "admin";
    private static final String password = "admin";

    // Par claves asimétricas RSA
    private static PublicKey publicServerKey;
    private static  PrivateKey privateServerKey;

    public static void main(String[] args) {
        int port = 1234; // Puerto en el que escucha el servidor
        ServerSocket serverSocket = null;

        try {
            serverSocket = new ServerSocket(port);

            // Generar un par de claves RSA
            KeyPair pair = RSAKeyPairGenerator();
            PublicKey publicKey = pair.getPublic();
            PrivateKey privateKey = pair.getPrivate();

            publicServerKey = publicKey;
            privateServerKey = privateKey;

            System.out.println("Servidor iniciado, escuchando en el puerto " + port);

            

            while (true) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    System.out.println("Cliente conectado.");
                    new Thread(new Handler(clientSocket)).start();
                } catch (IOException e) {
                    System.out.println("Error al aceptar conexión de cliente: " + e.getMessage());
                    // No detenemos el bucle porque queremos que el servidor siga corriendo
                }
            }
        } catch (IOException e) {
            System.out.println("No se pudo abrir el socket del servidor en el puerto " + port + ": " + e.getMessage());
        } finally {
            if (serverSocket != null) {
                try {
                    serverSocket.close();
                } catch (IOException e) {
                    System.out.println("Error al cerrar el socket del servidor: " + e.getMessage());
                }
            }
        }
    }

    private static class Handler implements Runnable {
        private Socket clientSocket;

        public Handler(Socket socket) {
            this.clientSocket = socket;
        }

        public void run() {
            try {
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

                String clientInput;
                while ((clientInput = in.readLine()) != null) {
                    System.out.println("Mensaje recibido del cliente: " + clientInput);
                    out.println("Eco del servidor: " + clientInput); // El servidor responde con un eco

                    // Diffie-Hellman

                    // Generar un vector de inicialización (IV) aleatorio
                    byte[] iv = new byte[16]; // AES utiliza bloques de 16 bytes
                    SecureRandom random = new SecureRandom();
                    random.nextBytes(iv);
                    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        
                }
            } catch (IOException e) {
                System.out.println("Error al manejar al cliente: " + e.getMessage());
            } finally {
                try {
                    clientSocket.close();
                } catch (IOException e) {
                    System.out.println("No se pudo cerrar el socket del cliente.");
                }
            }
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
}
