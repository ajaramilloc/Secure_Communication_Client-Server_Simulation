package prueba;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Servidor {
    public static void main(String[] args) throws Exception {

        // Generacion de las llaves publica y privada del servidor
        KeyPair pair = RSAKeyPairGenerator();
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();

        System.out.println("Llave publica del servidor: " + publicKey.toString());
        System.out.println("Llave privada del servidor: " + privateKey.toString());
        
        int port = 1234; // Puerto en el que el servidor escucha
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Servidor iniciado en el puerto " + port);

        while (true) {
            Socket socket = serverSocket.accept();
            new DelegadoServidor(socket).start(); // Crea un nuevo delegado para cada cliente
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

class DelegadoServidor extends Thread {
    private Socket socket;

    public DelegadoServidor(Socket socket) {
        this.socket = socket;
    }

    public void run() {
        try {
            // Aquí se implementaría el manejo del protocolo (cifrado, verificación, etc.)
            System.out.println("Conexión desde " + socket.getInetAddress());
            // Ejemplo: Leer datos, procesar y enviar respuesta

            DataInputStream input = new DataInputStream(socket.getInputStream());
            DataOutputStream output = new DataOutputStream(socket.getOutputStream());

            // Leer mensaje del cliente
            byte[] buffer = new byte[1024];
            int len = input.read(buffer);
            String message = new String(buffer, 0, len);
            System.out.println("Mensaje recibido: " + message);

            // Enviar respuesta al cliente
            output.writeUTF("Respuesta del servidor");
            output.flush();

            socket.close();
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
