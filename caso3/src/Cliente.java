import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;
import java.math.BigInteger;

public class Cliente {
    public static void main(String[] args) {
        String hostname = "localhost";
        int port = 1234;

        try {
            Socket socket = new Socket(hostname, port);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedReader stdInput = new BufferedReader(new InputStreamReader(System.in));

            // Paso 1: Cliente envía un número aleatorio al servidor
            BigInteger reto = generateRandomNumber();

            out.println(reto);

            String serverResponse = in.readLine();
            System.out.println("Respuesta del servidor: " + serverResponse);

            out.close();
            in.close();
            stdInput.close();
            socket.close();
        } catch (UnknownHostException e) {
            System.out.println("Servidor no encontrado: " + e.getMessage());
        } catch (IOException e) {
            System.out.println("Error de I/O: " + e.getMessage());
        }
    }


    public static BigInteger generateRandomNumber() {
        SecureRandom random = new SecureRandom();
        int numBits = 256;
        return new BigInteger(numBits, random);
    }
}
