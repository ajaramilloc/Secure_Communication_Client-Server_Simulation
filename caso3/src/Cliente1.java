import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;
import java.math.BigInteger;

public class Cliente1 implements Runnable {
    private Socket socket;
    private String serverAddress;
    private int serverPort;

    public Cliente1(String addr, int port) {
        this.serverAddress = addr;
        this.serverPort = port;
    }

    @Override
    public void run() {
        try {
            socket = new Socket(serverAddress, serverPort);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // Paso 1: Cliente envía un número aleatorio al servidor
            BigInteger reto = generateRandomNumber();

            // Enviar un mensaje al servidor
            out.println("Hello from " + Thread.currentThread().getName() + " with challenge: " + reto);

            // Leer la respuesta del servidor
            String response = in.readLine();
            System.out.println(Thread.currentThread().getName() + " received: " + response);

            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        String host = "localhost";
        int port = 12345;
        for (int i = 0; i < 5; i++) {
            Thread clientThread = new Thread(new Cliente1(host, port), "Client-" + i);
            clientThread.start();
        }
    }

    public static BigInteger generateRandomNumber() {
        SecureRandom random = new SecureRandom();
        int numBits = 256;
        return new BigInteger(numBits, random);
    }
}


