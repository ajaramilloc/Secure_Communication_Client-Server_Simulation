package prueba;

import java.net.*;
import java.io.*;

public class Client {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 12345;

    public static void main(String[] args) {
        for (int i = 0; i < 10; i++) { // Ejemplo para lanzar 10 clientes
            new Thread(() -> {
                try {
                    Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
                    System.out.println("Connected to server.");

                    DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                    DataInputStream input = new DataInputStream(socket.getInputStream());

                    // Send initial message
                    String message = "Secure Init Cliente ";
                    output.writeUTF(message);
                    output.flush();

                    // Receive response
                    String response = input.readUTF();
                    System.out.println("Server says: " + response);

                    socket.close();
                    System.out.println("Disconnected from server.");
                } catch (IOException e) {
                    System.out.println("Error: " + e.getMessage());
                    e.printStackTrace();
                }
            }).start();
        }
    }
}
