package prueba;

import java.net.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;

public class Server {
    private static final int PORT = 12345;
    private ServerSocket serverSocket;
    private final Map<Integer, DataOutputStream> clients = new ConcurrentHashMap<>();
    private static int clientID = 0;

    public Server() throws Exception {
        serverSocket = new ServerSocket(PORT);
        System.out.println("Server started on port " + PORT);
    }

    public void handleClients() throws Exception {
        while (true) {
            Socket clientSocket = serverSocket.accept();
            int id = clientID++;
            System.out.println("Client connected with ID: " + id);

            DataInputStream input = new DataInputStream(clientSocket.getInputStream());
            DataOutputStream output = new DataOutputStream(clientSocket.getOutputStream());
            clients.put(id, output);

            new Thread(() -> {
                try {
                    handleClient(clientSocket, input, output, id);
                } catch (Exception e) {
                    System.out.println("Error handling client: " + e.getMessage());
                    e.printStackTrace();
                } finally {
                    try {
                        clientSocket.close();
                        clients.remove(id);
                        System.out.println("Client disconnected with ID: " + id);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }).start();
        }
    }

    private void handleClient(Socket clientSocket, DataInputStream input, DataOutputStream output, int clientId) throws Exception {
        // Simulated server logic
        while (!clientSocket.isClosed()) {
            if (input.available() > 0) {
                String message = input.readUTF();
                System.out.println("Received from " + clientId + ": " + message);

                // Example response to this client only
                sendMessage(clientId, "Hello specifically to you, client " + clientId);
            }
        }
    }

    public void sendMessage(int clientId, String message) throws IOException {
        DataOutputStream output = clients.get(clientId);
        if (output != null) {
            output.writeUTF(message);
            output.flush();
        }
    }

    public static void main(String[] args) {
        try {
            Server server = new Server();
            server.handleClients();
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
