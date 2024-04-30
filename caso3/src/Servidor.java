import java.io.*;
import java.net.*;

public class Servidor {
    public static void main(String[] args) {
        int port = 1234; // Puerto en el que escucha el servidor
        ServerSocket serverSocket = null;

        try {
            serverSocket = new ServerSocket(port);
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
}
