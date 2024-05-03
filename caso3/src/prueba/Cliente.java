package prueba;

import java.io.*;
import java.net.Socket;
import java.util.*;

// Clase Cliente
class Cliente {
    public static void main(String[] args) {
        final String host = "localhost"; // Dirección IP del servidor
        final int puerto = 12345; // Puerto en el que el servidor escucha las conexiones

        try (Socket socket = new Socket(host, puerto)) {
            System.out.println("Conectado al servidor en " + host + ":" + puerto);
            BufferedReader entrada = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter salida = new PrintWriter(socket.getOutputStream(), true);
            Scanner scanner = new Scanner(System.in);

            // Lee los mensajes del usuario y los envía al servidor
            while (true) {
                System.out.print("Mensaje: ");
                String mensaje = scanner.nextLine();
                salida.println(mensaje);

                // Si el mensaje es "adios", cierra la conexión y termina el programa
                if (mensaje.equalsIgnoreCase("adios")) {
                    break;
                }

                // Muestra los mensajes recibidos del servidor
                System.out.println("Respuesta del servidor: " + entrada.readLine());
            }
            scanner.close();
        } catch (IOException e) {
            System.out.println("Error en el cliente: " + e.getMessage());
        }
    }
}