package prueba;

import java.io.*;
import java.net.*;
import java.util.*;

// Clase Servidor
class Servidor {
    public static void main(String[] args) {
        final int puerto = 12345; // Puerto en el que el servidor escucha las conexiones

        try (ServerSocket servidorSocket = new ServerSocket(puerto)) {
            System.out.println("Servidor escuchando en el puerto " + puerto);
            List<PrintWriter> clientes = new ArrayList<>(); // Lista de clientes conectados

            while (true) {
                Socket clienteSocket = servidorSocket.accept(); // Espera a que un cliente se conecte
                System.out.println("Nuevo cliente conectado: " + clienteSocket);

                // Crea un hilo para manejar la comunicación con el cliente
                Thread hiloCliente = new Thread(() -> {
                    try {
                        PrintWriter salida = new PrintWriter(clienteSocket.getOutputStream(), true);
                        BufferedReader entrada = new BufferedReader(new InputStreamReader(clienteSocket.getInputStream()));
                        clientes.add(salida); // Agrega el flujo de salida del cliente a la lista

                        // Lee los mensajes del cliente y los retransmite a todos los clientes conectados
                        String mensaje;
                        while ((mensaje = entrada.readLine()) != null) {
                            System.out.println("Mensaje recibido de " + clienteSocket + ": " + mensaje);
                            for (PrintWriter cliente : clientes) {
                                cliente.println(mensaje);
                            }
                        }
                    } catch (IOException e) {
                        System.out.println("Error al manejar la conexión con el cliente: " + e.getMessage());
                    } finally {
                        clientes.removeIf(cliente -> cliente.equals(clienteSocket));
                        try {
                            clienteSocket.close(); // Cierra la conexión con el cliente
                        } catch (IOException e) {
                            System.out.println("Error al cerrar la conexión con el cliente: " + e.getMessage());
                        }
                    }
                });
                hiloCliente.start(); // Inicia el hilo para manejar la comunicación con el cliente
            }
        } catch (IOException e) {
            System.out.println("Error en el servidor: " + e.getMessage());
        }
    }
}