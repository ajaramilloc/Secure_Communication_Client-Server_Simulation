package prueba;

import java.io.*;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Cliente {
    public static void main(String[] args) {
        // if (args.length < 1) {
        //     System.out.println("Uso: java Cliente <numero de clientes>");
        //     return;
        // }

        // int numClientes = Integer.parseInt(args[0]);
        int numClientes = 10;
        ExecutorService pool = Executors.newFixedThreadPool(numClientes);

        for (int i = 0; i < numClientes; i++) {
            pool.execute(new ClienteRunnable());
        }

        pool.shutdown();
    }
}

class ClienteRunnable implements Runnable {
    private static final String HOST = "localhost";
    private static final int PORT = 1234;

    @Override
    public void run() {
        try (Socket socket = new Socket(HOST, PORT)) {
            System.out.println("Conectado al servidor en " + HOST + ":" + PORT);
            // Enviar una consulta cifrada

            DataOutputStream output = new DataOutputStream(socket.getOutputStream());
            DataInputStream input = new DataInputStream(socket.getInputStream());

            // OutputStream outputStream = socket.getOutputStream();
            output.write("Consulta".getBytes());
            output.flush();
            System.out.println("Consulta enviada desde " + Thread.currentThread().getName());

            String respuesta = input.readUTF(); // Esperar respuesta

            System.out.println("Respuesta recibida en " + Thread.currentThread().getName() + ": " + respuesta);

        } catch (Exception e) {
            System.out.println("Error en cliente " + Thread.currentThread().getName() + ": " + e.getMessage());
        }
    }
}
