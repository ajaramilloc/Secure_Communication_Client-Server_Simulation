
import java.io.*;
import java.net.*;

public class Cliente {
    public static void main(String[] args) {
        String hostname = "localhost";
        int port = 1234;

        try {
            Socket socket = new Socket(hostname, port);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedReader stdInput = new BufferedReader(new InputStreamReader(System.in));

            System.out.println("Cliente conectado al servidor " + hostname + " en el puerto " + port);
            System.out.println("Escriba su mensaje:");
            String userInput = stdInput.readLine();
            out.println(userInput);

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
}
