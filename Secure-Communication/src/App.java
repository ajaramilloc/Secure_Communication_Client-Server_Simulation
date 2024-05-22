import java.io.IOException;
import java.util.Scanner;

public class App {
    private static final int BASE_PORT = 5000;

    public static void main(String[] args) throws IOException {
        Server server = new Server();
        server.start();

        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            System.out.println("Main thread interrupted.");
        }

        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter the number of clients: ");
        int numberOfClients = scanner.nextInt();
        scanner.close();

        Client client = new Client("localhost", BASE_PORT, numberOfClients);
        client.start();
    }
}
