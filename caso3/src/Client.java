import java.util.Scanner;

public class Client extends Thread {
    private String address;
    private int port;
    private int numberOfDelegates;

    public Client(String address, int port, int numberOfDelegates) {
        this.address = address;
        this.port = port;
        this.numberOfDelegates = numberOfDelegates;
    }

    @Override
    public void run() {
        startClient();
    }

    private void startClient() {
        for (int i = 0; i < numberOfDelegates; i++) {
            new ClientDelegate(address, port, i).start();
        }
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter the number of clients: ");
        int numberOfClients = scanner.nextInt();
        scanner.close();

        Client client = new Client("localhost", 5000, numberOfClients);
        client.start();
    }
}
