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
            new ClientDelegate(address, port).start();
        }
    }

    public static void main(String[] args) {
        Client client = new Client("localhost", 5000, 10);
        client.start();  // Starts the client thread which in turn starts 5 client delegates
    }
}
