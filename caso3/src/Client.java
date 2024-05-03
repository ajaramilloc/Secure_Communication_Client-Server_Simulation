public class Client {
    private String address;
    private int port;

    public Client(String address, int port) {
        this.address = address;
        this.port = port;
    }

    public void startClient(int numberOfDelegates) {
        for (int i = 0; i < numberOfDelegates; i++) {
            new ClientDelegate(address, port).start();
        }
    }

    public static void main(String[] args) {
        Client client = new Client("localhost", 5000);
        client.startClient(5);  // Starts 5 client delegates
    }
}