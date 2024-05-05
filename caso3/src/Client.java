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
}
