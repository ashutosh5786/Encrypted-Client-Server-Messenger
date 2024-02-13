import java.io.*;
import java.net.*;
import java.util.*;

public class Server {
    private static int PORT;
    private static final Map<String, ClientHandler> clients = new HashMap<>();
    public static Map<String, List<String>> userMessages = new HashMap<>();

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Syntax: java Server <port number>");
            return;
        }

        PORT = Integer.parseInt(args[0]);

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Chat Server is running on port " + PORT);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                ClientHandler clientHandler = new ClientHandler(clientSocket);
                clientHandler.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    static void broadcastMessage(String message, String recipientUserId) {
        if (!userMessages.containsKey(recipientUserId)) {
            userMessages.put(recipientUserId, new ArrayList<>());
        }
        userMessages.get(recipientUserId).add(message);
    }
}

class ClientHandler extends Thread {
    private final Socket clientSocket;
    private BufferedReader in;
    private PrintWriter out;
    private String userName;
    private String recipientUserID;

    public ClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    @Override
    public void run() {
        try {
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out = new PrintWriter(clientSocket.getOutputStream(), true);

            String message;
            while ((message = in.readLine()) != null) {
                if (message.equalsIgnoreCase("exit")) {
                    break;
                }
                if (userName == null) {
                    userName = message;
                    System.out.println(userName + " connected");
                    if (Server.userMessages.containsKey(userName)) {
                        int messageCount = Server.userMessages.get(userName).size();
                        out.println("There are " + messageCount + " message(s) for you.");
                        for (String msg : Server.userMessages.get(userName)) {
                            out.println(msg);
                        }
                        Server.userMessages.remove(userName);
                    } else {
                        out.println("There are 0 messages for you.");
                    }
                    out.println("END"); // Send "END" after sending all messages or if there are no messages
                } else if (recipientUserID == null) {
                    recipientUserID = message;
                    System.out.println("Recipient UserID: " + recipientUserID);
                } else {
                    System.out.println("Incoming Message for " + recipientUserID + " from " + userName);
                    System.out.println("Received message for " + recipientUserID + ": " + message);
                    Server.broadcastMessage(message, recipientUserID); // Pass recipientUserID as second argument
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    void sendMessage(String message) {
        out.println(message);
    }

    String getUserName() {
        return userName;
    }
}