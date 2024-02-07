import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class Client {
    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage: java Client <host> <port> <userID>");
            System.out.flush();
            return;
        }

        String serverAddress = args[0];
        int port = Integer.parseInt(args[1]);
        String userID = args[2];

        try (
                Socket socket = new Socket(serverAddress, port);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in))) {
            System.out.println("Connected to chat server");
            System.out.flush();

            out.println(userID); // Send the user's userID to the server immediately after connection

            // Read and display messages from the server
            String serverMessage;
            int messageCount = 0;
            int messagesRead = 0;
            while ((serverMessage = in.readLine()) != null) {
                if (messageCount == 0) {
                    // The first message from the server will be the number of messages
                    String[] parts = serverMessage.split(" ");
                    messageCount = Integer.parseInt(parts[2]); // The number of messages is the third word in the
                                                               // message
                    System.out.println("Server: " + serverMessage);
                } else {
                    System.out.println("Server: " + serverMessage);
                    messagesRead++;
                }
                if (messagesRead >= messageCount) {
                    break;
                }
            }

            String response;
            do {
                System.out.println("Do you want to send a message? (y/n)");
                System.out.flush();
                response = userInput.readLine();
                if (response.equalsIgnoreCase("y")) {
                    System.out.println("Enter recipient userID:");
                    System.out.flush();
                    String recipientUserID = userInput.readLine();
                    out.println(recipientUserID); // Send the recipient's userID to the server

                    System.out.println("Enter your message:");
                    System.out.flush();
                    String message = userInput.readLine();
                    out.println(message); // Send the message to the server
                }
            } while (response.equalsIgnoreCase("y"));

            System.out.println("Exiting...");
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}