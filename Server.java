import java.io.*;
import java.net.*;
import java.util.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.security.PublicKey;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.PrivateKey;
import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

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

    static void broadcastMessage(String message, String senderUserName, String hashedRecipientUserID,
            String recipientUserID) {
        if (!userMessages.containsKey(hashedRecipientUserID)) {
            userMessages.put(hashedRecipientUserID, new ArrayList<>());
        }
        userMessages.get(hashedRecipientUserID).add(message);
        // Print the sender and recipient user IDs, timestamp, and message contents
        System.out.println("Incoming Message From " + senderUserName);
    }

}

class ClientHandler extends Thread {
    private final Socket clientSocket;
    private BufferedReader in;
    private PrintWriter out;
    private String userName;
    private String recipientUserID;
    private String hashedUserID;

    public ClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    private static PublicKey getPublicKey(String userID) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(userID + ".pub"));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    private static boolean verifySignature(String message, String signature, PublicKey publicKey) throws Exception {
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initVerify(publicKey);
        sign.update(message.getBytes());
        return sign.verify(Base64.getDecoder().decode(signature));
    }

    private static PrivateKey getPrivateKey(String userID) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(userID + ".prv"));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private static String decrypt(String encryptedText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes);
    }

    private static String hashRID(String recipientUserID) throws NoSuchAlgorithmException {
        String secret = "gfhk2024:";
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hashedBytes = md.digest((secret + recipientUserID).getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : hashedBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String sign(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    @Override
    public void run() {
        try {
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out = new PrintWriter(clientSocket.getOutputStream(), true);

            String hashedUserID = in.readLine(); // Receive hashed UserID from client
            // String clientId = in.readLine(); // Receive ClientId from client
            String message; // Receive message from client

            if (hashedUserID != null) {
                // if (clientId != null && hashedUserID != null) {
                this.hashedUserID = hashedUserID;
                // userName = clientId;

                // System.out.println(message);
                System.out.println(hashedUserID + " connected");
                // System.out.println(clientId + " connected");
                if (Server.userMessages.containsKey(hashedUserID)) {
                    int messageCount = Server.userMessages.get(hashedUserID).size();
                    out.println("There are " + messageCount + " message(s) for you.");
                    for (String msg : Server.userMessages.get(hashedUserID)) {
                        out.println(msg);
                    }
                    Server.userMessages.remove(hashedUserID);
                } else {
                    out.println("There are 0 messages for you.");
                }

                while ((message = in.readLine()) != null) {
                    String[] parts = message.split(" ");
                    String encryptedMessage = parts[0];
                    String encryptedTimestamp = parts[1];
                    String signature = parts[2];
                    String recipientUserID = parts[3];
                    String userName = parts[4];
                    String hashedRecipientUserID = hashRID(recipientUserID);

                    // Verify the signature
                    try {
                        int messagesRead = 0; // Declare and initialize messagesRead variable
                        PublicKey clientPublicKey = getPublicKey(userName); // Load client's public key
                        if (verifySignature(encryptedMessage + " " + encryptedTimestamp, signature, clientPublicKey)) {
                            // Decrypt the message and timestamp
                            try {
                                String decryptedMessage;
                                String decryptedTimestamp;
                                // Decrypt the message and timestamp with the server private key first step
                                decryptedMessage = decrypt(encryptedMessage, getPrivateKey("server"));
                                decryptedTimestamp = decrypt(encryptedTimestamp, getPrivateKey("server"));

                                // Now Encrypt the message and timestamp with the recipient's public key second
                                // step
                                String encryptedMessage2 = encrypt(decryptedMessage, getPublicKey(recipientUserID));
                                String encryptedTimestamp2 = encrypt(decryptedTimestamp, getPublicKey(recipientUserID));

                                // Now sign the message and timestamp with the server private key third step
                                String reMessage = encryptedMessage2 + " " + encryptedTimestamp2 + " "
                                        + sign(encryptedMessage2 + " " + encryptedTimestamp2, getPrivateKey("server"));

                                // Broadcast the messaage for the message to store in the userMessages step four
                                Server.broadcastMessage(reMessage, userName, hashedRecipientUserID, recipientUserID); // Broadcast

                                System.out.println(
                                        "Recipient: " + recipientUserID + "\nMessage: " + decryptedMessage
                                                + "\nTimestamp: "
                                                + LocalDateTime.now()
                                                        .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
                            } catch (Exception e) {
                                System.out.println("Failed to decrypt message or timestamp: " + e.getMessage());
                                return;
                            }
                            messagesRead++; // Increment messagesRead
                        } else {
                            System.out.println("Invalid signature. Message ignored.");
                        }
                    } catch (Exception e) {
                        System.out.println("Error occurred: " + e.getMessage());
                    }
                }
            } else {
                System.out.println("Failed to authenticate user.");
                out.println("Failed to authenticate user.");
                return;
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
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
