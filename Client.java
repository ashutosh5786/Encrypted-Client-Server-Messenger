import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.*;
import javax.crypto.*;
import java.util.Base64;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

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
            // System.out.flush();

            // Hash the UserID using MD5 algorithm
            String hashedUserID = hashUserID(userID);
            out.println(hashedUserID); // Send the hashed UserID to the server immediately after connection


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
                } else {
                    // Decrypt and display the message
                    String[] parts = serverMessage.split(" ");
                    String encryptedMessage = parts[0];
                    String encryptedTimestamp = parts[1];
                    String signature = parts[2];

                    // Verify the signature
                    PublicKey serverPublicKey = getPublicKey("server"); // Load server's public key
                    if (verifySignature(encryptedMessage + " " + encryptedTimestamp, signature, serverPublicKey)) {

                        // Decrypt the message and timestamp with client private key
                        String decryptedMessage = decrypt(encryptedMessage, getPrivateKey(userID));
                        String decryptedTimestamp = decrypt(encryptedTimestamp, getPrivateKey(userID));

                        System.out.println("Server: " + decryptedMessage + " [Timestamp: " + decryptedTimestamp + "]");
                        messagesRead++;
                    } else {
                        System.out.println("Invalid signature. Message ignored.");
                    }
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
                    // System.out.flush();
                    String recipientUserID = userInput.readLine();

                    System.out.println("Enter your message:");
                    System.out.flush();
                    String message = userInput.readLine();
                    String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

                    // Encrypt the message and timestamp with seerver's public key
                    String encryptedMessage = encrypt(message, getPublicKey("server"));
                    String encryptedTimestamp = encrypt(timestamp, getPublicKey("server"));

                    // Generate signature for the encrypted message and timestamp
                    String signature = sign(encryptedMessage + " " + encryptedTimestamp, getPrivateKey(userID));

                    // Send the encrypted message, timestamp, and signature to the server
                    out.println(encryptedMessage + " " + encryptedTimestamp + " " + signature + " " + recipientUserID + " " + userID);                    


                }
            } while (response.equalsIgnoreCase("y"));

            socket.close();
            System.out.println("Exiting...");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String encryptedText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes);
    }

    private static String sign(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    private static boolean verifySignature(String message, String signature, PublicKey publicKey) throws Exception {
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initVerify(publicKey);
        sign.update(message.getBytes());
        return sign.verify(Base64.getDecoder().decode(signature));
    }

    private static String hashUserID(String userID) throws NoSuchAlgorithmException {
        String secretString = "gfhk2024:";
        String toHash = secretString + userID;
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hashedBytes = md.digest(toHash.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : hashedBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static PrivateKey getPrivateKey(String userID) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(userID + ".prv"));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private static PublicKey getPublicKey(String userID) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(userID + ".pub"));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
