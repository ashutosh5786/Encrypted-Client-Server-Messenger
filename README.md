# Project Title

This project is a simple client-server application implemented in Java. The server accepts connections from multiple clients and handles their requests concurrently. The clients send encrypted messages to the server, which are then decrypted and stored by the server.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

You need to have Java installed on your machine to run this project. You can download it from the [official Oracle website](https://www.oracle.com/java/technologies/javase-jdk11-downloads.html).

### Installing

Clone the repository to your local machine:

```bash
git clone https://github.com/ashutosh5786/Encrypted-Client-Server-Messenger
```


Navigate to the project directory:
```
cd Encrypted-Client-Server-Messenger
```

Compile the Java files:
```
javac Server.java Client.java
```

## Running the Application
Start the server:
```
java Server <port no>
```

In a new terminal window, start the client:

```
java Client <host> <port> <userID>
```

## Functionality
The server accepts connections from multiple clients. Each client sends messages to the server, which are encrypted with the server's public key. The server decrypts these messages with its private key.

The server stores the messages in a HashMap with the recipient ID as the key and the message as the value. When a client connects, the server sends all messages for that client and then removes them from the HashMap.

The server also hashes the recipient ID with MD5 and a secret string before storing the messages.

## Built With
- Java
## Authors
- Ashutosh Singh/@ashutosh5786
## License
This project is licensed under the MIT License - see the LICENSE.md file for details

## Acknowledgments
Thanks to GitHub Copilot/Chat-GPT for assisting with the code.