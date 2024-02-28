# Client - Server connection using TCP.

This project, developed in Golang, showcases a basic client-server connection model while integrating encryption techniques. Through this project, I gained valuable experience in network communications and encryption methodologies in Golang.

## Feautes:

- **TCP Connection**: Implements a reliable TCP connection mechanism between the client and server, ensuring stable and efficient communication.

- **RSA Key Pair Generation**: Generates RSA key pairs for secure encryption and decryption of data exchanged between the client and server.

- **Key Exchange with RSA**: Utilizes RSA encryption to securely exchange AES keys and initialization vectors (IVs) between the client and server for AES encryption.

- **AES Data Encryption**: Implements Advanced Encryption Standard (AES) encryption algorithm for encrypting sensitive data transmitted over the network.


## To run do:
```
# Server

cd ./server
go run connectServer.go {PORT}

# Client

cd ./client
go run connectClient.go {IP}:{PORT}

```

Made by: Mario Portilho
