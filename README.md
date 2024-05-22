
# Secure Communication Client-Server Project

## Introduction

This project demonstrates a secure communication system between a client and a server using cryptographic protocols to ensure data confidentiality and integrity. The project involves implementing the client and server in Java, following specific encryption and security guidelines.

## Objectives

- Understand the advantages and limitations of algorithms used for protecting data confidentiality and integrity.
- Develop a prototype tool that ensures data confidentiality and integrity.

## Problem Statement

The project involves creating a client and a server that communicate securely using the provided protocol. The server responds to client queries by decrementing the received number. Communication between the client and server must be encrypted, and the entire system is implemented in Java using standard libraries.

## Key Features

- **Communication**: Uses sockets for communication between the client and server.
- **Encryption**: Implements AES (CBC mode, PKCS5Padding, 256-bit key) for encrypting the data.
- **Signature**: Uses SHA256withRSA for digital signatures.
- **Authentication**: HMACSHA256 for message authentication codes.

## Protocol Details

### Key Generation

1. Calculate a master key using the Diffie-Hellman algorithm.
2. Generate a SHA-512 digest from the master key.
3. Split the digest into two halves for encryption and HMAC keys.
4. Generate a 16-byte initialization vector (IV) randomly for encryption.

### Communication Protocol

The communication protocol ensures secure data exchange by encrypting messages and verifying signatures. Detailed steps can be found in the protocol diagrams.

## Implementation

### Prerequisites

- Java Development Kit (JDK) installed.
- Basic understanding of Java and cryptography concepts.

### Running the Application

1. **Compile the Application**
   ```bash
   javac App.java
   ```

2. **Run the Application**
   ```bash
   java App
   ```

### Configuration

- Number of concurrent clients can be configured within the application settings.

## Performance Evaluation

Measure performance for different numbers of concurrent clients (e.g., 4, 16, 32) focusing on:

- Client-side operations:
  - Signature verification
  - Calculation of `Gy`
  - Query encryption
  - Authentication code generation

- Server-side operations:
  - Signature generation
  - Query decryption
  - Authentication code verification

## References

- "Cryptography and Network Security," W. Stallings, Prentice Hall, 2003.
- "Computer Networks," A. S. Tanenbaum, 4th Edition, Prentice Hall, 2003.
- Various online resources for cryptographic algorithms and protocols.
