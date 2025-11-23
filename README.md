# Secure Message Encryption Application

**Author:** Paul Sommers
**Course:** SDEV 245 - Secure Software Development
**Midterm:** Module 4 - Secure Hashing and Encryption

## Overview

This application demonstrates the practical implementation of confidentiality, integrity, and availability through the use of SHA-256 hashing and AES-256 symmetric encryption. The web-based interface allows users to encrypt messages, verify their integrity, and decrypt them securely.

## Features

- **Message Encryption**: Encrypts user input using AES-256 in CBC mode
- **Hash Generation**: Creates SHA-256 hashes for integrity verification
- **Message Decryption**: Decrypts encrypted messages using the correct key and IV
- **Integrity Verification**: Compares hashes to ensure message authenticity
- **Web Interface**: Clean, user-friendly interface for all operations

## Security Concepts Implemented

### Confidentiality
The application ensures confidentiality through AES-256 encryption, which converts plaintext messages into ciphertext that cannot be read without the proper decryption key. The use of CBC (Cipher Block Chaining) mode with random initialization vectors ensures that identical messages produce different ciphertexts each time they are encrypted.

### Integrity
Integrity is maintained through SHA-256 cryptographic hashing. Before encryption, the application computes a hash of the original message. After decryption, it computes the hash again and compares it to the original. If the hashes match, the message has not been tampered with. SHA-256 is collision-resistant, meaning it's computationally infeasible to find two different messages with the same hash.

### Availability
The application is designed to be highly available through its web-based architecture. It can be accessed from any device with a web browser, and the Flask framework ensures reliable request handling. The lightweight design minimizes resource usage, allowing the application to run efficiently even on modest hardware.

## Entropy and Key Generation

### Role of Entropy
Entropy is a measure of randomness or unpredictability. In cryptography, high entropy is critical for security because it makes cryptographic keys difficult to guess or brute-force. Low entropy keys can be compromised through dictionary attacks or systematic guessing.

### Key Generation Process
This application uses Python's `secrets` module for key generation, which provides cryptographically strong random numbers suitable for managing security-sensitive data. The `secrets.token_bytes()` function:

1. **Sources randomness** from the operating system's cryptographically secure random number generator
2. **Generates 256 bits (32 bytes)** of random data for AES-256 keys
3. **Ensures high entropy** by using hardware-based random number generation when available
4. **Prevents predictability** by using sources like system timings, hardware noise, and other unpredictable events

The initialization vector (IV) is also generated using `secrets.token_bytes()` to ensure each encryption operation is unique, even when encrypting the same message multiple times with the same key.

## Installation

### Option 1: Using Docker Compose (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/psommers1/Module-4-Assignment-Secure-Message-Encryption.git
cd Module-4-Assignment-Secure-Message-Encryption
```

2. Start the application using Docker Compose:
```bash
docker-compose up
```

3. Open your web browser and navigate to:
```
http://localhost:5000
```

4. To stop the application:
```bash
docker-compose down
```

### Option 2: Manual Installation

1. Clone the repository:
```bash
git clone https://github.com/psommers1/Module-4-Assignment-Secure-Message-Encryption.git
cd Module-4-Assignment-Secure-Message-Encryption
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Start the Flask application:
```bash
python app.py
```

4. Open your web browser and navigate to:
```
http://localhost:5000
```

## Usage

1. **To Encrypt a Message:**
   - Enter your message in the text area
   - Click "Encrypt Message"
   - The encrypted message, key, IV, and hash will be displayed
   - These values are automatically copied to the decryption fields for testing

2. **To Decrypt a Message:**
   - Paste the encrypted message, key, IV, and original hash
   - Click "Decrypt & Verify"
   - The decrypted message will be displayed along with integrity verification results

## Technical Details

### Encryption Algorithm
- **Algorithm:** AES (Advanced Encryption Standard)
- **Key Size:** 256 bits
- **Mode:** CBC (Cipher Block Chaining)
- **Padding:** PKCS7
- **IV Size:** 128 bits (randomly generated for each encryption)

### Hashing Algorithm
- **Algorithm:** SHA-256 (Secure Hash Algorithm 256-bit)
- **Output Size:** 256 bits (64 hexadecimal characters)
- **Collision Resistance:** Computationally infeasible to find two inputs with the same hash

### Dependencies
- **Flask 3.0.0:** Web framework for the application
- **cryptography 41.0.7:** Provides cryptographic primitives including AES and hashing
- **Werkzeug 3.0.1:** WSGI utility library (Flask dependency)

## Project Structure

```
Module 4 - Assignment - Secure Message Encryption/
├── app.py                 # Main Flask application with encryption/decryption logic
├── templates/
│   └── index.html        # Web interface
├── requirements.txt       # Python dependencies
├── README.md             # This file
└── explanation.txt       # Detailed security concepts explanation
```

## Security Notes

**Important:** This application is designed for educational purposes. In a production environment:
- Keys should NEVER be transmitted to the client
- Keys should be derived from user passwords using key derivation functions (e.g., PBKDF2, Argon2)
- Keys should be stored securely using hardware security modules or encrypted key stores
- HTTPS should be used for all communications
- Additional authentication and authorization mechanisms should be implemented

## How It Works

1. **Encryption Process:**
   - User enters a message
   - System generates a cryptographically secure random key (32 bytes for AES-256)
   - System computes SHA-256 hash of the original message
   - System generates a random IV (16 bytes)
   - Message is padded using PKCS7 to align with AES block size
   - Message is encrypted using AES-256-CBC with the key and IV
   - Encrypted message, key, IV, and hash are returned to the user

2. **Decryption Process:**
   - User provides encrypted message, key, IV, and original hash
   - System decrypts the message using AES-256-CBC
   - System removes PKCS7 padding
   - System computes SHA-256 hash of the decrypted message
   - System compares the new hash with the original hash
   - Integrity status (verified/failed) is displayed to the user

## License

This project is created for educational purposes as part of SDEV 245 coursework.

## Author

Paul Sommers  
GitHub: [@psommers1](https://github.com/psommers1)