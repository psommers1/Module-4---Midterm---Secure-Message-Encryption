"""
Secure Message Encryption Application
Author: Paul Sommers
Description: A web-based application that demonstrates confidentiality, integrity, and 
             availability through SHA-256 hashing and AES encryption.
"""

from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hashlib
import secrets
import base64
import os

app = Flask(__name__)

class SecureMessageHandler:
    """
    Handles encryption, decryption, and integrity verification of messages.
    Uses AES-256 for encryption and SHA-256 for integrity verification.
    """
    
    def __init__(self):
        """Initialize the secure message handler."""
        self.backend = default_backend()
    
    def generate_key(self):
        """
        Generate a cryptographically secure random key for AES-256 encryption.
        
        Returns:
            bytes: 32-byte (256-bit) random key with high entropy
        
        Note:
            This function uses secrets.token_bytes() which provides
            cryptographically strong random bytes suitable for managing
            data such as passwords, account authentication, security tokens,
            and related secrets.
        """
        # Generate 32 bytes (256 bits) of random data for AES-256
        # The secrets module uses the most secure source of randomness
        # available on your operating system
        return secrets.token_bytes(32)
    
    def generate_iv(self):
        """
        Generate a random initialization vector (IV) for AES encryption.
        
        Returns:
            bytes: 16-byte random IV
        
        Note:
            An IV is used to ensure that encrypting the same plaintext
            with the same key produces different ciphertexts. This prevents
            pattern analysis attacks. The IV doesn't need to be secret,
            but it must be unpredictable.
        """
        # AES block size is 128 bits (16 bytes), so IV must be 16 bytes
        return secrets.token_bytes(16)
    
    def compute_hash(self, message):
        """
        Compute SHA-256 hash of a message for integrity verification.
        
        Args:
            message (str): The message to hash
        
        Returns:
            str: Hexadecimal representation of the SHA-256 hash
        
        Note:
            SHA-256 is a cryptographic hash function that produces a fixed-size
            256-bit hash value. It's designed to be one-way (infeasible to reverse)
            and collision-resistant (infeasible to find two inputs with same hash).
        """
        # Encode the message to bytes for hashing
        message_bytes = message.encode('utf-8')
        
        # Create SHA-256 hash object
        hash_obj = hashlib.sha256()
        
        # Update hash with message bytes
        hash_obj.update(message_bytes)
        
        # Return hexadecimal digest of the hash
        return hash_obj.hexdigest()
    
    def encrypt_message(self, message, key):
        """
        Encrypt a message using AES-256 in CBC mode with PKCS7 padding.
        
        Args:
            message (str): The plaintext message to encrypt
            key (bytes): 32-byte AES-256 encryption key
        
        Returns:
            dict: Contains encrypted message (base64), IV (base64), and original hash
        
        Process:
            1. Compute hash of original message for integrity verification
            2. Add PKCS7 padding to message (AES requires block-aligned input)
            3. Generate random IV for this encryption operation
            4. Encrypt padded message using AES-256-CBC
            5. Return encrypted data, IV, and original hash
        """
        # Step 1: Compute hash of original message before encryption
        # This hash will be used later to verify the message wasn't altered
        original_hash = self.compute_hash(message)
        
        # Step 2: Convert message to bytes
        message_bytes = message.encode('utf-8')
        
        # Step 3: Apply PKCS7 padding
        # AES requires input to be a multiple of the block size (128 bits = 16 bytes)
        # PKCS7 padding adds bytes to make the message length a multiple of block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message_bytes) + padder.finalize()
        
        # Step 4: Generate a random IV for this encryption
        # Different IV ensures same message encrypted twice produces different ciphertext
        iv = self.generate_iv()
        
        # Step 5: Create AES cipher in CBC (Cipher Block Chaining) mode
        # CBC mode provides confidentiality by chaining blocks together
        cipher = Cipher(
            algorithms.AES(key),  # AES algorithm with our 256-bit key
            modes.CBC(iv),        # CBC mode with our random IV
            backend=self.backend
        )
        
        # Step 6: Encrypt the padded message
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Step 7: Return encrypted data, IV, and original hash
        # We encode to base64 for easy transmission and storage
        return {
            'encrypted_message': base64.b64encode(encrypted_data).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'original_hash': original_hash
        }
    
    def decrypt_message(self, encrypted_data, key, iv):
        """
        Decrypt a message that was encrypted with AES-256 CBC mode.
        
        Args:
            encrypted_data (str): Base64-encoded encrypted message
            key (bytes): 32-byte AES-256 decryption key (same as encryption key)
            iv (str): Base64-encoded initialization vector used during encryption
        
        Returns:
            str: Decrypted plaintext message
        
        Process:
            1. Decode base64-encoded encrypted data and IV
            2. Create AES cipher with same parameters used for encryption
            3. Decrypt the ciphertext
            4. Remove PKCS7 padding to recover original message
        """
        # Step 1: Decode base64-encoded data
        encrypted_bytes = base64.b64decode(encrypted_data)
        iv_bytes = base64.b64decode(iv)
        
        # Step 2: Create AES cipher in CBC mode with same key and IV
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv_bytes),
            backend=self.backend
        )
        
        # Step 3: Decrypt the ciphertext
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_bytes) + decryptor.finalize()
        
        # Step 4: Remove PKCS7 padding to recover original message
        unpadder = padding.PKCS7(128).unpadder()
        message_bytes = unpadder.update(padded_data) + unpadder.finalize()
        
        # Step 5: Convert bytes back to string
        return message_bytes.decode('utf-8')
    
    def verify_integrity(self, message, original_hash):
        """
        Verify the integrity of a message by comparing hashes.
        
        Args:
            message (str): The message to verify
            original_hash (str): The original SHA-256 hash to compare against
        
        Returns:
            bool: True if hashes match (integrity verified), False otherwise
        
        Note:
            This function ensures that the decrypted message matches the original
            by comparing cryptographic hashes. If even one bit of the message was
            altered, the hashes will not match.
        """
        # Compute hash of the current message
        current_hash = self.compute_hash(message)
        
        # Compare with original hash
        # Using == for hash comparison is safe here since we're comparing
        # hex strings of equal length
        return current_hash == original_hash

# Initialize the secure message handler
handler = SecureMessageHandler()

@app.route('/')
def index():
    """
    Render the main page of the application.
    
    Returns:
        HTML: The index page with the encryption/decryption interface
    """
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    """
    Handle encryption requests from the web interface.
    
    Expects:
        JSON with 'message' field containing the plaintext to encrypt
    
    Returns:
        JSON with encrypted message, IV, hash, and encryption key
    
    Process:
        1. Generate a new encryption key with high entropy
        2. Encrypt the message using AES-256
        3. Return all necessary data for later decryption and verification
    """
    try:
        # Get the message from the request
        data = request.get_json()
        message = data.get('message', '')
        
        if not message:
            return jsonify({'error': 'Message cannot be empty'}), 400
        
        # Generate a new encryption key for this message
        # In production, this key would be securely stored or derived from a password
        key = handler.generate_key()
        
        # Encrypt the message
        result = handler.encrypt_message(message, key)
        
        # Add the key to the result (base64 encoded for transmission)
        # Note: In a real application, the key would NOT be sent to the client
        # It would be securely stored on the server or derived from user password
        result['key'] = base64.b64encode(key).decode('utf-8')
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    """
    Handle decryption and integrity verification requests.
    
    Expects:
        JSON with encrypted_message, key, iv, and original_hash
    
    Returns:
        JSON with decrypted message and integrity verification result
    
    Process:
        1. Decrypt the ciphertext using provided key and IV
        2. Verify integrity by comparing hashes
        3. Return decrypted message and verification status
    """
    try:
        # Get the encrypted data from the request
        data = request.get_json()
        encrypted_message = data.get('encrypted_message', '')
        key_b64 = data.get('key', '')
        iv = data.get('iv', '')
        original_hash = data.get('original_hash', '')
        
        # Validate inputs
        if not all([encrypted_message, key_b64, iv, original_hash]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Decode the key from base64
        key = base64.b64decode(key_b64)
        
        # Decrypt the message
        decrypted_message = handler.decrypt_message(encrypted_message, key, iv)
        
        # Verify integrity by comparing hashes
        integrity_verified = handler.verify_integrity(decrypted_message, original_hash)
        
        # Compute hash of decrypted message for display
        decrypted_hash = handler.compute_hash(decrypted_message)
        
        return jsonify({
            'decrypted_message': decrypted_message,
            'integrity_verified': integrity_verified,
            'decrypted_hash': decrypted_hash,
            'original_hash': original_hash
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Run the Flask application
    # Debug mode should be False in production for security
    app.run(debug=True, host='0.0.0.0', port=5000)