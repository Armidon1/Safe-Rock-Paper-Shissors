import os
import time
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from tcp_json import send_json
from tcp_json import receive_json


def encrypt_message(msg_plaintext, key):
    nonce = os.urandom(12)

    algorithm = algorithms.AES(key)
    mode = modes.GCM(nonce)
    cipher = Cipher(algorithm, mode, backend=default_backend())
    
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(msg_plaintext.encode('utf-8')) + encryptor.finalize()
    
    tag = encryptor.tag

    return nonce, ciphertext, tag

def decrypt_message(nonce, ciphertext, tag, key):

    try:
        algorithm = algorithms.AES(key)
        mode = modes.GCM(nonce, tag) 
        cipher = Cipher(algorithm, mode, backend=default_backend())

        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        return decrypted_data.decode('utf-8')
        
    except Exception as e:
        return "ERROR: Someone touched the file!"

def load_private_key(filename):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  
            backend=default_backend()
        )
    return private_key

def load_public_key_from_cert(filename):
    # 1. read bytes from file.pem
    with open(filename, "rb") as cert_file:
        cert_data = cert_file.read()
        
    # 2. laod the certificate as X.509
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    
    # 3. extract the public key from the certificate
    public_key = cert.public_key()

    print(f"LOADED PUBLIC KEY {public_key} of FILENAME {filename}") #Debug
    
    return public_key

def is_timestamp_valid(received_timestamp, ttl=60):
    server_time = time.time()
    
    delta = server_time - received_timestamp

    if delta < -2.0:
        print(f"[SECURITY ALERT] Timestamp coming from the future! Difference: {delta:.2f}s. Clocks not synchronized or attack.")
        return False

    if delta > ttl:
        print(f"[SECURITY ALERT] Packet expired! Old by {delta:.2f}s (Max: {ttl}s). Possible Replay Attack.")
        return False

    return True

def send_json_encrypted(message, conn, client_id, session_key):
    nonce, ciphertext, tag = encrypt_message(json.dumps(message), session_key)
    message_encrypted = {
        "Symm-encrypted":"y",
        "client_id":client_id,
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8')
    }
    send_json(conn, message_encrypted)

def receive_and_decrypt_json_encrypted(conn, session_key, message=None):
    if message is None:
        encrypted_json = receive_json(conn)
    else:
        encrypted_json = message

    # receive_json can return None if the peer disconnected or JSON was malformed
    if encrypted_json is None:
        return None

    try:
        # Convert from Base64 String -> Original Bytes
        nonce = base64.b64decode(encrypted_json['nonce'])
        ciphertext = base64.b64decode(encrypted_json['ciphertext'])
        tag = base64.b64decode(encrypted_json['tag'])
        
        # 2. Decryption
        decrypted_str = decrypt_message(nonce, ciphertext, tag, session_key)
        
        # If decrypt_message returns an error string, handle it robustly
        if not isinstance(decrypted_str, str) or decrypted_str.startswith("ERRORE") or decrypted_str.startswith("ERROR"):
            print("Decryption failed (Tag mismatch or wrong key)")
            return None

        return json.loads(decrypted_str)

    except (KeyError, ValueError, json.JSONDecodeError) as e:
        print(f"Error in encrypted protocol: {e}")
        return None