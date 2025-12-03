import rps
import secrets
import socket
import json
import enc
import time
import struct
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from tcp_json import receive_json
from tcp_json import send_json
from cryptography import x509
from cryptography.hazmat.backends import default_backend


HOST = '0.0.0.0'
PORT = 8080
session_key = secrets.token_bytes(32)

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


server_public_key= load_public_key_from_cert("server_cert.pem")

def sendWhoIAm(socket):
    #encrypting the session key with the server public key
    encrypted_blob = server_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    #signing the key with the timestamp with the alice private key
    alice_private_key = load_private_key("alice_key.pem")
    timestamp = time.time()
    timestamp_bytes = struct.pack('>d', timestamp)
    data_to_sign = session_key+timestamp_bytes
    signature = alice_private_key.sign(
        data_to_sign, 
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), 
            salt_length=padding.PSS.MAX_LENGTH 
        ),
        hashes.SHA256() 
    )

    handshake_packet = {
        "client_id": "alice",
        "type": "auth",
        "timestamp": timestamp,          
        "encrypted_blob": encrypted_blob,
        "signature": signature          
    }

    send_json(socket, handshake_packet)


def main():

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        #s.sendall(b'Hello, World!') # Note the b'' for bytes
        sendWhoIAm(s)

        data = s.recv(1024)

    print(f"Received: {data.decode('utf-8')}")

if __name__ == "__main__":
    main()