import rps
import json
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend


HOST = '0.0.0.0'
PORT = 8080

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


keys_db = {
    "SERVER": load_public_key_from_cert("server_cert.pem"),
}


def main():

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(b'Hello, World!') # Note the b'' for bytes
        data = s.recv(1024)

    print(f"Received: {data.decode('utf-8')}")

if __name__ == "__main__":
    main()