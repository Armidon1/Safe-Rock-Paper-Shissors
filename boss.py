import socket
import threading
import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend

HOST = "0.0.0.0"
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
    "ALICE": load_public_key_from_cert("alice_cert.pem"),
    "BOB": load_public_key_from_cert("bob_cert.pem")
}

def handle(conn, addr):
    """
    This function runs inside a separate thread.
    It handles the conversation for a SINGLE client.
    """
    print(f"[NEW CONNECTION] {addr} connected.")
    
    while True:
        try:
            # This is a BLOCKING call, but it only blocks THIS thread.
            # The main server loop is free to accept other people.
            msg = conn.recv(1024)
            
            if not msg:
                # Empty bytes means the client disconnected
                break
            
            print(f"[{addr}] {msg.decode('utf-8')}")
            conn.sendall(b"Message received")
            
        except ConnectionResetError:
            break
            
    conn.close()
    print(f"[DISCONNECT] {addr} disconnected.")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print("Server listening on", (HOST, PORT))
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle, args=(conn, addr), daemon=True)
            t.start()

if __name__ == "__main__":
    main()