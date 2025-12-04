import secrets
import socket
import time
import struct
import base64
from time import sleep
from enc import load_private_key
from enc import load_public_key_from_cert
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from tcp_json import send_json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from rps import rock_paper_shissors_secure
from enc import send_json_encrypted
from enc import receive_and_decrypt_json_encrypted


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
        "Symm-encrypted":"n",
        "client_id": "alice",
        "type": "auth",
        "timestamp": timestamp,          
        "encrypted_key": base64.b64encode(encrypted_blob).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8')       
    }   

    send_json(socket, handshake_packet)

#TODO
def game_result(message, conn):
    # placeholder: process a game result message from server
    # print(f"Game result received: {message}")
    my_value = message.get("alice_value")
    bob_value = message.get("bob_value")
    winner = message.get("winner")
    print(f"I played: {my_value['value']}, Bob played: {bob_value['value']}. Winner: {winner}")
    sleep(1)
    print("Do you want to play again? (yes/no)")
    answer = input().strip().lower()
    if answer != "yes":
        print("Exiting the game.")
        return False
    else:game(message, conn)
    return True

#TODO
def game(message, conn):
    value = rock_paper_shissors_secure()
    message = {
        "client_id" : "alice",
        "type" : "game",
        "value" : value
    }
    #print("i'm inside the game function!")
    send_json_encrypted(message, conn, "alice",session_key)
    return True

def handle(message, conn):
    msg_type = message.get("type")
    match msg_type:
        case "you are a liar":
            print("damn he found me! I have to escape")
            return False
        case "game":
            return game(message, conn)
        case "game result":
            return game_result(message, conn)
        case "game ack":
            print("Server acknowledged game message")
            return True

def main():

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((HOST, PORT))
        print("Connected to the server")
        
        sendWhoIAm(conn)
        print("sent who i am")

        # receive initial message and then keep receiving inside the loop
        while True:
            print("Waiting for message...")
            # Do not pass 0 here; pass no message (or None) so the function reads from socket
            message = receive_and_decrypt_json_encrypted(conn, session_key)
            if not message:
                print("No message received, closing connection")
                break
            # print(f"message received : {message}")
            if handle(message, conn) == False:
                break

    

if __name__ == "__main__":
    main()