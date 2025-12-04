import socket
import threading
import base64
from time import sleep
from enc import load_private_key
from enc import load_public_key_from_cert
from enc import is_timestamp_valid
from tcp_json import receive_json
import struct
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from enc import send_json_encrypted
from enc import receive_and_decrypt_json_encrypted

HOST = "0.0.0.0"
PORT = 8080

alice_session_key = 0
bob_session_key = 0

alice_value = {"value": "", "count": 0}
bob_value = {"value": "", "count": 0}

keys_db = {
    "alice": load_public_key_from_cert("alice_cert.pem"),
    "bob": load_public_key_from_cert("bob_cert.pem")
}

def determine_winner(alice_move, bob_move):
    a = alice_move.lower()
    b = bob_move.lower()
    print(f"Determining winner: Alice({a}) vs Bob({b})")  # Debug
    
    valid_moves = ["rock", "paper", "scissors"]
    
    if a not in valid_moves or b not in valid_moves:
        return "Error: Invalid Move"

    if a == b:
        return "Draw"

    if (a == "rock" and b == "scissors") or \
       (a == "scissors" and b == "paper") or \
       (a == "paper" and b == "rock"):
        return "Alice"
    
    return "Bob"

def handle_auth(msg, conn, addr):
    global alice_session_key, bob_session_key
    timestamp = msg["timestamp"]
    if (is_timestamp_valid(timestamp) == False):
        print("WARNING! timestamp not valid. possible replay attack")
        return False

    encrypted_blob = base64.b64decode(msg["encrypted_key"])
    signature_bytes = base64.b64decode(msg["signature"])
    
    server_private_key = load_private_key("server_key.pem")
    decrypted_session_key = server_private_key.decrypt(
        encrypted_blob,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    #print(f"decrypted session key {decrypted_session_key}")

    try:
        # Ricostruisce i dati originali (Key decifrata + Timestamp ricevuto)
        data_to_verify = decrypted_session_key + struct.pack('>d', timestamp)

        if (msg["client_id"] == "alice"):
            keys_db["alice"].verify(
                signature_bytes,
                data_to_verify,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Valid Signature: Is Alice!")
            alice_session_key=decrypted_session_key

        elif (msg["client_id"] == "bob"):
            keys_db["bob"].verify(
                signature_bytes,
                data_to_verify,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Valid Signature: is Bob!")
            bob_session_key=decrypted_session_key
        
        # Usa la session key per comunicare con alice/bob
        message = {
            "type" : "game"
        }
        send_json_encrypted(message, conn, "server", decrypted_session_key)
        return decrypted_session_key

    except Exception:
        print("Invalid Signature: Someone is liying!")
        message = {
            "type" : "you're a liar!"
        }
        send_json_encrypted(message, conn, "server",decrypted_session_key)
        return None

def handle_game(msg, conn, addr, session_key):
    # Use the session_key provided for THIS connection instead of global variables
    if session_key is None:
        print(f"[{addr}] No session key available for game message from {msg.get('client_id')}")
        return

    print(f"[{addr}] Game message received with value: {msg.get('value')}")
    global alice_value, bob_value
    if msg.get("client_id") == "alice":
        alice_value["value"] = msg.get("value")
        alice_value["count"] += 1
    elif msg.get("client_id") == "bob":
        bob_value["value"] = msg.get("value")
        bob_value["count"] += 1 
    else:
        print(f"[{addr}] Unknown client_id: {msg.get('client_id')}")
        return
    # Here you can implement the game logic
    # For now, just acknowledge receipt
    response = {
        "type": "game ack",
        "value": msg.get("value")
    }
    send_json_encrypted(response, conn, "server", session_key)
    while True:
        if (alice_value["count"]==bob_value["count"]):
            print(f"Both players have made their moves: Alice({alice_value['value']}) vs Bob({bob_value['value']})")
            winner = determine_winner(alice_value["value"], bob_value["value"])
            print(f"Game result determined: {winner}")
            result_message = {
                "type": "game result",
                "winner": winner,
                "alice_value": alice_value,
                "bob_value": bob_value
            }
            # Send result to both players
            if (msg.get("client_id") == "alice"):
                print(f"Sending game result to Alice...")
            elif (msg.get("client_id") == "bob"):
                print(f"Sending game result to Bob...")
            send_json_encrypted(result_message, conn, "server", session_key)
            
            break
        print("Waiting for the other player to make a move...")
        sleep(1)  # Wait a bit before checking again
        

def handle(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    
    current_session_key = None 

    while True:
        try:
            # 1. Ricevi il "bussolotto" (Wrapper JSON)
            print(f"[{addr}] Waiting for message...")
            wrapper_msg = receive_json(conn)
            
            if not wrapper_msg:
                # Client disconnesso
                break
            
            # --- RAMO 1: MESSAGGI IN CHIARO (Auth) ---
            # Usa .get() per evitare crash se la chiave non esiste
            if wrapper_msg.get('Symm-encrypted') == "n":
                
                print(f"[{addr}] Messaggio in chiaro ricevuto: {wrapper_msg.get('type')}")
            
            if wrapper_msg.get("type") == "auth":
                # IMPORTANTE: handle_auth deve restituire la chiave AES se va tutto bene!
                # Se fallisce, restituisce None
                current_session_key = handle_auth(wrapper_msg, conn, addr)
                    
                if current_session_key is None:
                    print(f"[{addr}] Autenticazione fallita.")
                    break
                else:
                    print(f"[{addr}] Autenticato! Session Key memorizzata.")

            # --- RAMO 2: MESSAGGI CIFRATI (Game) ---
            else:
                if current_session_key is None:
                    print(f"[{addr}] ERRORE: Tentativo di invio cifrato senza auth.")
                    break

                # Usiamo la chiave di sessione salvata prima, passando il wrapper_msg come terzo argomento
                decrypted_msg = receive_and_decrypt_json_encrypted(conn, current_session_key, wrapper_msg)

                # Controllo CRITICO: La decifratura è andata a buon fine?
                if decrypted_msg is None:
                    print(f"[{addr}] Errore decifratura o disconnessione.")
                    break

                # Ora lavoriamo sul messaggio decifrato
                match decrypted_msg.get('type'):
                    case "game":
                        handle_game(decrypted_msg, conn, addr, current_session_key)
                    case "disconnect":
                        print(f"[{addr}] Richiesta disconnessione.")
                        break
                    case _:
                        print(f"[{addr}] Tipo messaggio sconosciuto: {decrypted_msg.get('type')}")
                
        except ConnectionResetError:
            print(f"[{addr}] Connection Reset.")
            break
        except Exception as e:
            print(f"[{addr}] Errore generico nel loop: {e}")
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