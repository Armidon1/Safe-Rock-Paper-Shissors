import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_message(msg_plaintext, key):
    # 1. Genera un Nonce (Number used ONCE)
    # Per AES-GCM, il nonce DEVE essere di 12 byte ed è UNICO per ogni messaggio.
    nonce = os.urandom(12)

    # 2. Configura il Cifrario
    algorithm = algorithms.AES(key)
    mode = modes.GCM(nonce)
    cipher = Cipher(algorithm, mode, backend=default_backend())
    
    # 3. Cifra
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(msg_plaintext.encode('utf-8')) + encryptor.finalize()
    
    # 4. Ottieni il Tag di Autenticazione (garantisce che nessuno abbia toccato i dati)
    tag = encryptor.tag

    # 5. Restituisci tutto ciò che serve al server per decifrare
    return nonce, ciphertext, tag

def decrypt_message(nonce, ciphertext, tag, key):
    try:
        # 1. Configura il Cifrario (con gli stessi parametri)
        algorithm = algorithms.AES(key)
        mode = modes.GCM(nonce, tag) # Passiamo il tag per la verifica
        cipher = Cipher(algorithm, mode, backend=default_backend())

        # 2. Decifra e Verifica
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        return decrypted_data.decode('utf-8')
        
    except Exception as e:
        return "ERROR: Someone touched the file!"