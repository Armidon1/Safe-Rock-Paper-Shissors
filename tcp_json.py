import json
import struct

def recvall(sock, n):
    """Funzione helper per ricevere ESATTAMENTE n byte o morire provandoci"""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None # Connessione chiusa dall'altro lato
        data += packet
    return data

def receive_json(sock):
    # 1. Leggi l'Header (primi 4 byte)
    header = recvall(sock, 4)
    if not header:
        return None # Il client si è disconnesso
        
    # 2. Unpack dell'Header per ottenere la lunghezza (intero)
    # Ritorna una tupla, quindi prendiamo il primo elemento [0]
    msg_length = struct.unpack('>I', header)[0]
    
    # 3. Leggi esattamente 'msg_length' byte (il Payload)
    payload_bytes = recvall(sock, msg_length)
    
    # 4. Decoding e Deserializzazione
    try:
        packet_dict = json.loads(payload_bytes.decode('utf-8'))
        return packet_dict
    except json.JSONDecodeError:
        print("ERRORE: JSON malformato ricevuto!")
        return None

def send_json(sock, packet_dict):
    # 1. Serializzazione: Dizionario -> Stringa JSON
    json_str = json.dumps(packet_dict)
    
    # 2. Encoding: Stringa -> Byte (UTF-8)
    data_bytes = json_str.encode('utf-8')
    
    # 3. Calcolo Lunghezza
    msg_length = len(data_bytes)
    
    # 4. Creazione Header (4 byte, Big Endian Unsigned Integer)
    # '>I' significa: Big Endian (>), Unsigned Int (I)
    header = struct.pack('>I', msg_length)
    
    # 5. Invio (Header + Dati)
    sock.sendall(header + data_bytes)