import json
import struct

def recvall(sock, n):
    """Helper function to receive EXACTLY n bytes or die trying"""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None # the connection was closed
        data += packet
    return data

def receive_json(sock):

    header = recvall(sock, 4)
    if not header:
        return None # the connection was closed
    
    msg_length = struct.unpack('>I', header)[0]
    
    payload_bytes = recvall(sock, msg_length)
    
    try:
        packet_dict = json.loads(payload_bytes.decode('utf-8'))
        return packet_dict
    except json.JSONDecodeError:
        print("ERROR: Malformed JSON received!")
        return None

def send_json(sock, packet_dict):

    json_str = json.dumps(packet_dict)
    
    data_bytes = json_str.encode('utf-8')
    
    msg_length = len(data_bytes)
    
    header = struct.pack('>I', msg_length)
    
    sock.sendall(header + data_bytes)