import socket
import pickle
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Load key from PEM file
def load_key(filename):
    with open(filename, "rb") as key_file:
        key = RSA.import_key(key_file.read())
    return key

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))  # Google's DNS server address
    ip_address = s.getsockname()[0]
    s.close()
    return ip_address

def sender():
    # Load certificate chunks from a pkl file
    with open('../INITIATOR/certificate_chunks.pkl', 'rb') as file:
        certificate_chunks = pickle.load(file)

    # Create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Define the IP address and port of the receiver
    host = input("Enter the receiver's address: ")
    port = 12345

    # Connect to the receiver
    s.connect((host, port))

    # Send each certificate chunk
    for chunk in certificate_chunks:
        print("Sent: ", chunk)
        s.sendall(pickle.dumps(chunk))
        time.sleep(0.3)  # Add a small delay

    # Close the socket
    s.close()

def receiver():
    # Load the CA's public key
    ca_public_key = load_key("keys/ca_public_key.pem")

    # Create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Define the IP address and port to bind to
    host = get_ip_address()
    port = 12345

    print("Receiving at: ", host)

    # Bind the socket to the address and port
    s.bind((host, port))

    # Listen for incoming connections
    s.listen()

    # Accept a connection from a sender
    conn, addr = s.accept()
    print('Connected by', addr)

    # Receive certificate chunks
    certificate_chunks = []
    while True:
        data = conn.recv(4096)
        if not data:
            break
        certificate_chunks.append(data)

    # Deserialize the received data using pickle
    deserialized_chunks = [pickle.loads(chunk) for chunk in certificate_chunks]

    # Decrypt certificate
    decrypted_data = b''
    cipher_rsa = PKCS1_OAEP.new(ca_public_key)
    for encrypted_chunk in deserialized_chunks:
        decrypted_chunk = cipher_rsa.decrypt(encrypted_chunk)
        decrypted_data += decrypted_chunk

    # Find the positions of delimiter characters
    pub_key_end = decrypted_data.find(b'\n-----END PUBLIC KEY-----') + len(b'\n-----END PUBLIC KEY-----')

    # Extract initiator ID and timestamps
    initiator_key = decrypted_data[:pub_key_end]
    initiator_id_binary = decrypted_data[pub_key_end:-16]
    timestamp_created = int.from_bytes(decrypted_data[-16:-8], byteorder='big')
    timestamp_valid_until = int.from_bytes(decrypted_data[-8:], byteorder='big')

    initiator_id = initiator_id_binary.decode('utf-8')

    # Print extracted information
    print("Initiator ID:", initiator_id)
    print("Timestamp Created:", timestamp_created)
    print("Timestamp Valid Until:", timestamp_valid_until)

    # # Save the decrypted data to a pkl file
    # with open('decrypted_certificate.pkl', 'wb') as file:
    #     pickle.dump(decrypted_data, file)

    # Close the connection and the socket
    conn.close()
    s.close()

# Prompt the user to choose sender or receiver
user_choice = input("Choose 'sender' or 'receiver': ")
if user_choice.lower() == 'sender':
    sender()
elif user_choice.lower() == 'receiver':
    receiver()
else:
    print("Invalid choice.")
