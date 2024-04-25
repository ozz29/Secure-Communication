import socket
import pickle
import time
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Function to get the IP address of the machine
def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))  # Google's DNS server address
    ip_address = s.getsockname()[0]
    s.close()
    return ip_address

# Load CA's private key from PEM file
def load_private_key(filename):
    with open(filename, "rb") as key_file:
        private_key = RSA.import_key(key_file.read())
    return private_key

# Load CA's public key from PEM file
def load_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key = RSA.import_key(key_file.read())
    return public_key

# Create a digital certificate
def create_certificate(initiator_public_key_pem, initiator_id, ca_private_key):
    timestamp_created = int(time.time())  # Current time
    timestamp_valid_until = timestamp_created + 3600*24*30  # Valid for 1 month
    
    # Concatenate information
    data = initiator_public_key_pem + initiator_id.encode('utf-8') + \
           timestamp_created.to_bytes(8, byteorder='big') + \
           timestamp_valid_until.to_bytes(8, byteorder='big')
    
    # Define chunk size
    chunk_size = 128  # Adjust as needed

    # Encrypt data in chunks
    encrypted_chunks = []
    for i in range(0, len(data), chunk_size):
        if i+chunk_size < len(data):
            chunk = data[i:i+chunk_size]
        else:
            chunk = data[i:]
        cipher_rsa = PKCS1_OAEP.new(ca_private_key)
        encrypted_chunk = cipher_rsa.encrypt(chunk)
        encrypted_chunks.append(encrypted_chunk)
        print(chunk_size, len(encrypted_chunk))

    return encrypted_chunks


def decrypt_certificate(encrypted_certificate, ca_public_key):
    decrypted_data = b''
    cipher_rsa = PKCS1_OAEP.new(ca_public_key)
    for encrypted_chunk in encrypted_certificate:
        decrypted_chunk = cipher_rsa.decrypt(encrypted_chunk)
        decrypted_data += decrypted_chunk

    # Find the positions of delimiter characters
    pub_key_end = decrypted_data.find(b'\n-----END PUBLIC KEY-----') + len(b'\n-----END PUBLIC KEY-----')
    
    # Extract initiator ID and timestamps
    initiator_id_binary = decrypted_data[pub_key_end:-16]
    timestamp_created = int.from_bytes(decrypted_data[-16:-8], byteorder='big')
    timestamp_valid_until = int.from_bytes(decrypted_data[-8:], byteorder='big')

    initiator_id = initiator_id_binary.decode('utf-8')

    # Print extracted information
    print("Initiator ID:", initiator_id)
    print("Timestamp Created:", timestamp_created)
    print("Timestamp Valid Until:", timestamp_valid_until)

    return initiator_id, decrypted_data

# CA
def ca():
    # Load CA's private key
    ca_private_key = load_private_key("keys/ca_private_key.pem")
    ca_public_key = load_public_key("keys/ca_public_key.pem")

    # Get IP address of the CA machine
    ca_ip_address = get_ip_address()
    #ca_ip_address = '127.0.0.1'

    # Set up server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(1)

    print("CA is running at:", ca_ip_address)
    print("Waiting for connection...")

    while True:
        client_socket, client_address = server_socket.accept()
        print("Connected to:", client_address)

        # Receive public key and ID from initiator
        initiator_public_key_pem, initiator_id = pickle.loads(client_socket.recv(1024))
        print("Received public key from initiator:", initiator_public_key_pem)
        print("Received ID from initiator:", initiator_id)

        # Create certificate
        certificate = create_certificate(initiator_public_key_pem, initiator_id, ca_private_key)
        print(len(certificate))
        print(certificate)

        print("\nSending the certificate!!\n") 
        # Send encrypted certificate to initiator
        client_socket.sendall(pickle.dumps(certificate))
        
        # Decrypt certificate
        decrypted_data = decrypt_certificate(certificate, ca_public_key)

        # Close connection
        client_socket.close()

# Main function
if __name__ == "__main__":
    ca()
