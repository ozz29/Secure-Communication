import socket
import pickle
import uuid
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Function to get the IP address of the machine
def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))  # Google's DNS server address
    ip_address = s.getsockname()[0]
    s.close()
    return ip_address
 
# Load key from PEM file
def load_key(filename):
    with open(filename, "rb") as key_file:
        key = RSA.import_key(key_file.read())
    return key
 
# Decrypt certificate
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
 
    return decrypted_data, initiator_id
 
# Initiator
def initiator():
    ca_address = input("Enter the CA's address: ")
    ca_port = 12345
 
    # Load CA's public key
    ca_public_key = load_key("keys/ca_public_key.pem")
    initiator_public_key = load_key("keys/public_key.pem")
 
    # Connect to CA
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((ca_address, ca_port))
 
        # Send initiator's public key and ID to CA
        
        initiator_id = mac = uuid.uuid4().hex[:12]
        client_socket.sendall(pickle.dumps((initiator_public_key.export_key(), initiator_id)))
 
        # Receive encrypted certificate chunks from CA
        encrypted_certificate_chunks_unproc = client_socket.recv(4096) 
        encrypted_certificate_chunks = pickle.loads(encrypted_certificate_chunks_unproc)
        print(encrypted_certificate_chunks)
        print(len(encrypted_certificate_chunks))
        # Decrypt certificate chunk by chunk
        decrypted_certificate, initiator_id_c = decrypt_certificate(encrypted_certificate_chunks, ca_public_key)
        
        if initiator_id_c == initiator_id:
            print("valid")
            # Store the certificate chunks into a file
            with open("certificate_chunks.pkl", "wb") as f:
                pickle.dump(encrypted_certificate_chunks, f)
                print("Certificate chunks stored successfully.")
 
        else:
            print("invalid", initiator_id, initiator_id_c)
 
 
if __name__ == "__main__":
    initiator()