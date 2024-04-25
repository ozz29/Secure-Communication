# Complete cryptography library
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, asymmetric, hashes
from cryptography.hazmat.primitives import padding as pad
from cryptography.hazmat.primitives.asymmetric import rsa

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
# Normal Libraries
import time
import os
import random
import socket
import threading
import hashlib
import pickle

def load_key(filename):
    with open(filename, "rb") as key_file:
        key = RSA.import_key(key_file.read())
    return key

class SecureChat:
    # As the name suggests, variables represent them
    def __init__(self):
        self.private_key = None
        self.private_key_pem = None
        self.public_key = None
        self.public_key_pem = None
        self.session_key = None
        self.client_public_key = None
        self.client_public_key_pem = None
        self.g = 2
        self.n = 11076478309435183247342274229442810489005322936188389787192673
        self.message_count = 0
    
    # Generation of both public key and private keys
    # the PEM variables makes the public/private key variable pem encoded
    # PEM encoding is used basically for presenting on screen
    def generate_key(self):
        public_key_path = 'keys/public_key.pem'
        private_key_path = 'keys/private_key.pem'
 
        if os.path.exists(public_key_path) and os.path.exists(private_key_path):
            with open(public_key_path, 'rb') as f:
                self.public_key_pem = f.read()
                self.public_key = serialization.load_pem_public_key(self.public_key_pem)
 
            with open(private_key_path, 'rb') as f:
                self.private_key_pem = f.read()
                self.private_key = serialization.load_pem_private_key(self.private_key_pem, password=None)
 
        else:
            self.private_key = asymmetric.rsa.generate_private_key(
                public_exponent=65537,
                key_size=1024
            )
            self.public_key = self.private_key.public_key()
 
            self.public_key_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.private_key_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
 
            with open(public_key_path, 'wb') as f:
                f.write(self.public_key_pem)
 
            with open(private_key_path, 'wb') as f:
                f.write(self.private_key_pem)
    
    # This function basically is used to compute the private key portion
    # This function also helps us define the session key
    def mod_exp(self, base, exp, mod):
        result = 1
        base = base % mod
        while exp > 0:
            if exp % 2 == 1:
                result = (result * base) % mod
            exp = exp // 2
            base = (base * base) % mod
        return result

    # This function initiates the key exchange, Mode = Deffie Hellman
    # Variable a = random private key
    # Variable A = Exchange value
    def initiate_keyEx_c(self, client_socket):
        a = random.randint(2, self.n - 1)
        A = self.mod_exp(self.g, a, self.n)
        encrypted_key1 = self.client_public_key.encrypt(
            str(A).encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        hash_key1 = hashlib.sha256(str(A).encode('utf-8')).hexdigest()
        message1 = encrypted_key1 + hash_key1.encode()  # Serialize hash_key1
        client_socket.send(message1)

        encrypted_key2_with_hash = client_socket.recv(1024)
        encrypted_key2 = encrypted_key2_with_hash[:128]
        received_hash = encrypted_key2_with_hash[128:].decode()  # Extract received hash
        key2 = self.private_key.decrypt(
            encrypted_key2,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        hash_key2 = hashlib.sha256(key2).hexdigest()  # Calculate hash for key2
        if received_hash != hash_key2:
            print("Error in transmitting key")
        else:
            self.print_statements("integrity")

        self.session_key = str(self.mod_exp(int(key2), a, self.n)).encode('utf-8')
        self.session_key = self.pad_key_to_256_bits(self.session_key)
        self.print_statements("session key")

    # This function initiates the key exchange, Mode = Deffie Hellman
    # Variable b = random private key
    # Variable B = Exchange value
    def initiate_keyEx_s(self, client_socket):
        encrypted_key1 = client_socket.recv(1024)
        key1 = self.private_key.decrypt(
            encrypted_key1[:128],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        hash_received = encrypted_key1[128:].decode()  # Extract received hash
        if hashlib.sha256(key1).hexdigest() != hash_received:
            print("Error in transmitting key")
        else:
            self.print_statements("integrity")

        b = random.randint(2, self.n-1)
        B = self.mod_exp(self.g, b, self.n)
        encrypted_key2 = self.client_public_key.encrypt(
            str(B).encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        hash_key = hashlib.sha256(str(B).encode('utf-8')).hexdigest()  # Calculate hash for key2
        message = encrypted_key2 + hash_key.encode()  # Serialize hash_key
        client_socket.send(message)

        self.session_key = str(self.mod_exp(int(key1), b, self.n)).encode('utf-8')
        self.session_key = self.pad_key_to_256_bits(self.session_key)
        self.print_statements("session key")

    # Basically the session key is updated
    # The session is passed through the hash function
    # The new key is 32bytes long
    def changeSess(self):
        hash_key = hashlib.sha256(str(self.session_key).encode()).hexdigest()
        self.session_key = self.pad_key_to_256_bits(hash_key.encode())

        # This function is used whenever the key length is mismatched
    # Used to keep the Encryption function running successfully
    def pad_key_to_256_bits(self, session_key):
        key_length = len(session_key)
        if key_length >= 32:
            return session_key[:32]  # If key is longer than 128 bits, truncate it
        else:
            # Pad the key with null bytes
            return session_key + bytes([0] * (32 - key_length))
    
    # Printing all the confirmation message on user side
    def print_statements(self, message, client_socket=None):
        if message == "failed inte":
            print("<-- Failed Integrity -->")

        elif message == "integrity":
            print("<-- Passed Integrity -->")

        elif message == "session key":
            print("<-- Generated Session key -->")

        else:
            print("<- Unrecognized statement ->")
    # Command set for the user side
    # Only change sess transmits the message before executing
    def command_Set(self, message, client_socket):
        if message == ":$ help":
            print("-> show - commands to reveal the user's key")
            print("-> change - commands to change certain aspects")

        elif message == ":$ show -h":
            print("-> show pvt  - reveals the user's private key")
            print("-> show pub  - reveals the user's public key")
            print("-> show client pub  - reveals the user's public key")
            print("-> show sess - reveals the current session key")

        elif message == ":$ show pvt":
            for i in range(0, len(self.private_key_pem.splitlines())):
                print(self.private_key_pem.splitlines()[i])

        elif message == ":$ show pub":
            for i in range(0, len(self.public_key_pem.splitlines())):
                print(self.public_key_pem.splitlines()[i])

        elif message == ":$ show client pub":
            for i in range(0, len(self.client_public_key_pem.splitlines())):
                print(self.client_public_key_pem.splitlines()[i])

        elif message == ":$ show sess":
            print(self.session_key)

        elif message == ":$ change -h":
            print("-> change sess  - regenerate the session key")

        elif message == ":$ change sess":
            client_socket.send(self.EncryptSession("Change Session"))
            self.changeSess()

        else:
            print("Unrecognized command")
    
    # The decryption function
    # Splits the input into two sections data and hash
    # The data is decrypted using the session key
    # Generation of hash based on this input
    # if they match, the message is printed
    # Else the error message is printed
    def DecryptSession(self, data):
        data1, hash_message = data.split(b"10101")
        cipher = Cipher(algorithms.AES(self.session_key), modes.ECB())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(data1) + decryptor.finalize()

        # Remove padding
        unpadder = pad.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_message = unpadder.update(decrypted_message) + unpadder.finalize()

        if hashlib.sha256(unpadded_message).hexdigest() == hash_message.decode():
            if unpadded_message.decode() == "Change Session":
                self.message_count = self.message_count - 1
                self.changeSess()
                return "[Changed Session Key]"
            else:
                return unpadded_message.decode()
        else:
            return self.print_statements("failed inte")

    # The encryption function
    # Initially the message is padded to reach the block size
    # Generation of encrypted text happens using AES method and ECB mode
    # hash is generated of the message
    # finally the encrypted text and hash is sent
    def EncryptSession(self, message):
        # Pad the message to ensure its length is a multiple of the block size
        padder = pad.PKCS7(algorithms.AES.block_size).padder()
        padded_message = padder.update(message.encode()) + padder.finalize()

        # Encrypt the padded message using AES with the session key
        cipher = Cipher(algorithms.AES(self.session_key), modes.ECB())
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(padded_message) + encryptor.finalize()

        hash_message = hashlib.sha256(message.encode()).hexdigest()
        # Send the encrypted message and its hash to the server
        return cipher_text + "10101".encode() + hash_message.encode()

    # Server socket is initialised
    # Only accepts connection and not directs connection
    # -> Keys are generated
    # -> Public Key is exchanged
    # -> Initiation of session key exchange
    # Starting threads, because we allow bidirectional communication

    def get_ip_address(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google's DNS server address
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address

    # Server side
    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.generate_key()

        host = self.get_ip_address()
        port = 12345

        server_socket.bind((host, port))
        server_socket.listen()

        print("Server listening on {}:{}".format(host, port))

        while True:
            client_socket, client_address = server_socket.accept()
            print("Connection from", client_address)

            # Sending portion
            with open('../INITIATOR/certificate_chunks.pkl', 'rb') as file:
                certificate_chunks = pickle.load(file)

            # Send each certificate chunk
            for chunk in certificate_chunks:
                #print("Sent: ", chunk)
                client_socket.sendall(pickle.dumps(chunk))
                time.sleep(0.3)  # Add a small delay
            client_socket.send(b'END_OF_DATA_STREAM')
            
            print("All certificate chunks sent")

            # Receiving portion
            ca_public_key = load_key("keys/ca_public_key.pem")

            # Receive certificate chunks
            certificate_chunks = []
            while True:
                data = client_socket.recv(4096)
                #print("data: ", data)
                if not data or data == b'END_OF_DATA_STREAM':
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
            print("<---Certifcate Received--->")
            print("Key: ", initiator_key)
            print("Initiator ID:", initiator_id)
            print("Timestamp Created:", timestamp_created)
            print("Timestamp Valid Until:", timestamp_valid_until)

            # ------------------------------------------certificate check start !!------------------------------------------

            curr_time = time.time()
            valid_cert = True
            if curr_time > timestamp_valid_until:
                print("<---Expired Certificate!!--->")
                valid_cert = False
                

            # ------------------------------------------certificate check end !!--------------------------------------------
            if valid_cert:
                print("<---Valid Certificate--->")
                self.client_public_key_pem = initiator_key
                self.client_public_key = serialization.load_pem_public_key(self.client_public_key_pem)

                self.initiate_keyEx_s(client_socket)

                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.start()

                send_thread = threading.Thread(target=self.send_messages, args=(client_socket,))
                send_thread.start()

        server_socket.close()  # Close the server socket when done



    # Client side
    def client_side(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.generate_key()
 
        server_ip = input("Enter server IP address: ")
        server_port = int(input("Enter server port: "))
 
        client_socket.connect((server_ip, server_port))
 
        # Receiving portion
        ca_public_key = load_key("keys/ca_public_key.pem")
 
        # Receive certificate chunks
        certificate_chunks = []
        while True:
            data = client_socket.recv(4096)
            #print("data: ", data)
            if not data or data == b'END_OF_DATA_STREAM':
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
        print("<---Certificate Received--->")
        print("key: ", initiator_key)
        print("Initiator ID:", initiator_id)
        print("Timestamp Created:", timestamp_created)
        print("Timestamp Valid Until:", timestamp_valid_until)
        self.client_public_key_pem = initiator_key
        self.client_public_key = serialization.load_pem_public_key(self.client_public_key_pem)
 
        # Sending portion
        with open('../INITIATOR/certificate_chunks.pkl', 'rb') as file:
            certificate_chunks = pickle.load(file)
        # Send each certificate chunk
        for chunk in certificate_chunks:
            #print("Sent: ", chunk)
            client_socket.sendall(pickle.dumps(chunk))
            time.sleep(0.3)  # Add a small delay
        client_socket.send(b'END_OF_DATA_STREAM')

        # ------------------------------------------certificate check start !!------------------------------------------
        valid_cert = True
        curr_time = time.time()
        if curr_time > timestamp_valid_until:
            print("<---Expired Certificate!!--->")
            valid_cert = False

        # ------------------------------------------certificate check end !!--------------------------------------------

        if valid_cert:
            print("<---Valid Certificate--->")
            self.initiate_keyEx_c(client_socket)
    
            receive_thread = threading.Thread(target=self.receive_messages, args=(client_socket,))
            receive_thread.start()
    
            while True:
                message = input()
                if message.lower() == 'exit':
                    break
                elif message.startswith(":$"):
                    self.command_Set(message, client_socket)
                else:
                    client_socket.send(self.EncryptSession(message))
                    self.message_count = self.message_count + 1
                    if self.message_count%10 == 0:
                        self.changeSess()
 
        client_socket.close()


    # Basically present whatever client is sending
    def receive_messages(self, client_socket):
        while True:
            try:
                data = client_socket.recv(2048)
                if data:
                    print("server>", self.DecryptSession(data))
                    self.message_count = self.message_count + 1
                    if self.message_count%10 == 0:
                        self.changeSess()
            except Exception as e:
                print(f"Error: {e}")
                break

    # Basically present whatever client is sending
    def handle_client(self, client_socket):
        while True:
            try:
                data = client_socket.recv(2048)
                if data:
                    print("client>", self.DecryptSession(data))
                    self.message_count = self.message_count + 1
                    if self.message_count%10 == 0:
                        self.changeSess()
            except Exception as e:
                print(f"Error: {e}")
                break

    # Basically send the encrypted text
    def send_messages(self, client_socket):
        try:
            while True:
                message = input()
                if message == "exit":
                    break
                elif message.startswith(":$"):
                    self.command_Set(message, client_socket)
                else:
                    client_socket.send(self.EncryptSession(message))
                    self.message_count = self.message_count + 1
                    if self.message_count%10 == 0:
                        self.changeSess()
        except Exception as e:
            print(f"Error: {e}")

    

if __name__ == "__main__":
    choice = input("Enter choice (server or client): ")
    peer = SecureChat()
    if choice == 'server':
        peer.start_server()
    elif choice == 'client':
        peer.client_side()
    else:
        print("Wrong choice!!")
    