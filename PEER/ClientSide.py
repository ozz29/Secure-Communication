# Complete cryptography library
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, asymmetric, hashes
from cryptography.hazmat.primitives import padding as pad

# Normal Libraries
import random
import socket
import threading
import hashlib

class SecureChatClient:
    # As the name suggests, variables represent them
    def __init__(self):
        self.private_key = None
        self.private_key_pem = None
        self.public_key = None
        self.public_key_pem = None
        self.session_key = None
        self.server_public_key = None
        self.server_public_key_pem = None
        self.g = 2
        self.n = 11076478309435183247342274229442810489005322936188389787192673

    # Generation of both public key and private keys
    # the PEM variables makes the public/private key variable pem encoded
    # PEM encoding is used basically for presenting on screen
    def generate_key(self):
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
    def initiate_keyEx(self, client_socket):
        a = random.randint(2, self.n - 1)
        A = self.mod_exp(self.g, a, self.n)
        encrypted_key1 = self.server_public_key.encrypt(
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
            for i in range(0, len(self.server_public_key_pem.splitlines())):
                print(self.server_public_key_pem.splitlines()[i])

        elif message == ":$ change -h":
            print("-> change keys  - regenerate the key pairs")
            print("-> change sess  - regenerate the session key")

        elif message == ":$ change keys":
            self.generate_key()

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

    # Basically present whatever client is sending
    def receive_messages(self, client_socket):
        while True:
            try:
                data = client_socket.recv(2048)
                if data:
                    print("server>", self.DecryptSession(data))
            except Exception as e:
                print(f"Error: {e}")
                break

    # Client socket is initialised
    # Only requests connection and not accepting connections
    # -> Keys are generated
    # -> Public Key is exchanged
    # -> Initiation of session key exchange
    # Presence of only one thread, wants to talk to only one server
    # Sending the messages encrypted
    def client_side(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.generate_key()

        server_ip = input("Enter server IP address: ")
        server_port = int(input("Enter server port: "))

        client_socket.connect((server_ip, server_port))

        # Sending/Accepting public key
        self.server_public_key_pem = client_socket.recv(2048)
        self.server_public_key = serialization.load_pem_public_key(self.server_public_key_pem)
        client_socket.send(self.public_key_pem)

        self.initiate_keyEx(client_socket)

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

        client_socket.close()


# Main Method
if __name__ == "__main__":
    client = SecureChatClient()
    client.client_side()
