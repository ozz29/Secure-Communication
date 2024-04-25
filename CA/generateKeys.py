from Crypto.PublicKey import RSA
 
def generate_key_pair():
    # Generate RSA key pair
    key = RSA.generate(2048)
 
    # Export private key
    private_key = key.export_key()
    with open("private_key.pem", "wb") as private_key_file:
        private_key_file.write(private_key)
 
    # Export public key
    public_key = key.publickey().export_key()
    with open("public_key.pem", "wb") as public_key_file:
        public_key_file.write(public_key)
 
def load_keys():
    # Load private key
    with open("private_key.pem", "rb") as private_key_file:
        private_key = private_key_file.read()
 
    # Load public key
    with open("public_key.pem", "rb") as public_key_file:
        public_key = public_key_file.read()
 
    return private_key, public_key
 
# Generate and save key pair
generate_key_pair()
 
# Later in the code, you can load the keys using:
# private_key, public_key = load_keys()