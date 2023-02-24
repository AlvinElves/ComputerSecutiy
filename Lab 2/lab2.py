import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.exceptions import InvalidSignature

# This is our fictitious server - feel free to look at its code for tips
from servers import EncryptionServer
server = EncryptionServer()


### Key Exchange ###
# a. Get server parameters
parameters = server.get_parameters()

# b. Generate our private key
private_key = parameters.generate_private_key()

# c. Generate a public key using our private key
public_key = private_key.public_key()

# d. Get server public key
server_public_key = server.get_public_key()

# e. Combine the server’s public key with our private key into a shared secret
shared_secret = private_key.exchange(server_public_key)

# f. Send our public key to the server, so it can do the same
key_to_server = server.submit_public_key(public_key)


### Key Derivation ###
# Use HKDF to derive a symmetric key (256-bytes)
hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'comp3077')
aes_key = hkdf.derive(shared_secret)

print(len(aes_key))


### Symmetric Encryption
# Get a message from the server encrypted using the new shared symmetric key
server_message = server.get_encrypted_message()
nonce = server_message[0:16]
ciphertext = server_message[16:]

# Use AES-CTR to decrypt the message
cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
decryptor = cipher.decryptor()

plain_text = decryptor.update(ciphertext) + decryptor.finalize()

print(plain_text)


### Hashing ###
# Hash the following messages using SHA256
message_one = b'This is a message we\'d like to hash. It includes a number #0112933.'
message_two = b'This is a message we\'d like to hash. It includes a number #0112934.'
digest = hashes.Hash(hashes.SHA256())
digest.update(message_one)
hashed_message_one = digest.finalize()
print(hashed_message_one.hex())

digest = hashes.Hash(hashes.SHA256())
digest.update(message_two)
hashed_message_two = digest.finalize()
print(hashed_message_two.hex())

# Load the entire works of Shakespeare into a bytes object
with open('./data/shakespeare.txt', 'rb') as f:
    data = f.read()

# Use the SHA-256 hash function to hash the entire works of Shakespeare
digest = hashes.Hash(hashes.SHA256())
digest.update(data)
hashed_data = digest.finalize()
print(hashed_data.hex())


### Asymmetric Cryptography ###
# Load server public key.
with open('./data/rsa_public.pem', 'r') as f:
    pem_data = f.read().encode("UTF-8")
    server_rsa_public_key = load_pem_public_key(data=pem_data)

print(server_rsa_public_key.public_numbers().e)
print(server_rsa_public_key.public_numbers().n)

# Create a challenge token
token = 'hellohowareyou'
byte_token = token.encode("UTF-8")

# Have the server sign it
signed_message = server.sign_document(byte_token)

# Verify the signature
try:
    # Verify the signed message using public_key.verify()
    server_rsa_public_key.verify(signed_message, byte_token, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                        salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    raise InvalidSignature("Replace this with verification code!")
    print("The server successfully signed the message.")

except InvalidSignature:
    print("The server failed our signature verification.")
